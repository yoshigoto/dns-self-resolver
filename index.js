// dns-self-resolver
// フルサービスリゾルバ (OS のスタブリゾルバ) には依存せず、ルートサーバーから自前で
// DNS の問い合わせ・NS 名前解決・グルー(bailiwick)判定を行うための共通ユーティリティ。
// dns-delegation-check / dnssec-validator など、DNS を自前で辿るツール間で重複していたロジックを集約したもの。

import net from 'net';
import dgram from 'dgram';
import dnsPacket from 'dns-packet';

export function isIPv6(ip) {
    return ip.includes(':');
}

export function normalizeDnsName(name) {
    return String(name || '').trim().toLowerCase().replace(/\.$/, '');
}

export function isSubdomainOrEqual(childCandidate, parentCandidate) {
    const c = normalizeDnsName(childCandidate);
    const p = normalizeDnsName(parentCandidate);
    if (!c || !p) return false;
    if (c === p) return true;
    return c.endsWith('.' + p);
}

export function hasParentChildRelationship(domainA, domainB) {
    return isSubdomainOrEqual(domainA, domainB) || isSubdomainOrEqual(domainB, domainA);
}

export function isInBailiwickGlue(record, nsNames, delegatedZone) {
    return (record.type === 'A' || record.type === 'AAAA') &&
        nsNames.includes(normalizeDnsName(record.name)) &&
        isSubdomainOrEqual(record.name, delegatedZone);
}

// RFC 9471 上の glue 判定 (isInBailiwickGlue) とは別に、次の問い合わせ先を選ぶための探索用アドレスを集める。
// a.gtld-servers.net のような out-of-bailiwick な追加レコードも、探索の効率化には利用してよい。
export function getReferralAddressRecords(additionals, nsNames) {
    return additionals.filter(record =>
        (record.type === 'A' || record.type === 'AAAA') &&
        nsNames.includes(normalizeDnsName(record.name)));
}

export const DNS_CACHE_TTL = {
    success: 30000,
    transient: 2000,
    timeout: Infinity
};

export function getCacheEntry(dnsResponseCache, cacheKey) {
    const entry = dnsResponseCache.get(cacheKey);
    if (!entry) {
        return null;
    }

    if (entry.expiresAt <= Date.now()) {
        dnsResponseCache.delete(cacheKey);
        return null;
    }

    return entry.value;
}

export function setCacheEntry(dnsResponseCache, cacheKey, value, ttlMs = DNS_CACHE_TTL.success) {
    dnsResponseCache.set(cacheKey, {
        value,
        expiresAt: Date.now() + ttlMs
    });
}

function normalizeQueryOptions(options, defaults = {}) {
    if (typeof options === 'boolean') {
        return { ...defaults, useEdns: options };
    }
    return { ...defaults, ...(options || {}) };
}

function getDnsCacheKey(serverIp, qType, domain, options) {
    return `${serverIp}|${qType}|${domain}|edns:${options.useEdns ? 1 : 0}|do:${options.dnssecOk ? 1 : 0}`;
}

function getAdditionals(options) {
    if (!options.useEdns) return [];
    return [{
        type: 'OPT',
        name: '.',
        udpPayloadSize: options.udpPayloadSize,
        flags: options.dnssecOk ? dnsPacket.DNSSEC_OK : 0
    }];
}

export function queryDirectlyTCP(domain, serverIp, dnsResponseCache, qType = 'NS', queryOptions = {}) {
    const options = normalizeQueryOptions(queryOptions, {
        useEdns: true,
        dnssecOk: false,
        udpPayloadSize: 1232,
        timeoutMs: 5000
    });

    return new Promise((resolve) => {
        const cacheKey = getDnsCacheKey(serverIp, qType, domain, options);
        const cachedResult = getCacheEntry(dnsResponseCache, cacheKey);
        // 以前に同じサーバー・タイプ・ドメインに対して問い合わせ済みなら、即時復元
        if (cachedResult) {
            return resolve({ ...cachedResult, isCached: true });
        }

        let settled = false;
        let socket = null;
        let timer = null;

        const finish = (result) => {
            if (settled) return;
            settled = true;
            if (timer) clearTimeout(timer);
            if (socket) socket.destroy();
            resolve(result);
        };

        try {
            const tcpBuf = dnsPacket.streamEncode({
                type: 'query',
                id: Math.floor(Math.random() * 65534),
                questions: [{ type: qType, name: domain }],
                additionals: getAdditionals(options)
            });

            socket = net.createConnection({ host: serverIp, port: 53 }, () => {
                socket.write(tcpBuf);
            });

            timer = setTimeout(() => {
                const timeoutResult = { error: 'TIMEOUT', transport: 'tcp' };
                setCacheEntry(dnsResponseCache, cacheKey, timeoutResult, DNS_CACHE_TTL.timeout);
                finish(timeoutResult);
            }, options.timeoutMs);

            socket.on('error', (err) => {
                const socketError = { error: 'SOCKET_ERROR', detail: err.message, transport: 'tcp' };
                setCacheEntry(dnsResponseCache, cacheKey, socketError, DNS_CACHE_TTL.transient);
                finish(socketError);
            });

            let receivedData = Buffer.alloc(0);
            socket.on('data', (chunk) => {
                receivedData = Buffer.concat([receivedData, chunk]);

                while (receivedData.length >= 2) {
                    // 先頭 2バイトから DNSメッセージの長さを取得
                    const msgLength = receivedData.readUInt16BE(0);
                    if (receivedData.length < msgLength + 2) break;

                    try {
                        const decoded = dnsPacket.streamDecode(receivedData);
                        if (!decoded) break;

                        receivedData = receivedData.subarray(2 + msgLength);
                        const tcpSuccess = { ...decoded, transport: 'tcp' };
                        setCacheEntry(dnsResponseCache, cacheKey, tcpSuccess, DNS_CACHE_TTL.success);
                        return finish(tcpSuccess);
                    } catch (e) {
                        const decodeError = { error: 'DECODE_ERROR', detail: e.message, transport: 'tcp' };
                        setCacheEntry(dnsResponseCache, cacheKey, decodeError, DNS_CACHE_TTL.transient);
                        return finish(decodeError);
                    }
                }
            });
        } catch (e) {
            const sendError = { error: 'SEND_ERROR', detail: e.message, transport: 'tcp' };
            setCacheEntry(dnsResponseCache, cacheKey, sendError, DNS_CACHE_TTL.transient);
            finish(sendError);
        }
    });
}

export function queryDirectlyUDP(domain, serverIp, dnsResponseCache, qType = 'NS', queryOptions = true) {
    const options = normalizeQueryOptions(queryOptions, {
        useEdns: true,
        dnssecOk: false,
        udpPayloadSize: 1232,
        timeoutMs: 5000
    });

    return new Promise((resolve) => {
        const cacheKey = getDnsCacheKey(serverIp, qType, domain, options);
        const cachedResult = getCacheEntry(dnsResponseCache, cacheKey);
        // 以前に同じサーバー・タイプ・ドメインに対して問い合わせ済みなら、即時復元
        if (cachedResult) {
            return resolve({ ...cachedResult, isCached: true });
        }

        const socketType = isIPv6(serverIp) ? 'udp6' : 'udp4';
        const client = dgram.createSocket(socketType);
        let settled = false;
        let timer = null;

        const finish = (result) => {
            if (settled) return;
            settled = true;
            if (timer) clearTimeout(timer);
            try { client.close(); } catch (e) {}
            resolve(result);
        };

        try {
            const buf = dnsPacket.encode({
                type: 'query',
                id: Math.floor(Math.random() * 65534),
                questions: [{ type: qType, name: domain }],
                additionals: getAdditionals(options)
            });

            client.send(buf, 0, buf.length, 53, serverIp, (err) => {
                if (err) {
                    const sendError = { error: 'SEND_ERROR', detail: err.message, transport: 'udp' };
                    setCacheEntry(dnsResponseCache, cacheKey, sendError, DNS_CACHE_TTL.transient);
                    return finish(sendError);
                }
            });
        } catch (e) {
            const sendError = { error: 'SEND_ERROR', detail: e.message, transport: 'udp' };
            setCacheEntry(dnsResponseCache, cacheKey, sendError, DNS_CACHE_TTL.transient);
            return finish(sendError);
        }

        timer = setTimeout(() => {
            const timeoutResult = { error: 'TIMEOUT', transport: 'udp' };
            setCacheEntry(dnsResponseCache, cacheKey, timeoutResult, DNS_CACHE_TTL.timeout);
            return finish(timeoutResult);
        }, options.timeoutMs);

        client.on('error', (err) => {
            const socketError = { error: 'SOCKET_ERROR', detail: err.message, transport: 'udp' };
            setCacheEntry(dnsResponseCache, cacheKey, socketError, DNS_CACHE_TTL.transient);
            return finish(socketError);
        });

        client.on('message', (msg) => {
            try {
                const decoded = dnsPacket.decode(msg);
                if (decoded.rcode === 'FORMERR' && options.useEdns) {
                    if (timer) clearTimeout(timer);
                    try { client.close(); } catch (e) {}
                    return queryDirectlyUDP(domain, serverIp, dnsResponseCache, qType, {
                        ...options,
                        useEdns: false,
                        dnssecOk: false
                    })
                        .then(result => finish({ ...result, retryWithoutEdns: true }));
                }
                const answers = decoded.answers || [];
                const authorities = decoded.authorities || [];

                const TC_FLAG = dnsPacket.TRUNCATED_RESPONSE;
                const isTruncated = (decoded.flags & TC_FLAG) !== 0;

                if (isTruncated) {
                    const fallback = () => queryDirectlyTCP(domain, serverIp, dnsResponseCache, qType, options)
                        .then((tcpResult) => {
                            return finish({
                                ...tcpResult,
                                transport: tcpResult?.transport || 'tcp',
                                retryFrom: 'udp-truncated',
                                isFallback: true
                            });
                        })
                        .catch((err) => {
                            return finish({
                                error: 'TCP_FALLBACK_ERROR',
                                detail: err?.message || 'TCP fallback failed',
                                transport: 'tcp',
                                retryFrom: 'udp-truncated',
                                isFallback: true
                            });
                        });

                    if (timer) clearTimeout(timer);
                    try { client.close(); } catch (e) {}
                    return fallback();
                }

                const hasNsRecord = [...answers, ...authorities].some(r => r.type === 'NS' && hasParentChildRelationship(domain, r.name));
                if (hasNsRecord) {
                    setCacheEntry(dnsResponseCache, cacheKey, decoded, DNS_CACHE_TTL.success);
                }

                return finish({ ...decoded, transport: 'udp' });
            } catch (e) {
                const decodeError = { error: 'DECODE_ERROR', detail: e.message, transport: 'udp' };
                setCacheEntry(dnsResponseCache, cacheKey, decodeError, DNS_CACHE_TTL.transient);
                return finish(decodeError);
            }
        });
    });
}

// a.root-servers.net の固定 IP。ここだけは OS/フルサービスリゾルバに頼らずに自己解決を開始するための起点。
export const ROOT_SERVER_BOOTSTRAP_IP = '198.41.0.4';
export const NAMESERVER_IP_CACHE_TTL = 300000; // レコードに TTL が無い場合のフォールバック
const nameserverIpCache = new Map(); // 正規化ホスト名 -> { ips, expiresAt }
const inFlightServerResolutions = new Map(); // 同一ホスト名の並行解決合流用 (Singleflight)
const inFlightIpv4Resolutions = new Map();   // 同一ホスト名の並行解決合流用 (Singleflight)

export function getCachedNameserverIPs(hostname) {
    const key = normalizeDnsName(hostname);
    const cached = nameserverIpCache.get(key);
    if (!cached) return null;
    if (cached.expiresAt <= Date.now()) {
        nameserverIpCache.delete(key);
        return null;
    }
    return cached.ips;
}

export function cacheNameserverIPs(hostname, ips, ttlMs = NAMESERVER_IP_CACHE_TTL) {
    if (!hostname || !ips || ips.length === 0) return;
    nameserverIpCache.set(normalizeDnsName(hostname), { ips, expiresAt: Date.now() + ttlMs });
}

export function getKnownAddress(knownAddresses, hostname, family = 'any') {
    if (!knownAddresses || !hostname) return null;
    const normalized = normalizeDnsName(hostname);
    let val = null;
    if (knownAddresses instanceof Map) {
        val = knownAddresses.get(normalized) || knownAddresses.get(hostname);
    } else if (typeof knownAddresses === 'object') {
        val = knownAddresses[normalized] || knownAddresses[hostname];
    }
    if (!val) return null;
    const list = Array.isArray(val) ? val : [val];
    if (family === 'A' || family === 'IPv4') {
        const v4 = list.filter(ip => !isIPv6(ip));
        return v4.length > 0 ? v4 : null;
    }
    if (family === 'AAAA' || family === 'IPv6') {
        const v6 = list.filter(ip => isIPv6(ip));
        return v6.length > 0 ? v6 : null;
    }
    return list.length > 0 ? list : null;
}

// 指定されたサーバーから特定レコード (A / AAAA 等) を直接取得するヘルパー
export async function resolveRecordFromServer(
    name,
    serverIp,
    qTypes = ['A', 'AAAA'],
    dnsResponseCache = new Map(),
    queryOptions = {}
) {
    const types = Array.isArray(qTypes) ? qTypes : [qTypes || 'A'];
    const options = normalizeQueryOptions(queryOptions);
    const queryUDP = options.queryDirectlyUDP || queryDirectlyUDP;
    const cache = dnsResponseCache || new Map();

    const results = await Promise.all(
        types.map(async (type) => {
            const res = await queryUDP(name, serverIp, cache, type, options);
            if (res?.error || !res?.answers) return [];
            return res.answers
                .filter(record => record.type === type && normalizeDnsName(record.name) === normalizeDnsName(name))
                .map(record => record.data);
        })
    );

    return results.flat();
}

// ルートサーバーから委任を辿って name の qType レコードを自己解決する (フルサービスリゾルバのキャッシュを経由しない)。
export async function resolveRecordFromRoot(name, qType, dnsResponseCache, dependencies = {}) {
    const queryUDP = dependencies.queryDirectlyUDP || queryDirectlyUDP;
    const resolveIPv4 = dependencies.resolveHostnameIPv4Self || resolveHostnameIPv4Self;
    let currentServerIp = ROOT_SERVER_BOOTSTRAP_IP;
    let candidateQueue = [];

    const useNextCandidate = async () => {
        while (candidateQueue.length > 0) {
            const candidate = candidateQueue.shift();
            const ip = candidate.ip || await resolveIPv4(candidate.nsName, dependencies);
            if (ip) {
                currentServerIp = ip;
                return true;
            }
        }
        return false;
    };

    for (let depth = 0; depth < 10; depth++) {
        const res = await queryUDP(name, currentServerIp, dnsResponseCache, qType);
        if (res.error) {
            if (await useNextCandidate()) continue;
            return [];
        }

        const matchedAnswers = (res.answers || [])
            .filter(record => record.type === qType && normalizeDnsName(record.name) === normalizeDnsName(name));
        if (matchedAnswers.length > 0) {
            return matchedAnswers.map(record => record.data);
        }

        const AUTHORITATIVE_ANSWER = dnsPacket.AUTHORITATIVE_ANSWER || 1024;
        const isAuthoritative = (res.flags & AUTHORITATIVE_ANSWER) !== 0;
        if (isAuthoritative) {
            return []; // 権威応答だが対象レコードが無い (NODATA/NXDOMAIN)
        }

        const nsRecords = (res.authorities || []).filter(r => r.type === 'NS');
        if (nsRecords.length === 0) {
            if (await useNextCandidate()) continue;
            return [];
        }

        const nsNames = nsRecords.map(r => normalizeDnsName(r.data));
        // 次の問い合わせ先の選定には、正式な glue (isInBailiwickGlue) に限らず、
        // a.gtld-servers.net のような out-of-bailiwick な参照アドレスも探索用に利用する。
        const referralAddressByNsName = new Map();
        getReferralAddressRecords(res.additionals || [], nsNames)
            .forEach(record => {
                const key = normalizeDnsName(record.name);
                if (!referralAddressByNsName.has(key)) referralAddressByNsName.set(key, record.data);
            });

        // 参照アドレスを持つ候補を優先し、無い候補は捨てずにフォールバック用に保持する。
        // knownAddresses が指定されていれば referral アドレスがない候補の事前解決アドレスとしても参照する。
        const candidates = nsNames
            .map(nsName => {
                let ip = referralAddressByNsName.get(nsName) || null;
                if (!ip && dependencies.knownAddresses) {
                    const known = getKnownAddress(dependencies.knownAddresses, nsName, 'A');
                    if (known && known.length > 0) ip = known[0];
                }
                return { nsName, ip };
            })
            .sort((a, b) => (a.ip ? 0 : 1) - (b.ip ? 0 : 1));
        const chosen = candidates.shift();
        candidateQueue = candidates;

        if (chosen.ip) {
            currentServerIp = chosen.ip;
            continue;
        }

        // グルーが無い NS 名は再帰的に自己解決する (循環参照は resolveHostnameIPv4Self 側で検出)
        const resolvedIp = await resolveIPv4(chosen.nsName, dependencies);
        if (!resolvedIp) {
            if (await useNextCandidate()) continue;
            return [];
        }
        currentServerIp = resolvedIp;
    }

    return [];
}

// NS 名の IP アドレス解決専用の入り口。グルー不足時の再帰呼び出しで循環参照を検出する。
export async function resolveHostnameIPv4Self(hostname, dependencies = {}) {
    const normalized = normalizeDnsName(hostname);
    if (net.isIP(normalized)) {
        return isIPv6(normalized) ? null : normalized;
    }

    const known = getKnownAddress(dependencies.knownAddresses, normalized, 'A');
    if (known && known.length > 0) return known[0];

    const cached = getCachedNameserverIPs(normalized);
    if (cached && cached.length > 0) {
        const v4 = cached.find(ip => !isIPv6(ip));
        if (v4) return v4;
    }

    const resolvingStack = dependencies.resolvingStack || new Set();
    if (resolvingStack.has(normalized)) {
        return null; // 循環参照 (グルーレコード不足の可能性)
    }

    if (inFlightIpv4Resolutions.has(normalized)) {
        return inFlightIpv4Resolutions.get(normalized);
    }

    const nextStack = new Set(resolvingStack).add(normalized);
    const childDependencies = { ...dependencies, resolvingStack: nextStack };

    const promise = (async () => {
        const dnsResponseCache = dependencies.dnsResponseCache || dependencies.cache || new Map();
        const ips = await resolveRecordFromRoot(normalized, 'A', dnsResponseCache, childDependencies);
        if (ips.length > 0) {
            cacheNameserverIPs(normalized, ips);
            return ips[0];
        }
        return null;
    })();

    inFlightIpv4Resolutions.set(normalized, promise);
    try {
        return await promise;
    } finally {
        inFlightIpv4Resolutions.delete(normalized);
    }
}

// フルサービスリゾルバ (OS のスタブリゾルバ経由) には依存せず、ルートサーバーから自前で NS 名を解決する。
export async function resolveServerIPs(nsName, dependencies = {}) {
    const normalized = normalizeDnsName(nsName);
    if (net.isIP(normalized)) return [normalized];

    const known = getKnownAddress(dependencies.knownAddresses, normalized);
    if (known && known.length > 0) return known;

    const cached = getCachedNameserverIPs(normalized);
    if (cached) return cached;

    const resolvingStack = dependencies.resolvingStack || new Set();
    if (resolvingStack.has(normalized)) {
        return null; // 循環参照 (グルーレコード不足の可能性)
    }

    if (inFlightServerResolutions.has(normalized)) {
        return inFlightServerResolutions.get(normalized);
    }

    const nextStack = new Set(resolvingStack).add(normalized);
    const childDependencies = { ...dependencies, resolvingStack: nextStack };

    const promise = (async () => {
        const dnsResponseCache = dependencies.dnsResponseCache || dependencies.cache || new Map();
        const [v4, v6] = await Promise.all([
            resolveRecordFromRoot(normalized, 'A', dnsResponseCache, childDependencies),
            resolveRecordFromRoot(normalized, 'AAAA', dnsResponseCache, childDependencies)
        ]);
        const ips = [...v4, ...v6];
        if (ips.length === 0) return null;
        cacheNameserverIPs(normalized, ips);
        return ips;
    })();

    inFlightServerResolutions.set(normalized, promise);
    try {
        return await promise;
    } finally {
        inFlightServerResolutions.delete(normalized);
    }
}
