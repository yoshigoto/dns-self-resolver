// dns-self-resolver
// フルサービスリゾルバ (OS のスタブリゾルバ) には依存せず、ルートサーバーから自前で
// DNS の問い合わせ・NS 名前解決・グルー(bailiwick)判定を行うための共通ユーティリティ。
// dns-delegation-check / dnssec-validator など、DNS を自前で辿るツール間で重複していたロジックを集約したもの。

import net from 'net';
import dgram from 'dgram';
import { randomBytes, randomInt } from 'crypto';
import dnsPacket from 'dns-packet';

export function isIPv6(ip) {
    return typeof ip === 'string' && ip.includes(':');
}

function isIpLiteral(ip) {
    return typeof ip === 'string' && net.isIP(ip) !== 0;
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
        nsNames.some(nsName => normalizeDnsName(nsName) === normalizeDnsName(record.name)) &&
        isSubdomainOrEqual(record.name, delegatedZone);
}

// 委任 owner 配下の glue を使い、root referral では root が返す TLD NS glue も許可する。
// それ以外の out-of-bailiwick な追加レコードは authoritative な A/AAAA 解決を迂回するため利用しない。
export function getReferralAddressRecords(
    additionals,
    nsNames,
    delegatedZone,
    gluePolicy = 'strict',
    serverZone = delegatedZone
) {
    const normalizedNsNames = new Set(nsNames.map(normalizeDnsName));
    const isNsAddressRecord = record =>
        (record.type === 'A' || record.type === 'AAAA') &&
        normalizedNsNames.has(normalizeDnsName(record.name));

    if (gluePolicy === 'strict') {
        const isRootReferral = serverZone === '.';
        return additionals.filter(record =>
            isInBailiwickGlue(record, nsNames, delegatedZone) ||
            (isRootReferral && isNsAddressRecord(record)));
    }
    if (gluePolicy !== 'allow-sibling') {
        throw new Error(`未対応の gluePolicy です: ${gluePolicy}`);
    }
    return additionals.filter(record =>
        isNsAddressRecord(record) &&
        (!normalizeDnsName(serverZone) ||
            isSubdomainOrEqual(record.name, serverZone)));
}

export const DNS_CACHE_TTL = {
    success: 30000,
    transient: 2000,
    // 恒久障害と誤認しないよう、タイムアウトも短命にキャッシュする (Infinity は不可)
    timeout: 2000
};

// レコード TTL (秒) と上限 (ms) の小さい方をキャッシュ期間として採用する
function computeSuccessTtlMs(decoded, capMs = DNS_CACHE_TTL.success) {
    const records = [...(decoded?.answers || []), ...(decoded?.authorities || [])];
    const ttlSeconds = records
        .map(record => record.ttl)
        .filter(ttl => typeof ttl === 'number' && ttl >= 0);
    if (ttlSeconds.length === 0) return capMs;
    return Math.min(Math.min(...ttlSeconds) * 1000, capMs);
}

function buildDnsError(code, { domain, serverIp, qType, transport, detail, retryable }) {
    return {
        error: code,
        name: domain,
        serverIp,
        qType,
        transport,
        retryable,
        ...(detail !== undefined ? { detail } : {})
    };
}

function buildAbortError({ domain, serverIp, qType, transport, signal }) {
    return buildDnsError('ABORTED', {
        domain,
        serverIp,
        qType,
        transport,
        detail: signal?.reason?.message,
        retryable: false
    });
}

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

// 応答キャッシュの最大エントリ数。大量の名前を問い合わせさせる攻撃でメモリを使い切らないよう上限を設ける
export const DNS_RESPONSE_CACHE_MAX_ENTRIES = 10000;

// 上限を超える場合は最も古く挿入されたエントリから追い出す (Map の挿入順を利用)
function setBounded(map, key, entry, maxEntries) {
    if (map.has(key)) map.delete(key);
    while (map.size >= maxEntries && typeof map.keys === 'function') {
        const oldestKey = map.keys().next().value;
        if (oldestKey === undefined) break;
        map.delete(oldestKey);
    }
    map.set(key, entry);
}

export function setCacheEntry(dnsResponseCache, cacheKey, value, ttlMs = DNS_CACHE_TTL.success) {
    setBounded(dnsResponseCache, cacheKey, {
        value,
        expiresAt: Date.now() + ttlMs
    }, DNS_RESPONSE_CACHE_MAX_ENTRIES);
}

function normalizeQueryOptions(options, defaults = {}) {
    if (typeof options === 'boolean') {
        return { ...defaults, useEdns: options };
    }
    return { ...defaults, ...(options || {}) };
}

function getDnsCacheKey(serverIp, qType, domain, options) {
    return `${serverIp}|${qType}|${domain}|udpPort:${options.udpPort}|tcpPort:${options.tcpPort}|edns:${options.useEdns ? 1 : 0}|do:${options.dnssecOk ? 1 : 0}|timeout:${options.timeoutMs}`;
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

// キャッシュポイズニング対策として、予測困難な暗号論的乱数で 16 bit の id を生成する
function createQueryId() {
    return randomInt(0, 65536);
}

function stripTrailingDot(name) {
    const value = String(name ?? '').trim();
    return value === '.' ? value : value.replace(/\.$/, '');
}

// DNS 0x20 (draft-vixie-dnsext-dns0x20): question 名の英字の大文字小文字をランダム化し、
// 応答側で完全一致を要求することで、偽装応答に必要な推測ビット数を増やす
function randomizeNameCase(name) {
    const chars = [...String(name)];
    const random = randomBytes(chars.length);
    return chars.map((ch, i) => {
        if (!/[a-z]/i.test(ch)) return ch;
        return (random[i] & 1) ? ch.toUpperCase() : ch.toLowerCase();
    }).join('');
}

// 0x20 で変化させた owner 名を呼び出し側が指定した表記に戻し、下流の比較処理に影響を与えないようにする
function restoreQueryNameCase(decoded, sentName, domain) {
    if (sentName === domain) return decoded;
    const lowerDomain = normalizeDnsName(domain);
    const restoredName = stripTrailingDot(domain);
    const restore = records => Array.isArray(records)
        ? records.map(record => (record && typeof record.name === 'string' &&
            normalizeDnsName(record.name) === lowerDomain)
            ? { ...record, name: restoredName }
            : record)
        : records;
    return {
        ...decoded,
        questions: restore(decoded.questions),
        answers: restore(decoded.answers),
        authorities: restore(decoded.authorities),
        additionals: restore(decoded.additionals)
    };
}

// 遅延して届いた別クエリの応答や偽装応答を拾わないよう、id と question を照合する。
// 戻り値: 'match' | 'case-mismatch' (0x20 の大文字小文字のみ不一致) | 'mismatch'
function classifyResponse(decoded, queryId, sentName, qType) {
    if (decoded.id !== queryId) return 'mismatch';
    if (decoded.type !== 'response') return 'mismatch';
    const questions = decoded.questions || [];
    // FORMERR では question セクションが省略される実装があるため、その場合のみ id 一致で許容する
    // (FORMERR はレコードを含まずキャッシュもされないため、偽装されてもキャッシュポイズニングには使えない)
    if (questions.length === 0) return decoded.rcode === 'FORMERR' ? 'match' : 'mismatch';
    if (questions.length !== 1) return 'mismatch';
    const question = questions[0];
    if (question.type !== qType || normalizeDnsName(question.name) !== normalizeDnsName(sentName)) {
        return 'mismatch';
    }
    return stripTrailingDot(question.name) === stripTrailingDot(sentName) ? 'match' : 'case-mismatch';
}

function isMatchingResponse(decoded, queryId, domain, qType) {
    return classifyResponse(decoded, queryId, domain, qType) !== 'mismatch';
}

const DNS_HEADER_LENGTH = 12;
const DNS_QR_BIT = 0x80;
const DNS_PORT = 53;
// TCP で 1 接続から受信するデータ量の上限 (最大メッセージ長 65535 + 長さ 2 バイトの数倍)
const MAX_TCP_RECEIVE_BYTES = 4 * (65535 + 2);
// ソースポートのランダム化範囲 (特権ポートは避ける)
const SOURCE_PORT_MIN = 1024;
const SOURCE_PORT_MAX_EXCLUSIVE = 65536;
const MAX_SOURCE_PORT_ATTEMPTS = 8;

function isValidDnsPort(port) {
    return Number.isInteger(port) && port >= 1 && port <= 65535;
}

function bindSocket(socket, port) {
    return new Promise((resolve, reject) => {
        const onError = (err) => reject(err);
        socket.once('error', onError);
        socket.bind({ port, exclusive: true }, () => {
            socket.removeListener('error', onError);
            resolve(socket);
        });
    });
}

// OS のエフェメラルポート範囲 (環境によっては 12 bit 程度) に依存せず、
// 暗号論的乱数で選んだソースポートにバインドして偽装応答に必要な推測空間を広げる
async function createRandomPortSocket(socketType, onCreate = () => {}) {
    for (let attempt = 0; attempt < MAX_SOURCE_PORT_ATTEMPTS; attempt++) {
        const socket = dgram.createSocket(socketType);
        onCreate(socket);
        try {
            return await bindSocket(socket, randomInt(SOURCE_PORT_MIN, SOURCE_PORT_MAX_EXCLUSIVE));
        } catch (err) {
            try { socket.close(); } catch (e) {}
            if (err?.code !== 'EADDRINUSE' && err?.code !== 'EACCES') throw err;
        }
    }
    const socket = dgram.createSocket(socketType);
    onCreate(socket);
    try {
        return await bindSocket(socket, 0);
    } catch (err) {
        try { socket.close(); } catch (e) {}
        throw err;
    }
}

function buildInvalidServerError(domain, serverIp, qType, transport) {
    return buildDnsError('SEND_ERROR', {
        domain,
        serverIp,
        qType,
        transport,
        detail: 'serverIp must be an IPv4/IPv6 address literal',
        retryable: false
    });
}

function buildInvalidPortError(domain, serverIp, qType, transport, portName) {
    return buildDnsError('SEND_ERROR', {
        domain,
        serverIp,
        qType,
        transport,
        detail: `${portName} must be an integer between 1 and 65535`,
        retryable: false
    });
}

export function queryDirectlyTCP(domain, serverIp, dnsResponseCache, qType = 'NS', queryOptions = {}) {
    const options = normalizeQueryOptions(queryOptions, {
        useEdns: true,
        dnssecOk: false,
        udpPayloadSize: 1232,
        udpPort: DNS_PORT,
        tcpPort: DNS_PORT,
        timeoutMs: 5000
    });

    return new Promise((resolve) => {
        if (options.signal?.aborted) {
            return resolve(buildAbortError({ domain, serverIp, qType, transport: 'tcp', signal: options.signal }));
        }
        if (!isIpLiteral(serverIp)) {
            return resolve(buildInvalidServerError(domain, serverIp, qType, 'tcp'));
        }
        if (!isValidDnsPort(options.tcpPort)) {
            return resolve(buildInvalidPortError(domain, serverIp, qType, 'tcp', 'tcpPort'));
        }
        if (!isValidDnsPort(options.udpPort)) {
            return resolve(buildInvalidPortError(domain, serverIp, qType, 'tcp', 'udpPort'));
        }

        const cacheKey = getDnsCacheKey(serverIp, qType, domain, options);
        const cachedResult = getCacheEntry(dnsResponseCache, cacheKey);
        // 以前に同じサーバー・タイプ・ドメインに対して問い合わせ済みなら、即時復元
        if (cachedResult) {
            return resolve({ ...cachedResult, isCached: true });
        }

        let settled = false;
        let socket = null;
        let timer = null;
        let abortHandler = null;

        const finish = (result) => {
            if (settled) return;
            settled = true;
            if (timer) clearTimeout(timer);
            if (abortHandler) options.signal.removeEventListener('abort', abortHandler);
            if (socket) socket.destroy();
            resolve(result);
        };

        if (options.signal) {
            abortHandler = () => finish(buildAbortError({
                domain,
                serverIp,
                qType,
                transport: 'tcp',
                signal: options.signal
            }));
            options.signal.addEventListener('abort', abortHandler, { once: true });
        }

        const queryId = createQueryId();

        try {
            const tcpBuf = dnsPacket.streamEncode({
                type: 'query',
                id: queryId,
                questions: [{ type: qType, name: domain }],
                additionals: getAdditionals(options)
            });

            socket = net.createConnection({ host: serverIp, port: options.tcpPort }, () => {
                if (!settled) socket.write(tcpBuf);
            });

            timer = setTimeout(() => {
                const timeoutResult = buildDnsError('TIMEOUT', { domain, serverIp, qType, transport: 'tcp', retryable: true });
                setCacheEntry(dnsResponseCache, cacheKey, timeoutResult, DNS_CACHE_TTL.timeout);
                finish(timeoutResult);
            }, options.timeoutMs);

            socket.on('error', (err) => {
                const socketError = buildDnsError('SOCKET_ERROR', { domain, serverIp, qType, transport: 'tcp', detail: err.message, retryable: true });
                setCacheEntry(dnsResponseCache, cacheKey, socketError, DNS_CACHE_TTL.transient);
                finish(socketError);
            });

            let receivedData = Buffer.alloc(0);
            let totalReceivedBytes = 0;
            socket.on('data', (chunk) => {
                if (settled) return;
                totalReceivedBytes += chunk.length;
                if (totalReceivedBytes > MAX_TCP_RECEIVE_BYTES) {
                    const overflowError = buildDnsError('DECODE_ERROR', { domain, serverIp, qType, transport: 'tcp', detail: 'TCP response exceeded the size limit', retryable: false });
                    setCacheEntry(dnsResponseCache, cacheKey, overflowError, DNS_CACHE_TTL.transient);
                    return finish(overflowError);
                }
                receivedData = Buffer.concat([receivedData, chunk]);

                while (receivedData.length >= 2) {
                    // 先頭 2バイトから DNSメッセージの長さを取得
                    const msgLength = receivedData.readUInt16BE(0);
                    if (receivedData.length < msgLength + 2) break;

                    // デコード前にヘッダの id と QR ビットを確認し、無関係なメッセージは解析せず破棄する
                    if (msgLength < DNS_HEADER_LENGTH ||
                        receivedData.readUInt16BE(2) !== queryId ||
                        (receivedData[4] & DNS_QR_BIT) === 0) {
                        receivedData = receivedData.subarray(2 + msgLength);
                        continue;
                    }

                    try {
                        const decoded = dnsPacket.streamDecode(receivedData);
                        if (!decoded) break;

                        receivedData = receivedData.subarray(2 + msgLength);

                        // 遅延・不正な応答を受理しないよう、id と質問内容を照合する
                        if (!isMatchingResponse(decoded, queryId, domain, qType)) {
                            continue; // このメッセージは破棄し、後続データを引き続き待つ
                        }

                        const tcpSuccess = { ...decoded, transport: 'tcp' };
                        if (decoded.rcode === 'NOERROR') {
                            setCacheEntry(dnsResponseCache, cacheKey, tcpSuccess, computeSuccessTtlMs(decoded));
                        }
                        return finish(tcpSuccess);
                    } catch (e) {
                        const decodeError = buildDnsError('DECODE_ERROR', { domain, serverIp, qType, transport: 'tcp', detail: e.message, retryable: false });
                        setCacheEntry(dnsResponseCache, cacheKey, decodeError, DNS_CACHE_TTL.transient);
                        return finish(decodeError);
                    }
                }
            });
        } catch (e) {
            const sendError = buildDnsError('SEND_ERROR', { domain, serverIp, qType, transport: 'tcp', detail: e.message, retryable: true });
            setCacheEntry(dnsResponseCache, cacheKey, sendError, DNS_CACHE_TTL.transient);
            finish(sendError);
        }
    });
}

const UDP_QUERY_DEFAULTS = Object.freeze({
    useEdns: true,
    dnssecOk: false,
    udpPayloadSize: 1232,
    udpPort: DNS_PORT,
    tcpPort: DNS_PORT,
    timeoutMs: 5000,
    use0x20: true
});

// 応答待ちの同一 UDP 問い合わせ (サーバー・名前・タイプ・オプションが同じもの) の合流用。
// 同じ問い合わせを並行して複数送ると、偽装応答がいずれかに一致する確率が送信数に比例して上がる
// (誕生日攻撃, CERT VU#457875)。応答待ちの間は 1 本にまとめ、結果を全呼び出し元で共有する。
const inFlightUdpQueries = new Map();

function getUdpInFlightKey(cacheKey, options) {
    return `${cacheKey}|udp:${options.udpPayloadSize}|0x20:${options.use0x20 ? 1 : 0}`;
}

export function queryDirectlyUDP(domain, serverIp, dnsResponseCache, qType = 'NS', queryOptions = true) {
    const options = normalizeQueryOptions(queryOptions, UDP_QUERY_DEFAULTS);
    const callerSignal = options.signal;

    if (callerSignal?.aborted) {
        return Promise.resolve(buildAbortError({ domain, serverIp, qType, transport: 'udp', signal: callerSignal }));
    }
    if (!isIpLiteral(serverIp)) {
        return Promise.resolve(buildInvalidServerError(domain, serverIp, qType, 'udp'));
    }
    if (!isValidDnsPort(options.udpPort)) {
        return Promise.resolve(buildInvalidPortError(domain, serverIp, qType, 'udp', 'udpPort'));
    }
    if (!isValidDnsPort(options.tcpPort)) {
        return Promise.resolve(buildInvalidPortError(domain, serverIp, qType, 'udp', 'tcpPort'));
    }

    const cacheKey = getDnsCacheKey(serverIp, qType, domain, options);
    const cachedResult = getCacheEntry(dnsResponseCache, cacheKey);
    if (cachedResult) {
        return Promise.resolve({ ...cachedResult, isCached: true });
    }

    const inFlightKey = getUdpInFlightKey(cacheKey, options);
    let flight = inFlightUdpQueries.get(inFlightKey);
    if (!flight) {
        // 実際の問い合わせは呼び出し元の signal ではなく共有用の signal で制御し、
        // 待っている呼び出し元が全員中断した場合にだけ中断する
        const controller = new AbortController();
        flight = { controller, cache: dnsResponseCache, subscribers: 0, settled: false };
        flight.promise = performUdpQuery(domain, serverIp, dnsResponseCache, qType, {
            ...options,
            signal: controller.signal
        }).catch(err => buildDnsError('SOCKET_ERROR', {
            domain, serverIp, qType, transport: 'udp', detail: err?.message, retryable: true
        })).then((result) => {
            flight.settled = true;
            if (inFlightUdpQueries.get(inFlightKey) === flight) inFlightUdpQueries.delete(inFlightKey);
            return result;
        });
        inFlightUdpQueries.set(inFlightKey, flight);
    }

    flight.subscribers++;
    return new Promise((resolve) => {
        let done = false;
        let abortHandler = null;

        const leave = () => {
            done = true;
            flight.subscribers--;
            if (abortHandler) callerSignal.removeEventListener('abort', abortHandler);
        };

        if (callerSignal) {
            abortHandler = () => {
                if (done) return;
                leave();
                if (flight.subscribers === 0 && !flight.settled) {
                    if (inFlightUdpQueries.get(inFlightKey) === flight) inFlightUdpQueries.delete(inFlightKey);
                    flight.controller.abort(callerSignal.reason);
                }
                resolve(buildAbortError({ domain, serverIp, qType, transport: 'udp', signal: callerSignal }));
            };
            callerSignal.addEventListener('abort', abortHandler, { once: true });
        }

        flight.promise.then((result) => {
            if (done) return;
            leave();
            // 合流した呼び出し元が別のキャッシュを使っている場合も、問い合わせ結果のキャッシュを反映する
            if (dnsResponseCache && dnsResponseCache !== flight.cache) {
                const entry = flight.cache?.get?.(cacheKey);
                if (entry) setBounded(dnsResponseCache, cacheKey, { ...entry }, DNS_RESPONSE_CACHE_MAX_ENTRIES);
            }
            resolve({ ...result });
        });
    });
}

function performUdpQuery(domain, serverIp, dnsResponseCache, qType, options) {
    return new Promise((resolve) => {
        if (options.signal?.aborted) {
            return resolve(buildAbortError({ domain, serverIp, qType, transport: 'udp', signal: options.signal }));
        }
        if (!isIpLiteral(serverIp)) {
            return resolve(buildInvalidServerError(domain, serverIp, qType, 'udp'));
        }

        const cacheKey = getDnsCacheKey(serverIp, qType, domain, options);
        const cachedResult = getCacheEntry(dnsResponseCache, cacheKey);
        // 以前に同じサーバー・タイプ・ドメインに対して問い合わせ済みなら、即時復元
        if (cachedResult) {
            return resolve({ ...cachedResult, isCached: true });
        }

        const socketType = isIPv6(serverIp) ? 'udp6' : 'udp4';
        let client = null;
        let settled = false;
        let timer = null;
        let abortHandler = null;
        let caseMismatchSeen = false;
        let lastDecodeError = null;

        const closeClient = () => {
            if (!client) return;
            try { client.close(); } catch (e) {}
            client = null;
        };

        const finish = (result) => {
            if (settled) return;
            settled = true;
            if (timer) clearTimeout(timer);
            if (abortHandler) options.signal.removeEventListener('abort', abortHandler);
            closeClient();
            resolve(result);
        };

        // 再試行・フォールバックの結果で完了させる (現在のソケットは閉じて以降の受信を止める)
        const handOff = (promise) => {
            if (settled) return;
            if (timer) clearTimeout(timer);
            timer = null;
            closeClient();
            promise.then(finish);
        };

        if (options.signal) {
            abortHandler = () => finish(buildAbortError({
                domain,
                serverIp,
                qType,
                transport: 'udp',
                signal: options.signal
            }));
            options.signal.addEventListener('abort', abortHandler, { once: true });
        }

        const queryId = createQueryId();
        const sentName = options.use0x20 ? randomizeNameCase(domain) : domain;

        let buf;
        try {
            buf = dnsPacket.encode({
                type: 'query',
                id: queryId,
                questions: [{ type: qType, name: sentName }],
                additionals: getAdditionals(options)
            });
        } catch (e) {
            const sendError = buildDnsError('SEND_ERROR', { domain, serverIp, qType, transport: 'udp', detail: e.message, retryable: false });
            setCacheEntry(dnsResponseCache, cacheKey, sendError, DNS_CACHE_TTL.transient);
            return finish(sendError);
        }

        timer = setTimeout(() => {
            timer = null;
            // 大文字小文字を保持しないサーバーへの互換措置として、id・質問内容が一致し
            // 大文字小文字のみ異なる応答を受信していた場合に限り 0x20 なしで再試行する
            if (caseMismatchSeen && options.use0x20) {
                return handOff(queryDirectlyUDP(domain, serverIp, dnsResponseCache, qType, {
                    ...options,
                    use0x20: false
                }).then(result => ({ ...result, caseRandomizationFallback: true })));
            }
            if (lastDecodeError !== null) {
                const decodeError = buildDnsError('DECODE_ERROR', { domain, serverIp, qType, transport: 'udp', detail: lastDecodeError, retryable: false });
                setCacheEntry(dnsResponseCache, cacheKey, decodeError, DNS_CACHE_TTL.transient);
                return finish(decodeError);
            }
            const timeoutResult = buildDnsError('TIMEOUT', { domain, serverIp, qType, transport: 'udp', retryable: true });
            setCacheEntry(dnsResponseCache, cacheKey, timeoutResult, DNS_CACHE_TTL.timeout);
            return finish(timeoutResult);
        }, options.timeoutMs);

        const onMessage = (msg, rinfo) => {
            if (settled) return;
            // 想定外の送信元アドレス・ポートからの応答 (スプーフィング等) は無視し、正規の応答を待ち続ける
            if (rinfo && (String(rinfo.address).toLowerCase() !== serverIp.toLowerCase() ||
                (rinfo.port !== undefined && rinfo.port !== options.udpPort))) {
                return;
            }
            // デコード前にヘッダの id と QR ビットを確認する。不一致のデータグラムは解析もせず破棄し、
            // 偽装された不正パケット 1 つで問い合わせが打ち切られないようにする
            if (!Buffer.isBuffer(msg) || msg.length < DNS_HEADER_LENGTH ||
                msg.readUInt16BE(0) !== queryId || (msg[2] & DNS_QR_BIT) === 0) {
                return;
            }

            let decoded;
            try {
                decoded = dnsPacket.decode(msg);
            } catch (e) {
                // id が一致していても偽装の可能性があるため、確定エラーにはせず正規の応答を待ち続ける
                lastDecodeError = e.message;
                return;
            }

            try {
                const verdict = classifyResponse(decoded, queryId, sentName, qType);
                // 0x20 を使っていない場合は従来どおり大文字小文字を区別しない
                if (verdict === 'case-mismatch' && options.use0x20) {
                    caseMismatchSeen = true;
                    return;
                }
                if (verdict === 'mismatch') return;

                decoded = restoreQueryNameCase(decoded, sentName, domain);

                if (decoded.rcode === 'FORMERR' && options.useEdns) {
                    return handOff(queryDirectlyUDP(domain, serverIp, dnsResponseCache, qType, {
                        ...options,
                        useEdns: false,
                        dnssecOk: false
                    }).then(result => ({ ...result, retryWithoutEdns: true })));
                }

                const isTruncated = (decoded.flags & dnsPacket.TRUNCATED_RESPONSE) !== 0;
                if (isTruncated) {
                    return handOff(queryDirectlyTCP(domain, serverIp, dnsResponseCache, qType, options)
                        .then(
                            tcpResult => ({
                                ...tcpResult,
                                transport: tcpResult?.transport || 'tcp',
                                retryFrom: 'udp-truncated',
                                isFallback: true
                            }),
                            err => ({
                                error: 'TCP_FALLBACK_ERROR',
                                detail: err?.message || 'TCP fallback failed',
                                transport: 'tcp',
                                retryFrom: 'udp-truncated',
                                isFallback: true
                            })
                        ));
                }

                if (decoded.rcode === 'NOERROR') {
                    setCacheEntry(dnsResponseCache, cacheKey, decoded, computeSuccessTtlMs(decoded));
                }

                return finish({ ...decoded, transport: 'udp' });
            } catch (e) {
                const decodeError = buildDnsError('DECODE_ERROR', { domain, serverIp, qType, transport: 'udp', detail: e.message, retryable: false });
                setCacheEntry(dnsResponseCache, cacheKey, decodeError, DNS_CACHE_TTL.transient);
                return finish(decodeError);
            }
        };

        // バインド中のソケットも中断時に即座に閉じられるよう client に保持する
        createRandomPortSocket(socketType, (socket) => {
            if (settled) {
                try { socket.close(); } catch (e) {}
                return;
            }
            client = socket;
        })
            .then((socket) => {
                if (settled) {
                    try { socket.close(); } catch (e) {}
                    return;
                }
                client = socket;

                client.on('error', (err) => {
                    const socketError = buildDnsError('SOCKET_ERROR', { domain, serverIp, qType, transport: 'udp', detail: err.message, retryable: true });
                    setCacheEntry(dnsResponseCache, cacheKey, socketError, DNS_CACHE_TTL.transient);
                    return finish(socketError);
                });
                client.on('message', onMessage);

                client.send(buf, 0, buf.length, options.udpPort, serverIp, (err) => {
                    if (err) {
                        const sendError = buildDnsError('SEND_ERROR', { domain, serverIp, qType, transport: 'udp', detail: err.message, retryable: true });
                        setCacheEntry(dnsResponseCache, cacheKey, sendError, DNS_CACHE_TTL.transient);
                        return finish(sendError);
                    }
                });
            })
            .catch((err) => {
                const socketError = buildDnsError('SOCKET_ERROR', { domain, serverIp, qType, transport: 'udp', detail: err?.message, retryable: true });
                setCacheEntry(dnsResponseCache, cacheKey, socketError, DNS_CACHE_TTL.transient);
                return finish(socketError);
            });
    });
}

// a.root-servers.net の固定 IP。ここだけは OS/フルサービスリゾルバに頼らずに自己解決を開始するための起点。
export const ROOT_SERVER_BOOTSTRAP_IP = '198.41.0.4';
export const ROOT_SERVER_IPS = [
    ROOT_SERVER_BOOTSTRAP_IP,
    '199.9.14.201',
    '192.33.4.12',
    '199.7.91.13',
    '192.203.230.10',
    '192.5.5.241',
    '192.112.36.4',
    '198.97.190.53',
    '192.36.148.17',
    '192.58.128.30',
    '193.0.14.129',
    '199.7.83.42',
    '202.12.27.33'
];
export const NAMESERVER_IP_CACHE_TTL = 300000; // NS アドレスキャッシュの上限 (レコードに TTL が無い場合のフォールバック)
// 自己解決に失敗した NS 名の短時間ネガティブキャッシュ (同じ失敗する名前への再問い合わせ増幅を防ぐ)
export const NAMESERVER_NEGATIVE_CACHE_TTL = 5000;
export const NAMESERVER_CACHE_MAX_ENTRIES = 10000;

// NXNS 攻撃 (CVE-2020-12667 等) 型の増幅やリソース枯渇を防ぐための既定上限
export const RESOLUTION_LIMITS = Object.freeze({
    // 1 回のトップレベル解決 (入れ子の NS 名解決を含む) で送信する問い合わせ数の上限
    maxQueriesPerResolution: 100,
    // 1 つの referral から glue なしで自己解決を試みる NS 名の上限
    maxGluelessNsPerReferral: 5,
    // 1 つの referral から試行するアドレス付き候補の上限
    maxCandidatesPerReferral: 20,
    // glue なし NS 名の入れ子解決の深さ上限
    maxNsResolutionDepth: 5
});

const nameserverIpCache = new Map(); // スコープ・正規化ホスト名・gluePolicy -> { ips, expiresAt }
const nameserverNegativeCache = new Map(); // スコープ・正規化ホスト名・gluePolicy・family -> { expiresAt }
const inFlightServerResolutions = new Map(); // 同一ホスト名・ポリシーの並行解決合流用 (Singleflight)
const inFlightIpv4Resolutions = new Map();   // 同一ホスト名・ポリシーの並行解決合流用 (Singleflight)
const inFlightIpv6Resolutions = new Map();   // 同一ホスト名・ポリシーの並行解決合流用 (Singleflight)

// 結果に影響する呼び出し側固有の差し替え (knownAddresses やクエリ関数) ごとにキャッシュを分離し、
// ある呼び出し元が持ち込んだアドレスが別の呼び出し元の解決結果を汚染しないようにする
const cacheScopeIds = new WeakMap();
let nextCacheScopeId = 1;

function getIdentity(value) {
    if (!value || (typeof value !== 'object' && typeof value !== 'function')) return '-';
    if (!cacheScopeIds.has(value)) cacheScopeIds.set(value, nextCacheScopeId++);
    return String(cacheScopeIds.get(value));
}

function getCacheScope(dependencies) {
    if (typeof dependencies === 'string') return dependencies;
    if (!dependencies) return `default|udp:${DNS_PORT},tcp:${DNS_PORT}`;
    const queryOptions = dependencies.queryOptions || {};
    const portScope = `udp:${queryOptions.udpPort ?? DNS_PORT},tcp:${queryOptions.tcpPort ?? DNS_PORT}`;
    const parts = [
        dependencies.knownAddresses,
        dependencies.queryDirectlyUDP,
        dependencies.resolveHostnameIPv4Self,
        dependencies.resolveHostnameIPv6Self
    ].map(getIdentity);
    return `${parts.every(part => part === '-') ? 'default' : `scope:${parts.join(',')}`}|${portScope}`;
}

function getNameserverResolutionKey(hostname, gluePolicy = 'strict', scope = 'default') {
    return `${scope}|${normalizeDnsName(hostname)}|glue:${gluePolicy}`;
}

function getResolutionLimits(dependencies = {}) {
    const overrides = dependencies.resolutionLimits || {};
    const limits = { ...RESOLUTION_LIMITS };
    for (const key of Object.keys(RESOLUTION_LIMITS)) {
        const value = overrides[key];
        if (Number.isInteger(value) && value > 0) limits[key] = value;
    }
    return limits;
}

// 入れ子の解決全体で共有する問い合わせ予算
function getResolutionBudget(dependencies = {}) {
    if (dependencies.resolutionBudget) return dependencies.resolutionBudget;
    return {
        remaining: getResolutionLimits(dependencies).maxQueriesPerResolution,
        // 予算超過・深さ上限・循環検出など経路依存の打ち切りが起きた回数 (ネガティブキャッシュ可否の判定に使う)
        limitHits: 0
    };
}

function consumeQueryBudget(budget) {
    if (budget.remaining <= 0) {
        budget.limitHits++;
        return false;
    }
    budget.remaining--;
    return true;
}

function markLimitHit(dependencies) {
    if (dependencies?.resolutionBudget) dependencies.resolutionBudget.limitHits++;
}

function getUnexpiredEntry(map, key) {
    const entry = map.get(key);
    if (!entry) return null;
    if (entry.expiresAt <= Date.now()) {
        map.delete(key);
        return null;
    }
    return entry;
}

export function getCachedNameserverIPs(hostname, gluePolicy = 'strict', dependencies = {}) {
    const key = getNameserverResolutionKey(hostname, gluePolicy, getCacheScope(dependencies));
    return getUnexpiredEntry(nameserverIpCache, key)?.ips || null;
}

export function cacheNameserverIPs(
    hostname,
    ips,
    ttlMs = NAMESERVER_IP_CACHE_TTL,
    gluePolicy = 'strict',
    dependencies = {}
) {
    if (!hostname || !Array.isArray(ips)) return;
    const validIps = ips.filter(isIpLiteral);
    if (validIps.length === 0 || !(ttlMs > 0)) return;
    setBounded(
        nameserverIpCache,
        getNameserverResolutionKey(hostname, gluePolicy, getCacheScope(dependencies)),
        { ips: validIps, expiresAt: Date.now() + Math.min(ttlMs, NAMESERVER_IP_CACHE_TTL) },
        NAMESERVER_CACHE_MAX_ENTRIES
    );
}

function getNegativeCacheKey(hostname, gluePolicy, scope, family) {
    return `${getNameserverResolutionKey(hostname, gluePolicy, scope)}|${family}`;
}

function isNegativelyCached(hostname, gluePolicy, scope, family) {
    return getUnexpiredEntry(nameserverNegativeCache, getNegativeCacheKey(hostname, gluePolicy, scope, family)) !== null;
}

function cacheNegativeResult(hostname, gluePolicy, scope, family) {
    setBounded(
        nameserverNegativeCache,
        getNegativeCacheKey(hostname, gluePolicy, scope, family),
        { expiresAt: Date.now() + NAMESERVER_NEGATIVE_CACHE_TTL },
        NAMESERVER_CACHE_MAX_ENTRIES
    );
}

export function getKnownAddress(knownAddresses, hostname, family = 'any') {
    if (!knownAddresses || !hostname) return null;
    const normalized = normalizeDnsName(hostname);
    let val = null;
    if (knownAddresses instanceof Map) {
        val = knownAddresses.get(normalized) || knownAddresses.get(hostname);
    } else if (typeof knownAddresses === 'object') {
        // NS 名はリモートから与えられるため、`constructor` や `__proto__` 等のプロトタイプ上のプロパティを参照しない
        if (Object.hasOwn(knownAddresses, normalized)) {
            val = knownAddresses[normalized];
        } else if (Object.hasOwn(knownAddresses, hostname)) {
            val = knownAddresses[hostname];
        }
    }
    if (!val) return null;
    const list = (Array.isArray(val) ? val : [val]).filter(isIpLiteral);
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

// referral は「問い合わせ中のサーバーゾーンの真の子孫」かつ「問い合わせ名の祖先 (または同一)」でなければならない。
// 上向き・横向きの referral (lame delegation や偽装) を受け入れると、解決経路を任意のサーバーへ誘導されうる
function isValidReferral(delegatedZone, serverZone, queryName) {
    if (!delegatedZone) return false;
    if (!isSubdomainOrEqual(queryName, delegatedZone)) return false;
    if (serverZone === '.' || !normalizeDnsName(serverZone)) return true;
    return delegatedZone !== normalizeDnsName(serverZone) && isSubdomainOrEqual(delegatedZone, serverZone);
}

// ルートから委任を辿って解決し、レコードと TTL、および上限・中断で打ち切られていないかを返す
async function resolveFromRootDetailed(name, qType, dnsResponseCache, dependencies = {}) {
    const queryUDP = dependencies.queryDirectlyUDP || queryDirectlyUDP;
    const resolveIPv4 = dependencies.resolveHostnameIPv4Self || resolveHostnameIPv4Self;
    const resolveIPv6 = dependencies.resolveHostnameIPv6Self || resolveHostnameIPv6Self;
    const gluePolicy = dependencies.gluePolicy || 'strict';
    const limits = getResolutionLimits(dependencies);
    const budget = getResolutionBudget(dependencies);
    const cache = dnsResponseCache || dependencies.dnsResponseCache || dependencies.cache || new Map();
    // 入れ子の NS 名解決にも同じ応答キャッシュと問い合わせ予算を引き継ぐ
    const nestedDependencies = { ...dependencies, dnsResponseCache: cache, resolutionBudget: budget };
    const queryOptions = {
        ...(dependencies.queryOptions || {}),
        ...(dependencies.signal ? { signal: dependencies.signal } : {})
    };
    const limitHitsAtStart = budget.limitHits;
    let minTtl = null;
    const trackTtl = (record) => {
        if (typeof record?.ttl === 'number' && record.ttl >= 0) {
            minTtl = minTtl === null ? record.ttl : Math.min(minTtl, record.ttl);
        }
    };
    const isAborted = () => queryOptions.signal?.aborted === true;
    const done = (records) => ({
        records,
        ttlSeconds: minTtl,
        complete: !isAborted() && budget.limitHits === limitHitsAtStart
    });

    let queryName = normalizeDnsName(name);
    let currentServerIp = ROOT_SERVER_BOOTSTRAP_IP;
    let currentServerZone = '.';
    let candidateQueue = ROOT_SERVER_IPS.slice(1).map(ip => ({ ip, zone: '.' }));
    const visitedNames = new Set([queryName]);

    const resolveNsAddress = async (nsName) => {
        const v4 = await resolveIPv4(nsName, nestedDependencies);
        if (isIpLiteral(v4)) return v4;
        if (isAborted()) return null;
        const v6 = await resolveIPv6(nsName, nestedDependencies);
        return isIpLiteral(v6) ? v6 : null;
    };

    const useNextCandidate = async () => {
        while (candidateQueue.length > 0) {
            if (isAborted()) return false;
            if (budget.remaining <= 0) {
                budget.limitHits++;
                return false;
            }
            const candidate = candidateQueue.shift();
            const ip = isIpLiteral(candidate.ip)
                ? candidate.ip
                : (candidate.nsName ? await resolveNsAddress(candidate.nsName) : null);
            if (ip) {
                currentServerIp = ip;
                currentServerZone = candidate.zone;
                return true;
            }
        }
        return false;
    };

    for (let depth = 0; depth < 10; depth++) {
        if (isAborted()) return done([]);
        if (!consumeQueryBudget(budget)) return done([]);

        let res;
        try {
            res = await queryUDP(queryName, currentServerIp, cache, qType, queryOptions);
        } catch (e) {
            res = { error: 'QUERY_EXCEPTION', detail: e?.message };
        }
        if (res?.error === 'ABORTED') return done([]);
        if (!res || res.error) {
            if (await useNextCandidate()) continue;
            return done([]);
        }

        const matchedAnswers = (res.answers || [])
            .filter(record => record.type === qType && normalizeDnsName(record.name) === queryName);
        if (matchedAnswers.length > 0) {
            matchedAnswers.forEach(trackTtl);
            return done(matchedAnswers.map(record => record.data));
        }

        const cname = (res.answers || []).find(record =>
            record.type === 'CNAME' && normalizeDnsName(record.name) === queryName);
        if (cname) {
            const cnameTarget = normalizeDnsName(cname.data);
            if (!cnameTarget || visitedNames.has(cnameTarget)) return done([]);
            trackTtl(cname);
            visitedNames.add(cnameTarget);
            queryName = cnameTarget;
            currentServerIp = ROOT_SERVER_BOOTSTRAP_IP;
            currentServerZone = '.';
            candidateQueue = ROOT_SERVER_IPS.slice(1).map(ip => ({ ip, zone: '.' }));
            continue;
        }

        const AUTHORITATIVE_ANSWER = dnsPacket.AUTHORITATIVE_ANSWER || 1024;
        const isAuthoritative = (res.flags & AUTHORITATIVE_ANSWER) !== 0;
        if (isAuthoritative) {
            return done([]); // 権威応答だが対象レコードが無い (NODATA/NXDOMAIN)
        }

        const allNsRecords = (res.authorities || []).filter(r => r.type === 'NS');
        const delegatedZone = allNsRecords.length > 0 ? normalizeDnsName(allNsRecords[0].name) : '';
        if (allNsRecords.length === 0 || !isValidReferral(delegatedZone, currentServerZone, queryName)) {
            if (await useNextCandidate()) continue;
            return done([]);
        }
        const nsRecords = allNsRecords.filter(r => normalizeDnsName(r.name) === delegatedZone);

        const nsNames = [...new Set(nsRecords.map(r => normalizeDnsName(r.data)).filter(Boolean))];
        const referralAddressByNsName = new Map();
        getReferralAddressRecords(
            res.additionals || [],
            nsNames,
            delegatedZone,
            gluePolicy,
            currentServerZone
        )
            .forEach(record => {
                if (!isIpLiteral(record.data)) return;
                const key = normalizeDnsName(record.name);
                const addresses = referralAddressByNsName.get(key) || [];
                if (!addresses.includes(record.data)) addresses.push(record.data);
                referralAddressByNsName.set(key, addresses);
            });

        // 参照アドレスを持つ候補を優先し、無い候補は捨てずにフォールバック用に保持する。
        // knownAddresses が指定されていれば referral アドレスがない候補の事前解決アドレスとしても参照する。
        // NXNS 型の増幅を防ぐため、試行する候補数 (特に glue なしで自己解決する NS 名) には上限を設ける。
        const candidates = nsNames.flatMap(nsName => {
            const referralAddresses = referralAddressByNsName.get(nsName) || [];
            const knownAddresses = dependencies.knownAddresses
                ? getKnownAddress(dependencies.knownAddresses, nsName)
                : [];
            const addresses = [...new Set([...referralAddresses, ...(knownAddresses || [])])];
            return addresses.length > 0
                ? addresses.map(ip => ({ nsName, ip, zone: delegatedZone }))
                : [{ nsName, ip: null, zone: delegatedZone }];
        });
        candidateQueue = [
            ...candidates.filter(c => c.ip).slice(0, limits.maxCandidatesPerReferral),
            ...candidates.filter(c => !c.ip).slice(0, limits.maxGluelessNsPerReferral)
        ];

        // グルーが無い NS 名は再帰的に自己解決する (循環参照は resolveHostnameIPv4Self 側で検出)
        if (await useNextCandidate()) continue;
        return done([]);
    }

    budget.limitHits++;
    return done([]);
}

// ルートサーバーから委任を辿って name の qType レコードを自己解決する (フルサービスリゾルバのキャッシュを経由しない)。
export async function resolveRecordFromRoot(name, qType, dnsResponseCache, dependencies = {}) {
    const result = await resolveFromRootDetailed(name, qType, dnsResponseCache, dependencies);
    return result.records;
}

export async function resolveDnsServerAddressByType(
    dnsServer,
    preferIpv6 = false,
    resolutionDepth = 0,
    dependencies = {}
) {
    const normalized = normalizeDnsName(dnsServer);
    if (net.isIP(normalized)) {
        return normalized;
    }
    if (resolutionDepth >= 5) {
        throw new Error('DNSサーバー名の解決で入れ子の委任が上限を超えました。');
    }

    const family = preferIpv6 ? 'AAAA' : 'A';
    const known = getKnownAddress(dependencies.knownAddresses, normalized, family);
    if (known && known.length > 0) return known[0];

    const cache = dependencies.dnsResponseCache || dependencies.cache || new Map();
    const resolver = dependencies.resolveRecordFromRoot || resolveRecordFromRoot;
    const addresses = await resolver(normalized, family, cache, {
        ...dependencies,
        resolvingStack: new Set(dependencies.resolvingStack || []).add(normalized)
    });
    const address = (addresses || []).find(candidate =>
        net.isIP(candidate) === (preferIpv6 ? 6 : 4));
    if (address) return address;
    throw new Error(`DNSサーバー名 ${dnsServer} の ${family} レコードが見つかりませんでした。`);
}

export async function resolveDnsServerAddress(
    dnsServer,
    preferIpv6 = false,
    resolutionDepth = 0,
    dependencies = {}
) {
    try {
        return await resolveDnsServerAddressByType(dnsServer, preferIpv6, resolutionDepth, dependencies);
    } catch (error) {
        if (preferIpv6) throw error;
        try {
            return await resolveDnsServerAddressByType(dnsServer, true, resolutionDepth, dependencies);
        } catch {
            throw error;
        }
    }
}

// NS 名のアドレス解決の共通処理 (循環・深さ上限・ネガティブキャッシュ・Singleflight・TTL に基づくキャッシュ)。
// family: 'A' | 'AAAA' | 'ANY'。成功時は IP の配列、失敗時は null を返す。
async function resolveNameserverAddresses(normalized, dependencies, family, inFlightMap) {
    const gluePolicy = dependencies.gluePolicy || 'strict';
    const scope = getCacheScope(dependencies);
    const limits = getResolutionLimits(dependencies);

    const resolvingStack = dependencies.resolvingStack || new Set();
    if (resolvingStack.has(normalized)) {
        markLimitHit(dependencies);
        return null; // 循環参照 (グルーレコード不足の可能性)
    }
    if (resolvingStack.size >= limits.maxNsResolutionDepth) {
        markLimitHit(dependencies);
        return null; // glue なし NS 名の入れ子が深すぎる (NXNS 型の増幅対策)
    }
    if (isNegativelyCached(normalized, gluePolicy, scope, family)) return null;

    const resolutionKey = `${getNameserverResolutionKey(normalized, gluePolicy, scope)}|${family}`;
    const shareInFlight = !dependencies.signal;
    if (shareInFlight && inFlightMap.has(resolutionKey)) {
        const shared = await inFlightMap.get(resolutionKey);
        // 合流先の失敗は別の解決経路の上限による打ち切りかもしれないため、呼び出し側でキャッシュさせない
        if (!shared) markLimitHit(dependencies);
        return shared;
    }

    const budget = getResolutionBudget(dependencies);
    const childDependencies = {
        ...dependencies,
        resolvingStack: new Set(resolvingStack).add(normalized),
        resolutionBudget: budget
    };

    const promise = (async () => {
        const dnsResponseCache = dependencies.dnsResponseCache || dependencies.cache || new Map();
        const qTypes = family === 'ANY' ? ['A', 'AAAA'] : [family];
        const results = await Promise.all(qTypes.map(qType =>
            resolveFromRootDetailed(normalized, qType, dnsResponseCache, childDependencies)));
        const ips = results.flatMap(result => result.records).filter(isIpLiteral);
        if (ips.length > 0) {
            const ttls = results.map(result => result.ttlSeconds).filter(ttl => ttl !== null);
            const ttlMs = ttls.length > 0
                ? Math.min(Math.min(...ttls) * 1000, NAMESERVER_IP_CACHE_TTL)
                : NAMESERVER_IP_CACHE_TTL;
            cacheNameserverIPs(normalized, ips, ttlMs, gluePolicy, scope);
            return ips;
        }
        // 上限や中断で打ち切られた失敗は経路依存のためキャッシュせず、確定的な失敗のみ短時間キャッシュする
        if (results.every(result => result.complete) && !dependencies.signal?.aborted) {
            cacheNegativeResult(normalized, gluePolicy, scope, family);
        }
        return null;
    })();

    if (shareInFlight) inFlightMap.set(resolutionKey, promise);
    try {
        return await promise;
    } finally {
        if (shareInFlight) inFlightMap.delete(resolutionKey);
    }
}

// NS 名の IP アドレス解決専用の入り口。グルー不足時の再帰呼び出しで循環参照を検出する。
export async function resolveHostnameIPv4Self(hostname, dependencies = {}) {
    const normalized = normalizeDnsName(hostname);
    const gluePolicy = dependencies.gluePolicy || 'strict';
    if (net.isIP(normalized)) {
        return isIPv6(normalized) ? null : normalized;
    }

    const known = getKnownAddress(dependencies.knownAddresses, normalized, 'A');
    if (known && known.length > 0) return known[0];

    const cached = getCachedNameserverIPs(normalized, gluePolicy, dependencies);
    const cachedV4 = cached?.find(ip => !isIPv6(ip));
    if (cachedV4) return cachedV4;

    const ips = await resolveNameserverAddresses(normalized, dependencies, 'A', inFlightIpv4Resolutions);
    return ips?.find(ip => !isIPv6(ip)) || null;
}

// NS 名の IPv6 アドレス解決専用の入り口。IPv4 glue が無い委任でも AAAA glue/応答を辿れるようにする。
export async function resolveHostnameIPv6Self(hostname, dependencies = {}) {
    const normalized = normalizeDnsName(hostname);
    const gluePolicy = dependencies.gluePolicy || 'strict';
    if (net.isIP(normalized)) {
        return isIPv6(normalized) ? normalized : null;
    }

    const known = getKnownAddress(dependencies.knownAddresses, normalized, 'AAAA');
    if (known && known.length > 0) return known[0];

    const cached = getCachedNameserverIPs(normalized, gluePolicy, dependencies);
    const cachedV6 = cached?.find(ip => isIPv6(ip));
    if (cachedV6) return cachedV6;

    const ips = await resolveNameserverAddresses(normalized, dependencies, 'AAAA', inFlightIpv6Resolutions);
    return ips?.find(ip => isIPv6(ip)) || null;
}

// フルサービスリゾルバ (OS のスタブリゾルバ経由) には依存せず、ルートサーバーから自前で NS 名を解決する。
export async function resolveServerIPs(nsName, dependencies = {}) {
    const normalized = normalizeDnsName(nsName);
    const gluePolicy = dependencies.gluePolicy || 'strict';
    if (net.isIP(normalized)) return [normalized];

    const known = getKnownAddress(dependencies.knownAddresses, normalized);
    if (known && known.length > 0) return known;

    const cached = getCachedNameserverIPs(normalized, gluePolicy, dependencies);
    if (cached && cached.length > 0) return cached;

    return resolveNameserverAddresses(normalized, dependencies, 'ANY', inFlightServerResolutions);
}
