import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import test from 'node:test';
import dgram from 'node:dgram';
import net from 'node:net';
import dnsPacket from 'dns-packet';

import {
    hasParentChildRelationship,
    isInBailiwickGlue,
    isIPv6,
    isSubdomainOrEqual,
    normalizeDnsName,
    queryDirectlyTCP,
    queryDirectlyUDP,
    resolveRecordFromRoot,
    resolveServerIPs,
    resolveHostnameIPv4Self,
    resolveRecordFromServer,
    resolveDnsServerAddressByType,
    resolveDnsServerAddress,
    ROOT_SERVER_BOOTSTRAP_IP
} from '../index.js';

function createDnsResponse(query, flags = 0) {
    return dnsPacket.encode({
        type: 'response',
        id: query.id,
        flags,
        questions: query.questions,
        answers: [{
            type: 'NS',
            name: query.questions[0].name,
            ttl: 300,
            data: 'a.gtld-servers.net'
        }]
    });
}

function createDnssecDsResponse(query) {
    return dnsPacket.encode({
        type: 'response',
        id: query.id,
        questions: query.questions,
        answers: [
            {
                type: 'DS',
                name: 'com',
                ttl: 86400,
                data: {
                    keyTag: 19718,
                    algorithm: 13,
                    digestType: 2,
                    digest: Buffer.alloc(32, 1)
                }
            },
            {
                type: 'RRSIG',
                name: 'com',
                ttl: 86400,
                data: {
                    typeCovered: 'DS',
                    algorithm: 8,
                    labels: 1,
                    originalTTL: 86400,
                    expiration: 2000000000,
                    inception: 1900000000,
                    keyTag: 12345,
                    signersName: '.',
                    signature: Buffer.alloc(64, 2)
                }
            }
        ]
    });
}

function mockUdp(onQuery) {
    const originalCreateSocket = dgram.createSocket;
    dgram.createSocket = () => {
        const socket = new EventEmitter();
        socket.close = () => {};
        socket.send = (buffer, offset, length, port, host, callback) => {
            callback?.(null);
            onQuery(dnsPacket.decode(buffer), socket, host);
        };
        return socket;
    };
    return () => {
        dgram.createSocket = originalCreateSocket;
    };
}

test('DNS 名を小文字化し、末尾ドットを除去する', () => {
    assert.equal(normalizeDnsName(' NS1.Example.COM. '), 'ns1.example.com');
    assert.equal(normalizeDnsName(null), '');
});

test('サブドメインまたは同一名だけを親子関係として判定する', () => {
    assert.equal(isSubdomainOrEqual('www.example.com', 'example.com'), true);
    assert.equal(isSubdomainOrEqual('example.com.', 'example.com'), true);
    assert.equal(isSubdomainOrEqual('example.com', 'ample.com'), false);
    assert.equal(isSubdomainOrEqual('example.net', 'example.com'), false);
    assert.equal(hasParentChildRelationship('www.example.com', 'example.com'), true);
    assert.equal(hasParentChildRelationship('example.com', 'www.example.com'), true);
    assert.equal(hasParentChildRelationship('example.net', 'example.com'), false);
});

test('IPv4 と IPv6 を識別する', () => {
    assert.equal(isIPv6('2001:db8::53'), true);
    assert.equal(isIPv6('192.0.2.53'), false);
});

test('in-domain glue だけを採用する', () => {
    const nsNames = ['ns1.child.example.com', 'ns2.external.example.net'];

    assert.equal(
        isInBailiwickGlue(
            { type: 'A', name: 'ns1.child.example.com' },
            nsNames,
            'child.example.com'
        ),
        true
    );
    assert.equal(
        isInBailiwickGlue(
            { type: 'AAAA', name: 'ns2.external.example.net' },
            nsNames,
            'child.example.com'
        ),
        false
    );
    assert.equal(
        isInBailiwickGlue(
            { type: 'TXT', name: 'ns1.child.example.com' },
            nsNames,
            'child.example.com'
        ),
        false
    );
});

test('queryDirectlyUDP sets DO and separates DO/EDNS cache entries', async () => {
    const queries = [];
    const restoreUdp = mockUdp((query, socket) => {
        queries.push(query);
        queueMicrotask(() => socket.emit('message', createDnsResponse(query)));
    });

    try {
        const cache = new Map();
        await queryDirectlyUDP('com', '192.0.2.1', cache, 'NS', false);
        await queryDirectlyUDP('com', '192.0.2.1', cache, 'NS', {
            useEdns: true,
            dnssecOk: true,
            udpPayloadSize: 1400
        });
        const cached = await queryDirectlyUDP('com', '192.0.2.1', cache, 'NS', {
            useEdns: true,
            dnssecOk: true,
            udpPayloadSize: 1400
        });

        assert.equal(queries.length, 2);
        assert.equal(queries[0].additionals.length, 0);
        assert.equal(queries[1].additionals[0].flags, dnsPacket.DNSSEC_OK);
        assert.equal(queries[1].additionals[0].udpPayloadSize, 1400);
        assert.equal(cached.isCached, true);
    } finally {
        restoreUdp();
    }
});

test('FORMERR retries without EDNS', async () => {
    const queries = [];
    const restoreUdp = mockUdp((query, socket) => {
        queries.push(query);
        const response = queries.length === 1
            ? dnsPacket.encode({ type: 'response', id: query.id, flags: 1 })
            : createDnsResponse(query);
        queueMicrotask(() => socket.emit('message', response));
    });

    try {
        const result = await queryDirectlyUDP('formerr.test', '192.0.2.2', new Map(), 'NS', {
            useEdns: true,
            dnssecOk: true
        });

        assert.equal(queries.length, 2);
        assert.equal(queries[0].additionals[0].flags, dnsPacket.DNSSEC_OK);
        assert.equal(queries[1].additionals.length, 0);
        assert.equal(result.retryWithoutEdns, true);
    } finally {
        restoreUdp();
    }
});

test('DO query for com DS returns DS and RRSIG records', async () => {
    let sentQuery;
    const restoreUdp = mockUdp((query, socket) => {
        sentQuery = query;
        queueMicrotask(() => socket.emit('message', createDnssecDsResponse(query)));
    });

    try {
        const result = await queryDirectlyUDP('com', '198.41.0.4', new Map(), 'DS', {
            useEdns: true,
            dnssecOk: true
        });

        assert.equal(sentQuery.additionals[0].flags, dnsPacket.DNSSEC_OK);
        assert.deepEqual(result.answers.map(record => record.type), ['DS', 'RRSIG']);
        assert.equal(result.answers[1].data.typeCovered, 'DS');
    } finally {
        restoreUdp();
    }
});

test('UDP truncation preserves DO during TCP fallback', async () => {
    const originalCreateConnection = net.createConnection;
    let tcpQuery;
    const restoreUdp = mockUdp((query, socket) => {
        queueMicrotask(() => socket.emit(
            'message',
            createDnsResponse(query, dnsPacket.TRUNCATED_RESPONSE)
        ));
    });

    net.createConnection = (options, onConnect) => {
        const socket = new EventEmitter();
        socket.destroy = () => {};
        socket.write = (buffer) => {
            tcpQuery = dnsPacket.streamDecode(buffer);
            queueMicrotask(() => socket.emit('data', dnsPacket.streamEncode({
                type: 'response',
                id: tcpQuery.id,
                questions: tcpQuery.questions,
                answers: []
            })));
        };
        queueMicrotask(onConnect);
        return socket;
    };

    try {
        const result = await queryDirectlyUDP('com', '192.0.2.1', new Map(), 'DS', {
            dnssecOk: true,
            timeoutMs: 100
        });

        assert.equal(tcpQuery.additionals[0].flags, dnsPacket.DNSSEC_OK);
        assert.equal(result.transport, 'tcp');
        assert.equal(result.isFallback, true);
    } finally {
        restoreUdp();
        net.createConnection = originalCreateConnection;
    }
});

test('TCP query finishes after receiving a complete message without waiting for close', async () => {
    const originalCreateConnection = net.createConnection;
    let destroyed = false;

    net.createConnection = (options, onConnect) => {
        const socket = new EventEmitter();
        socket.destroy = () => {
            destroyed = true;
        };
        socket.write = (buffer) => {
            const query = dnsPacket.streamDecode(buffer);
            const response = dnsPacket.streamEncode({
                type: 'response',
                id: query.id,
                questions: query.questions,
                answers: [{ name: 'example.test', type: 'A', data: '192.0.2.10' }]
            });
            queueMicrotask(() => {
                socket.emit('data', response.subarray(0, 3));
                socket.emit('data', response.subarray(3));
            });
        };
        queueMicrotask(onConnect);
        return socket;
    };

    try {
        const result = await queryDirectlyTCP(
            'example.test',
            '192.0.2.3',
            new Map(),
            'A',
            { timeoutMs: 100 }
        );

        assert.equal(result.answers[0].data, '192.0.2.10');
        assert.equal(destroyed, true);
    } finally {
        net.createConnection = originalCreateConnection;
    }
});

test('a candidate without any referral address falls back to recursive self-resolution', async () => {
    const calls = [];
    const resolvedHosts = [];
    const result = await resolveRecordFromRoot('host.glue-fallback.test', 'A', new Map(), {
        queryDirectlyUDP: async (domain, serverIp) => {
            calls.push(serverIp);
            if (serverIp === ROOT_SERVER_BOOTSTRAP_IP) {
                return {
                    authorities: [
                        { name: 'glue-fallback.test', type: 'NS', data: 'ns1.glue-fallback.test' },
                        { name: 'glue-fallback.test', type: 'NS', data: 'ns2.external.test' }
                    ],
                    additionals: [
                        { name: 'ns1.glue-fallback.test', type: 'A', data: '192.0.2.11' }
                    ]
                };
            }
            if (serverIp === '192.0.2.11') return { error: 'SOCKET_ERROR' };
            assert.equal(serverIp, '192.0.2.20');
            return {
                answers: [{ name: domain, type: 'A', data: '192.0.2.30' }]
            };
        },
        resolveHostnameIPv4Self: async hostname => {
            resolvedHosts.push(hostname);
            return hostname === 'ns2.external.test' ? '192.0.2.20' : null;
        }
    });

    assert.deepEqual(result, ['192.0.2.30']);
    assert.deepEqual(calls, [ROOT_SERVER_BOOTSTRAP_IP, '192.0.2.11', '192.0.2.20']);
    assert.deepEqual(resolvedHosts, ['ns2.external.test']);
});

test('out-of-bailiwick referral address (root -> com) is used without recursive self-resolution', async () => {
    const calls = [];
    const resolvedHosts = [];
    // a.gtld-servers.net はルートから見て out-of-bailiwick (com. 配下ではない) だが、
    // 探索用の参照アドレスとして additionals に含まれる。
    const result = await resolveRecordFromRoot('example.com', 'NS', new Map(), {
        queryDirectlyUDP: async (domain, serverIp) => {
            calls.push(serverIp);
            if (serverIp === ROOT_SERVER_BOOTSTRAP_IP) {
                return {
                    authorities: [
                        { name: 'com', type: 'NS', data: 'a.gtld-servers.net' }
                    ],
                    additionals: [
                        { name: 'a.gtld-servers.net', type: 'A', data: '192.5.6.30' }
                    ]
                };
            }
            assert.equal(serverIp, '192.5.6.30');
            return {
                answers: [{ name: domain, type: 'NS', data: 'ns1.example.com' }]
            };
        },
        resolveHostnameIPv4Self: async hostname => {
            resolvedHosts.push(hostname);
            return null;
        }
    });

    assert.deepEqual(result, ['ns1.example.com']);
    assert.deepEqual(calls, [ROOT_SERVER_BOOTSTRAP_IP, '192.5.6.30']);
    // 参照アドレスがそのまま使われ、循環しうる自己解決へは進まない。
    assert.deepEqual(resolvedHosts, []);
});

test('resolveServerIPs returns knownAddresses without root resolution', async () => {
    const knownAddresses = {
        'ns1.yodobashi.com': '219.127.199.121',
        'ns2.yodobashi.com': ['219.127.199.122', '2001:db8::122']
    };

    const ips1 = await resolveServerIPs('ns1.yodobashi.com', { knownAddresses });
    assert.deepEqual(ips1, ['219.127.199.121']);

    const ips2 = await resolveServerIPs('ns2.yodobashi.com', { knownAddresses });
    assert.deepEqual(ips2, ['219.127.199.122', '2001:db8::122']);
});

test('resolveRecordFromRoot uses knownAddresses for referral candidates missing glue', async () => {
    const calls = [];
    const resolvedHosts = [];
    const knownAddresses = new Map([
        ['ns1.missing-glue.test', '192.0.2.77']
    ]);

    const result = await resolveRecordFromRoot('target.missing-glue.test', 'A', new Map(), {
        knownAddresses,
        queryDirectlyUDP: async (domain, serverIp) => {
            calls.push(serverIp);
            if (serverIp === ROOT_SERVER_BOOTSTRAP_IP) {
                return {
                    authorities: [
                        { name: 'missing-glue.test', type: 'NS', data: 'ns1.missing-glue.test' }
                    ],
                    additionals: [] // no glue in referral
                };
            }
            assert.equal(serverIp, '192.0.2.77');
            return {
                answers: [{ name: domain, type: 'A', data: '192.0.2.88' }]
            };
        },
        resolveHostnameIPv4Self: async hostname => {
            resolvedHosts.push(hostname);
            return null;
        }
    });

    assert.deepEqual(result, ['192.0.2.88']);
    assert.deepEqual(calls, [ROOT_SERVER_BOOTSTRAP_IP, '192.0.2.77']);
    assert.deepEqual(resolvedHosts, []);
});

test('concurrent resolution of the same NS name shares promise without returning null', async () => {
    let queryCount = 0;
    const mockQueryUDP = async (domain, serverIp, cache, qType) => {
        // slight delay to simulate async network
        await new Promise(r => setTimeout(r, 10));
        queryCount++;
        return {
            flags: 1024,
            answers: [{ name: domain, type: qType, data: qType === 'A' ? '192.0.2.55' : '2001:db8::55' }]
        };
    };

    const [res1, res2, res3] = await Promise.all([
        resolveServerIPs('concurrent-ns.example.com', { queryDirectlyUDP: mockQueryUDP }),
        resolveServerIPs('concurrent-ns.example.com', { queryDirectlyUDP: mockQueryUDP }),
        resolveServerIPs('concurrent-ns.example.com', { queryDirectlyUDP: mockQueryUDP })
    ]);

    assert.deepEqual(res1, ['192.0.2.55', '2001:db8::55']);
    assert.deepEqual(res2, ['192.0.2.55', '2001:db8::55']);
    assert.deepEqual(res3, ['192.0.2.55', '2001:db8::55']);
    // All 3 callers shared the singleflight resolution
    assert.equal(queryCount, 2); // 1 for A and 1 for AAAA
});

test('cycle in NS self-resolution properly returns null', async () => {
    // ns1.cyclic.test delegates to ns1.cyclic.test with no glue
    const mockQueryUDP = async (domain, serverIp, cache, qType) => {
        return {
            authorities: [
                { name: 'cyclic.test', type: 'NS', data: 'ns1.cyclic.test' }
            ],
            additionals: []
        };
    };

    const result = await resolveServerIPs('ns1.cyclic.test', { queryDirectlyUDP: mockQueryUDP });
    assert.equal(result, null);
});

test('resolveRecordFromServer queries specified server for A and AAAA', async () => {
    const queries = [];
    const mockQueryUDP = async (domain, serverIp, cache, qType) => {
        queries.push({ domain, serverIp, qType });
        if (qType === 'A') {
            return {
                answers: [{ name: domain, type: 'A', data: '192.0.2.99' }]
            };
        }
        if (qType === 'AAAA') {
            return {
                answers: [{ name: domain, type: 'AAAA', data: '2001:db8::99' }]
            };
        }
        return { answers: [] };
    };

    const ips = await resolveRecordFromServer('auth.example.com', '192.0.2.1', ['A', 'AAAA'], new Map(), {
        queryDirectlyUDP: mockQueryUDP
    });

    assert.deepEqual(ips, ['192.0.2.99', '2001:db8::99']);
    assert.equal(queries.length, 2);
    assert.equal(queries[0].serverIp, '192.0.2.1');
    assert.equal(queries[1].serverIp, '192.0.2.1');
});

test('resolveRecordFromRoot follows CNAME before returning the requested type', async () => {
    const queries = [];
    const result = await resolveRecordFromRoot('alias.example.test', 'A', new Map(), {
        queryDirectlyUDP: async (domain, serverIp, cache, qType) => {
            queries.push({ domain, serverIp, qType });
            if (domain === 'alias.example.test') {
                return { answers: [{ name: domain, type: 'CNAME', data: 'target.example.test' }] };
            }
            return { answers: [{ name: domain, type: 'A', data: '192.0.2.45' }] };
        }
    });

    assert.deepEqual(result, ['192.0.2.45']);
    assert.deepEqual(queries.map(query => query.domain), ['alias.example.test', 'target.example.test']);
});

test('resolveDnsServerAddressByType resolves the requested address family', async () => {
    const calls = [];
    const dependencies = {
        resolveRecordFromRoot: async (name, qType) => {
            calls.push({ name, qType });
            return qType === 'AAAA' ? ['2001:db8::53'] : [];
        }
    };

    assert.equal(
        await resolveDnsServerAddressByType('ns.example.test', true, 0, dependencies),
        '2001:db8::53'
    );
    assert.deepEqual(calls, [{ name: 'ns.example.test', qType: 'AAAA' }]);
});

test('resolveDnsServerAddress falls back from A to AAAA', async () => {
    const queriedTypes = [];
    const address = await resolveDnsServerAddress('ns.example.test', false, 0, {
        resolveRecordFromRoot: async (name, qType) => {
            queriedTypes.push(qType);
            return qType === 'AAAA' ? ['2001:db8::54'] : [];
        }
    });

    assert.equal(address, '2001:db8::54');
    assert.deepEqual(queriedTypes, ['A', 'AAAA']);
});

test('mismatched transaction ID response is ignored, later matching response is accepted', async () => {
    const restoreUdp = mockUdp((query, socket) => {
        // 先に無関係な (id 不一致) 応答が届き、後から正しい応答が届くケースを模す
        queueMicrotask(() => {
            const stray = dnsPacket.encode({
                type: 'response',
                id: (query.id + 1) % 65535,
                questions: query.questions,
                answers: [{ name: query.questions[0].name, type: 'NS', data: 'stray.test' }]
            });
            socket.emit('message', stray, { address: '192.0.2.1', port: 53 });
            socket.emit('message', createDnsResponse(query), { address: '192.0.2.1', port: 53 });
        });
    });

    try {
        const result = await queryDirectlyUDP('id-mismatch.test', '192.0.2.1', new Map(), 'NS', { useEdns: false });
        assert.equal(result.answers[0].data, 'a.gtld-servers.net');
    } finally {
        restoreUdp();
    }
});

test('response with mismatched question is ignored', async () => {
    const restoreUdp = mockUdp((query, socket) => {
        queueMicrotask(() => {
            const wrongQuestion = dnsPacket.encode({
                type: 'response',
                id: query.id,
                questions: [{ type: 'NS', name: 'other-domain.test' }],
                answers: [{ name: 'other-domain.test', type: 'NS', data: 'wrong.test' }]
            });
            socket.emit('message', wrongQuestion, { address: '192.0.2.1', port: 53 });
            socket.emit('message', createDnsResponse(query), { address: '192.0.2.1', port: 53 });
        });
    });

    try {
        const result = await queryDirectlyUDP('question-mismatch.test', '192.0.2.1', new Map(), 'NS', { useEdns: false });
        assert.equal(result.answers[0].data, 'a.gtld-servers.net');
    } finally {
        restoreUdp();
    }
});

test('UDP response from an unexpected source address is ignored', async () => {
    const restoreUdp = mockUdp((query, socket) => {
        queueMicrotask(() => {
            // なりすまし送信元からの応答は無視され、正規サーバーからの応答のみ受理される
            socket.emit('message', createDnsResponse(query), { address: '203.0.113.99', port: 53 });
            socket.emit('message', createDnsResponse(query), { address: '192.0.2.1', port: 53 });
        });
    });

    try {
        const result = await queryDirectlyUDP('spoofed-source.test', '192.0.2.1', new Map(), 'NS', { useEdns: false });
        assert.equal(result.answers[0].data, 'a.gtld-servers.net');
    } finally {
        restoreUdp();
    }
});

test('TIMEOUT results are cached only briefly, not forever', async () => {
    const restoreUdp = mockUdp(() => {
        // 応答を返さずタイムアウトさせる
    });

    try {
        const cache = new Map();
        const result = await queryDirectlyUDP('timeout.test', '192.0.2.1', cache, 'NS', { useEdns: false, timeoutMs: 10 });
        assert.equal(result.error, 'TIMEOUT');

        const cacheKey = [...cache.keys()][0];
        const entry = cache.get(cacheKey);
        assert.ok(entry.expiresAt < Date.now() + 5000, 'timeout cache entry must not be cached for a long duration');
    } finally {
        restoreUdp();
    }
});

test('structured errors include serverIp, name, qType and retryable', async () => {
    const restoreUdp = mockUdp(() => {});

    try {
        const result = await queryDirectlyUDP('structured-error.test', '192.0.2.5', new Map(), 'A', { useEdns: false, timeoutMs: 10 });
        assert.equal(result.error, 'TIMEOUT');
        assert.equal(result.serverIp, '192.0.2.5');
        assert.equal(result.name, 'structured-error.test');
        assert.equal(result.qType, 'A');
        assert.equal(result.transport, 'udp');
        assert.equal(result.retryable, true);
    } finally {
        restoreUdp();
    }
});