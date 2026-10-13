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
    getReferralAddressRecords,
    normalizeDnsName,
    queryDirectlyTCP,
    queryDirectlyUDP,
    resolveRecordFromRoot,
    resolveServerIPs,
    resolveHostnameIPv4Self,
    resolveHostnameIPv6Self,
    resolveRecordFromServer,
    resolveDnsServerAddressByType,
    resolveDnsServerAddress,
    getKnownAddress,
    getCachedNameserverIPs,
    RESOLUTION_LIMITS,
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
        socket.bind = (options, callback) => queueMicrotask(callback);
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

function createAbortAwareQuery() {
    let queryCount = 0;
    return {
        queryDirectlyUDP: async (domain, serverIp, cache, qType, options = {}) => {
            queryCount++;
            if (options.signal) {
                return new Promise(resolve => {
                    const abort = () => resolve({ error: 'ABORTED' });
                    if (options.signal.aborted) return abort();
                    options.signal.addEventListener('abort', abort, { once: true });
                });
            }
            return {
                flags: 1024,
                answers: [{
                    name: domain,
                    type: qType,
                    data: qType === 'A' ? '192.0.2.57' : '2001:db8::57'
                }]
            };
        },
        getQueryCount: () => queryCount
    };
}

async function assertCancellationIsolated(hostname, resolver, expectedResult, expectedQueryCount) {
    const controller = new AbortController();
    const query = createAbortAwareQuery();
    const cancelled = resolver(hostname, {
        signal: controller.signal,
        queryDirectlyUDP: query.queryDirectlyUDP
    });
    const independent = resolver(hostname, { queryDirectlyUDP: query.queryDirectlyUDP });

    controller.abort();

    assert.equal(await cancelled, null);
    assert.deepEqual(await independent, expectedResult);
    assert.equal(query.getQueryCount(), expectedQueryCount);
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

test('glue 判定では NS 名リストの大文字と末尾ドットを正規化する', () => {
    const additionals = [
        { type: 'A', name: 'NS1.Child.Example.COM.', data: '192.0.2.53' },
        { type: 'AAAA', name: 'ns1.child.example.com', data: '2001:db8::53' }
    ];

    assert.equal(
        isInBailiwickGlue(additionals[0], ['NS1.Child.Example.COM.'], 'CHILD.EXAMPLE.COM.'),
        true
    );
    assert.deepEqual(
        getReferralAddressRecords(
            additionals,
            ['NS1.Child.Example.COM.'],
            'CHILD.EXAMPLE.COM.'
        ),
        additionals
    );
});

test('root referral では委任先ゾーン外でも NS に対応する glue を採用する', () => {
    const additionals = [
        { type: 'A', name: 'a.gtld-servers.net', data: '192.0.2.53' },
        { type: 'A', name: 'unlisted.example.net', data: '192.0.2.54' },
        { type: 'TXT', name: 'a.gtld-servers.net', data: 'not glue' }
    ];

    assert.deepEqual(
        getReferralAddressRecords(
            additionals,
            ['a.gtld-servers.net'],
            'com',
            'strict',
            '.'
        ),
        [additionals[0]]
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

test('UDP and TCP share successful response cache entries', async () => {
    const originalCreateConnection = net.createConnection;
    let udpQueryCount = 0;
    const restoreUdp = mockUdp((query, socket) => {
        udpQueryCount++;
        queueMicrotask(() => socket.emit('message', dnsPacket.encode({
            type: 'response',
            id: query.id,
            questions: query.questions,
            answers: [{
                name: query.questions[0].name,
                type: 'A',
                ttl: 60,
                data: '192.0.2.20'
            }]
        })));
    });

    try {
        const udpFirstCache = new Map();
        await queryDirectlyUDP('udp-first.test', '192.0.2.1', udpFirstCache, 'A');
        net.createConnection = () => {
            throw new Error('TCP query should use the UDP cache entry');
        };
        const udpCachedByTcp = await queryDirectlyTCP('udp-first.test', '192.0.2.1', udpFirstCache, 'A');
        assert.equal(udpCachedByTcp.isCached, true);

        net.createConnection = (options, onConnect) => {
            const socket = new EventEmitter();
            socket.destroy = () => {};
            socket.write = buffer => {
                const query = dnsPacket.streamDecode(buffer);
                queueMicrotask(() => socket.emit('data', dnsPacket.streamEncode({
                    type: 'response',
                    id: query.id,
                    questions: query.questions,
                    answers: [{
                        name: query.questions[0].name,
                        type: 'A',
                        ttl: 60,
                        data: '192.0.2.21'
                    }]
                })));
            };
            queueMicrotask(onConnect);
            return socket;
        };

        const tcpFirstCache = new Map();
        await queryDirectlyTCP('tcp-first.test', '192.0.2.1', tcpFirstCache, 'A');
        const udpCountAfterTcpQuery = udpQueryCount;
        const tcpCachedByUdp = await queryDirectlyUDP('tcp-first.test', '192.0.2.1', tcpFirstCache, 'A');
        assert.equal(tcpCachedByUdp.isCached, true);
        assert.equal(udpQueryCount, udpCountAfterTcpQuery);
    } finally {
        restoreUdp();
        net.createConnection = originalCreateConnection;
    }
});

test('resolveRecordFromRoot forwards query options and signal to each DNS query', async () => {
    const controller = new AbortController();
    const receivedOptions = [];

    const result = await resolveRecordFromRoot('options.example.test', 'A', new Map(), {
        queryOptions: { timeoutMs: 250, useEdns: false },
        signal: controller.signal,
        queryDirectlyUDP: async (domain, serverIp, cache, qType, options) => {
            receivedOptions.push(options);
            return {
                flags: dnsPacket.AUTHORITATIVE_ANSWER,
                answers: [{ name: domain, type: qType, data: '192.0.2.25' }]
            };
        }
    });

    assert.deepEqual(result, ['192.0.2.25']);
    assert.equal(receivedOptions.length, 1);
    assert.equal(receivedOptions[0].timeoutMs, 250);
    assert.equal(receivedOptions[0].useEdns, false);
    assert.equal(receivedOptions[0].signal, controller.signal);
});

test('queryDirectlyUDP closes its socket when aborted', async () => {
    const originalCreateSocket = dgram.createSocket;
    const controller = new AbortController();
    let closed = false;

    dgram.createSocket = () => {
        const socket = new EventEmitter();
        socket.close = () => { closed = true; };
        socket.bind = (options, callback) => queueMicrotask(callback);
        socket.send = (buffer, offset, length, port, host, callback) => callback?.(null);
        return socket;
    };

    try {
        const pending = queryDirectlyUDP('abort.test', '192.0.2.1', new Map(), 'A', {
            timeoutMs: 1000,
            signal: controller.signal
        });
        controller.abort();
        const result = await pending;

        assert.equal(result.error, 'ABORTED');
        assert.equal(closed, true);
    } finally {
        dgram.createSocket = originalCreateSocket;
    }
});

test('queryDirectlyTCP destroys its socket when aborted', async () => {
    const originalCreateConnection = net.createConnection;
    const controller = new AbortController();
    let destroyed = false;

    net.createConnection = () => {
        const socket = new EventEmitter();
        socket.destroy = () => { destroyed = true; };
        socket.write = () => {};
        return socket;
    };

    try {
        const pending = queryDirectlyTCP('abort.test', '192.0.2.1', new Map(), 'A', {
            timeoutMs: 1000,
            signal: controller.signal
        });
        controller.abort();
        const result = await pending;

        assert.equal(result.error, 'ABORTED');
        assert.equal(destroyed, true);
    } finally {
        net.createConnection = originalCreateConnection;
    }
});

test('resolveRecordFromRoot does not retry another server after cancellation', async () => {
    const controller = new AbortController();
    let queryCount = 0;

    const result = await resolveRecordFromRoot('abort.example.test', 'A', new Map(), {
        signal: controller.signal,
        queryDirectlyUDP: async () => {
            queryCount++;
            controller.abort();
            return { error: 'ABORTED' };
        }
    });

    assert.deepEqual(result, []);
    assert.equal(queryCount, 1);
});

test('timeout cache entries are separated by timeoutMs', async () => {
    const restoreUdp = mockUdp(() => {});

    try {
        const cache = new Map();
        await queryDirectlyUDP('timeout-options.test', '192.0.2.1', cache, 'A', { timeoutMs: 1 });
        await queryDirectlyUDP('timeout-options.test', '192.0.2.1', cache, 'A', { timeoutMs: 2 });

        assert.equal(cache.size, 2);
    } finally {
        restoreUdp();
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

test('strict ignores out-of-bailiwick glue from a non-root referral', async () => {
    const calls = [];
    const resolvedHosts = [];
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
            if (serverIp === '192.5.6.30') {
                return {
                    authorities: [
                        { name: 'example.com', type: 'NS', data: 'ns1.external.net' }
                    ],
                    additionals: [
                        { name: 'ns1.external.net', type: 'A', data: '192.5.6.31' }
                    ]
                };
            }
            assert.equal(serverIp, '192.5.6.31');
            return {
                answers: [{ name: domain, type: 'NS', data: 'ns1.example.com' }]
            };
        },
        resolveHostnameIPv4Self: async hostname => {
            resolvedHosts.push(hostname);
            assert.equal(hostname, 'ns1.external.net');
            return '192.5.6.31';
        }
    });

    assert.deepEqual(result, ['ns1.example.com']);
    assert.deepEqual(calls, [ROOT_SERVER_BOOTSTRAP_IP, '192.5.6.30', '192.5.6.31']);
    assert.deepEqual(resolvedHosts, ['ns1.external.net']);
});

test('allow-sibling policy uses out-of-bailiwick referral address', async () => {
    const calls = [];
    const resolvedHosts = [];
    const result = await resolveRecordFromRoot('example.com', 'NS', new Map(), {
        gluePolicy: 'allow-sibling',
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
    assert.deepEqual(resolvedHosts, []);
});

test('allow-sibling rejects referral addresses outside the queried server zone', async () => {
    const calls = [];
    const result = await resolveRecordFromRoot('host.nested.example.test', 'A', new Map(), {
        gluePolicy: 'allow-sibling',
        queryDirectlyUDP: async (domain, serverIp) => {
            calls.push(serverIp);
            if (serverIp === ROOT_SERVER_BOOTSTRAP_IP) {
                return {
                    authorities: [
                        { name: 'example.test', type: 'NS', data: 'ns.example.test' }
                    ],
                    additionals: [
                        { name: 'ns.example.test', type: 'A', data: '192.0.2.10' }
                    ]
                };
            }
            if (serverIp === '192.0.2.10') {
                return {
                    authorities: [
                        { name: 'nested.example.test', type: 'NS', data: 'ns.outside.test' },
                        { name: 'nested.example.test', type: 'NS', data: 'ns.sibling.example.test' }
                    ],
                    additionals: [
                        { name: 'ns.outside.test', type: 'A', data: '192.0.2.11' },
                        { name: 'ns.sibling.example.test', type: 'A', data: '192.0.2.12' }
                    ]
                };
            }
            assert.equal(serverIp, '192.0.2.12');
            return { answers: [{ name: domain, type: 'A', data: '192.0.2.13' }] };
        }
    });

    assert.deepEqual(result, ['192.0.2.13']);
    assert.deepEqual(calls, [ROOT_SERVER_BOOTSTRAP_IP, '192.0.2.10', '192.0.2.12']);
});

test('all referral addresses are tried and missing IPv4 glue falls back to IPv6 resolution', async () => {
    const calls = [];
    const resolvedHosts = [];
    const result = await resolveRecordFromRoot('target.example.test', 'A', new Map(), {
        queryDirectlyUDP: async (domain, serverIp) => {
            calls.push(serverIp);
            if (serverIp === ROOT_SERVER_BOOTSTRAP_IP) {
                return {
                    authorities: [
                        { name: 'example.test', type: 'NS', data: 'ns1.example.test' },
                        { name: 'example.test', type: 'NS', data: 'ns2.example.test' }
                    ],
                    additionals: [
                        { name: 'ns1.example.test', type: 'A', data: '192.0.2.41' },
                        { name: 'ns1.example.test', type: 'AAAA', data: '2001:db8::41' }
                    ]
                };
            }
            if (serverIp === '192.0.2.41' || serverIp === '2001:db8::41') {
                return { error: 'SOCKET_ERROR' };
            }
            assert.equal(serverIp, '2001:db8::42');
            return { answers: [{ name: domain, type: 'A', data: '192.0.2.43' }] };
        },
        resolveHostnameIPv4Self: async hostname => {
            resolvedHosts.push(`A:${hostname}`);
            return null;
        },
        resolveHostnameIPv6Self: async hostname => {
            resolvedHosts.push(`AAAA:${hostname}`);
            return hostname === 'ns2.example.test' ? '2001:db8::42' : null;
        }
    });

    assert.deepEqual(result, ['192.0.2.43']);
    assert.deepEqual(calls, [ROOT_SERVER_BOOTSTRAP_IP, '192.0.2.41', '2001:db8::41', '2001:db8::42']);
    assert.deepEqual(resolvedHosts, ['A:ns2.example.test', 'AAAA:ns2.example.test']);
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

test('IPv4 cancellation does not affect a concurrent resolution without a signal', async () => {
    await assertCancellationIsolated(
        'cancel-isolated-ipv4.example.test',
        resolveHostnameIPv4Self,
        '192.0.2.57',
        2
    );
});

test('IPv6 cancellation does not affect a concurrent resolution without a signal', async () => {
    await assertCancellationIsolated(
        'cancel-isolated-ipv6.example.test',
        resolveHostnameIPv6Self,
        '2001:db8::57',
        2
    );
});

test('server IP cancellation does not affect a concurrent resolution without a signal', async () => {
    await assertCancellationIsolated(
        'cancel-isolated-server.example.test',
        resolveServerIPs,
        ['192.0.2.57', '2001:db8::57'],
        4
    );
});

test('nameserver resolution cache is separated by glue policy', async () => {
    let queryCount = 0;
    const queryDirectlyUDP = async (domain, serverIp, cache, qType) => {
        queryCount++;
        await new Promise(resolve => setTimeout(resolve, 5));
        return {
            flags: 1024,
            answers: [{ name: domain, type: qType, data: qType === 'A' ? '192.0.2.56' : '2001:db8::56' }]
        };
    };
    const concurrentHostname = 'policy-isolated-concurrent-ns.example.test';

    await Promise.all([
        resolveServerIPs(concurrentHostname, { gluePolicy: 'allow-sibling', queryDirectlyUDP }),
        resolveServerIPs(concurrentHostname, { gluePolicy: 'strict', queryDirectlyUDP })
    ]);
    assert.equal(queryCount, 4);

    const cachedHostname = 'policy-isolated-cached-ns.example.test';
    await resolveServerIPs(cachedHostname, { gluePolicy: 'allow-sibling', queryDirectlyUDP });
    await resolveServerIPs(cachedHostname, { gluePolicy: 'strict', queryDirectlyUDP });
    assert.equal(queryCount, 8);
});

for (const [label, resolveSelf, qType, answer] of [
    ['IPv4', resolveHostnameIPv4Self, 'A', '192.0.2.10'],
    ['IPv6', resolveHostnameIPv6Self, 'AAAA', '2001:db8::10']
]) {
    test(`resolveHostname${label}Self does not reuse allow-sibling results for strict policy`, async () => {
        const hostname = `ns-${label.toLowerCase()}.external.test`;
        const calls = [];
        const makeDeps = gluePolicy => ({
            gluePolicy,
            queryDirectlyUDP: async (domain, serverIp, cache, type) => {
                calls.push({ gluePolicy, serverIp });
                assert.equal(serverIp, ROOT_SERVER_BOOTSTRAP_IP);
                return { flags: 1024, answers: [{ name: domain, type, data: answer }] };
            }
        });

        assert.equal(await resolveSelf(hostname, makeDeps('allow-sibling')), answer);
        const callsAfterSibling = calls.length;

        assert.equal(await resolveSelf(hostname, makeDeps('strict')), answer);
        assert.ok(calls.length > callsAfterSibling, 'strict must query instead of reusing the allow-sibling cache');
        assert.ok(calls.slice(callsAfterSibling).every(call => call.serverIp === ROOT_SERVER_BOOTSTRAP_IP));
    });
}

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
test('response without question section is ignored unless it is FORMERR', async () => {
    const restoreUdp = mockUdp((query, socket) => {
        queueMicrotask(() => {
            // id が一致しても question を省略した NOERROR 応答 (偽装の可能性) は受理しない
            const forged = dnsPacket.encode({
                type: 'response',
                id: query.id,
                answers: [{ name: query.questions[0].name, type: 'NS', data: 'forged.test' }]
            });
            socket.emit('message', forged, { address: '192.0.2.1', port: 53 });
            socket.emit('message', createDnsResponse(query), { address: '192.0.2.1', port: 53 });
        });
    });

    try {
        const result = await queryDirectlyUDP('no-question.test', '192.0.2.1', new Map(), 'NS', { useEdns: false });
        assert.equal(result.answers[0].data, 'a.gtld-servers.net');
    } finally {
        restoreUdp();
    }
});

test('transaction IDs are generated with a CSPRNG instead of Math.random', async () => {
    const ids = [];
    const originalRandom = Math.random;
    Math.random = () => 0;
    const restoreUdp = mockUdp((query, socket) => {
        ids.push(query.id);
        queueMicrotask(() => socket.emit('message', createDnsResponse(query)));
    });

    try {
        for (let i = 0; i < 4; i++) {
            await queryDirectlyUDP(`txid-${i}.test`, '192.0.2.1', new Map(), 'NS', { useEdns: false });
        }
        assert.equal(ids.length, 4);
        assert.ok(ids.every(id => Number.isInteger(id) && id >= 0 && id <= 65535));
        assert.ok(new Set(ids).size > 1, `transaction IDs must not be predictable: ${ids.join(', ')}`);
    } finally {
        Math.random = originalRandom;
        restoreUdp();
    }
});

test('NXNS: glueless NS names resolved per referral are capped', async () => {
    const resolvedHosts = [];
    const nsRecords = Array.from({ length: 50 }, (_, i) =>
        ({ name: 'nxns-attacker.test', type: 'NS', data: `x${i}.victim.test` }));

    const result = await resolveRecordFromRoot('www.nxns-attacker.test', 'A', new Map(), {
        queryDirectlyUDP: async () => ({ authorities: nsRecords, additionals: [] }),
        resolveHostnameIPv4Self: async hostname => {
            resolvedHosts.push(hostname);
            return null;
        },
        resolveHostnameIPv6Self: async () => null
    });

    assert.deepEqual(result, []);
    assert.equal(resolvedHosts.length, RESOLUTION_LIMITS.maxGluelessNsPerReferral);
});

test('NXNS: nested glueless resolutions share a bounded query budget', async () => {
    let queryCount = 0;
    let nsCounter = 0;
    // 毎回 glue なしの新しい NS 名を大量に返して入れ子解決を誘発する悪性サーバー
    const queryUDP = async (domain) => {
        queryCount++;
        const zone = domain.split('.').slice(-2).join('.');
        return {
            authorities: Array.from({ length: 10 }, () =>
                ({ name: zone, type: 'NS', data: `ns${nsCounter++}.amp${nsCounter}.test` })),
            additionals: []
        };
    };

    const result = await resolveRecordFromRoot('www.budget-attacker.test', 'A', new Map(), {
        queryDirectlyUDP: queryUDP,
        resolutionLimits: { maxQueriesPerResolution: 30 }
    });

    assert.deepEqual(result, []);
    assert.ok(queryCount <= 30, `query count must be bounded by the budget: ${queryCount}`);
});

test('getKnownAddress ignores prototype properties and invalid values', () => {
    const knownAddresses = { 'ns.ok.test': ['192.0.2.1', 'not-an-ip', { evil: true }] };
    assert.equal(getKnownAddress(knownAddresses, 'constructor'), null);
    assert.equal(getKnownAddress(knownAddresses, '__proto__'), null);
    assert.equal(getKnownAddress(knownAddresses, 'toString'), null);
    assert.deepEqual(getKnownAddress(knownAddresses, 'ns.ok.test'), ['192.0.2.1']);
});

test('referral to an NS named like a prototype property does not crash resolution', async () => {
    const calls = [];
    const result = await resolveRecordFromRoot('www.proto.test', 'A', new Map(), {
        knownAddresses: { 'ns.other.test': '192.0.2.1' },
        queryDirectlyUDP: async (domain, serverIp) => {
            calls.push(serverIp);
            if (serverIp === ROOT_SERVER_BOOTSTRAP_IP) {
                return {
                    authorities: [{ name: 'proto.test', type: 'NS', data: 'constructor' }],
                    additionals: []
                };
            }
            throw new Error(`unexpected server ${serverIp}`);
        },
        resolveHostnameIPv4Self: async () => null,
        resolveHostnameIPv6Self: async () => null
    });

    assert.deepEqual(result, []);
    assert.deepEqual(calls, [ROOT_SERVER_BOOTSTRAP_IP]);
});

test('exceptions thrown by a query function are treated as a failed server', async () => {
    const calls = [];
    const result = await resolveRecordFromRoot('www.throw.test', 'A', new Map(), {
        queryDirectlyUDP: async (domain, serverIp) => {
            calls.push(serverIp);
            if (calls.length === 1) throw new TypeError('boom');
            return { flags: 1024, answers: [{ name: domain, type: 'A', data: '192.0.2.70' }] };
        }
    });

    assert.deepEqual(result, ['192.0.2.70']);
    assert.equal(calls.length, 2);
});

test('upward and sideways referrals are rejected as lame', async () => {
    const calls = [];
    const result = await resolveRecordFromRoot('www.example.test', 'A', new Map(), {
        queryDirectlyUDP: async (domain, serverIp) => {
            calls.push(serverIp);
            if (serverIp === ROOT_SERVER_BOOTSTRAP_IP) {
                return {
                    authorities: [{ name: 'example.test', type: 'NS', data: 'ns.example.test' }],
                    additionals: [{ name: 'ns.example.test', type: 'A', data: '192.0.2.10' }]
                };
            }
            if (serverIp === '192.0.2.10') {
                // 委任先サーバーが無関係なゾーンへの referral を返す (偽装/lame)
                return {
                    authorities: [{ name: 'attacker.test', type: 'NS', data: 'ns.attacker.test' }],
                    additionals: [{ name: 'ns.attacker.test', type: 'A', data: '203.0.113.66' }]
                };
            }
            throw new Error(`must not query ${serverIp}`);
        }
    });

    assert.deepEqual(result, []);
    assert.ok(!calls.includes('203.0.113.66'));
});

test('nameserver IP cache is isolated from callers that inject knownAddresses', async () => {
    const hostname = 'www.scope-victim.test';
    const queries = [];
    const queryUDP = async (domain, serverIp, cache, qType) => {
        queries.push(serverIp);
        if (serverIp === ROOT_SERVER_BOOTSTRAP_IP) {
            return {
                authorities: [{ name: 'scope-victim.test', type: 'NS', data: 'ns.provider.test' }],
                additionals: []
            };
        }
        const data = serverIp === '203.0.113.66' ? '203.0.113.99' : '192.0.2.99';
        return { flags: 1024, answers: [{ name: domain, type: qType, data }] };
    };

    const resolveNs = async () => '192.0.2.53';

    const attacker = await resolveHostnameIPv4Self(hostname, {
        knownAddresses: { 'ns.provider.test': '203.0.113.66' },
        queryDirectlyUDP: queryUDP,
        resolveHostnameIPv4Self: resolveNs
    });
    assert.equal(attacker, '203.0.113.99');

    const victim = await resolveHostnameIPv4Self(hostname, {
        queryDirectlyUDP: queryUDP,
        resolveHostnameIPv4Self: resolveNs
    });
    assert.equal(victim, '192.0.2.99');
});

test('nameserver IP cache honours record TTL', async () => {
    const hostname = 'ttl-zero-ns.example.test';
    let queryCount = 0;
    const queryUDP = async (domain, serverIp, cache, qType) => {
        queryCount++;
        return { flags: 1024, answers: [{ name: domain, type: qType, ttl: 0, data: '192.0.2.81' }] };
    };

    assert.equal(await resolveHostnameIPv4Self(hostname, { queryDirectlyUDP: queryUDP }), '192.0.2.81');
    assert.equal(getCachedNameserverIPs(hostname, 'strict', { queryDirectlyUDP: queryUDP }), null);
    assert.equal(await resolveHostnameIPv4Self(hostname, { queryDirectlyUDP: queryUDP }), '192.0.2.81');
    assert.equal(queryCount, 2);
});

test('failed nameserver resolution is negatively cached for a short time', async () => {
    const hostname = 'nx-ns.example.test';
    let queryCount = 0;
    const queryUDP = async () => {
        queryCount++;
        return { flags: 1024, rcode: 'NXDOMAIN', answers: [] };
    };

    assert.equal(await resolveHostnameIPv4Self(hostname, { queryDirectlyUDP: queryUDP }), null);
    assert.equal(await resolveHostnameIPv4Self(hostname, { queryDirectlyUDP: queryUDP }), null);
    assert.equal(queryCount, 1);
});

test('nested NS resolution reuses the caller response cache', async () => {
    const cache = new Map();
    const seenCaches = new Set();
    await resolveRecordFromRoot('www.shared-cache.test', 'A', cache, {
        queryDirectlyUDP: async (domain, serverIp, usedCache, qType) => {
            seenCaches.add(usedCache);
            if (domain === 'www.shared-cache.test' && serverIp === ROOT_SERVER_BOOTSTRAP_IP) {
                return {
                    authorities: [{ name: 'shared-cache.test', type: 'NS', data: 'ns.glueless-provider.test' }],
                    additionals: []
                };
            }
            return { flags: 1024, answers: [{ name: domain, type: qType, data: qType === 'A' ? '192.0.2.31' : '2001:db8::31' }] };
        }
    });

    assert.deepEqual([...seenCaches], [cache]);
});

test('UDP: malformed datagram with matching ID does not abort the query', async () => {
    const restoreUdp = mockUdp((query, socket) => {
        queueMicrotask(() => {
            const garbage = Buffer.alloc(14, 0xff);
            garbage.writeUInt16BE(query.id, 0);
            socket.emit('message', garbage, { address: '192.0.2.1', port: 53 });
            socket.emit('message', Buffer.from([1, 2, 3]), { address: '192.0.2.1', port: 53 });
            socket.emit('message', createDnsResponse(query), { address: '192.0.2.1', port: 53 });
        });
    });

    try {
        const result = await queryDirectlyUDP('malformed-spoof.test', '192.0.2.1', new Map(), 'NS', { useEdns: false });
        assert.equal(result.error, undefined);
        assert.equal(result.answers[0].data, 'a.gtld-servers.net');
    } finally {
        restoreUdp();
    }
});

test('UDP: only malformed responses result in DECODE_ERROR after the timeout', async () => {
    const restoreUdp = mockUdp((query, socket) => {
        queueMicrotask(() => {
            const garbage = Buffer.alloc(14, 0xff);
            garbage.writeUInt16BE(query.id, 0);
            socket.emit('message', garbage, { address: '192.0.2.1', port: 53 });
        });
    });

    try {
        const result = await queryDirectlyUDP('malformed-only.test', '192.0.2.1', new Map(), 'NS', { useEdns: false, timeoutMs: 20 });
        assert.equal(result.error, 'DECODE_ERROR');
    } finally {
        restoreUdp();
    }
});

test('UDP: response from an unexpected source port is ignored', async () => {
    const restoreUdp = mockUdp((query, socket) => {
        queueMicrotask(() => {
            socket.emit('message', createDnsResponse(query), { address: '192.0.2.1', port: 5353 });
            socket.emit('message', createDnsResponse(query), { address: '192.0.2.1', port: 53 });
        });
    });

    try {
        const result = await queryDirectlyUDP('spoofed-port.test', '192.0.2.1', new Map(), 'NS', { useEdns: false });
        assert.equal(result.answers[0].data, 'a.gtld-servers.net');
    } finally {
        restoreUdp();
    }
});

test('UDP: source port is randomized with a CSPRNG', async () => {
    const originalCreateSocket = dgram.createSocket;
    const ports = [];
    dgram.createSocket = () => {
        const socket = new EventEmitter();
        socket.close = () => {};
        socket.bind = (options, callback) => {
            ports.push(options.port);
            queueMicrotask(callback);
        };
        socket.send = (buffer, offset, length, port, host, callback) => {
            callback?.(null);
            const query = dnsPacket.decode(buffer);
            queueMicrotask(() => socket.emit('message', createDnsResponse(query)));
        };
        return socket;
    };

    try {
        for (let i = 0; i < 4; i++) {
            await queryDirectlyUDP(`port-${i}.test`, '192.0.2.1', new Map(), 'NS', { useEdns: false });
        }
        assert.equal(ports.length, 4);
        assert.ok(ports.every(port => Number.isInteger(port) && port >= 1024 && port <= 65535));
        assert.ok(new Set(ports).size > 1, `source ports must not be predictable: ${ports.join(', ')}`);
    } finally {
        dgram.createSocket = originalCreateSocket;
    }
});

test('UDP: 0x20 randomizes the query name case and restores it in the result', async () => {
    const sentNames = [];
    const restoreUdp = mockUdp((query, socket) => {
        sentNames.push(query.questions[0].name);
        queueMicrotask(() => socket.emit('message', createDnsResponse(query)));
    });

    try {
        let result;
        for (let i = 0; i < 4; i++) {
            result = await queryDirectlyUDP(`case-randomization-${i}.example.test`, '192.0.2.1', new Map(), 'NS', { useEdns: false });
        }
        assert.ok(sentNames.some(name => name !== name.toLowerCase()), sentNames.join(', '));
        assert.equal(result.questions[0].name, 'case-randomization-3.example.test');
        assert.equal(result.answers[0].name, 'case-randomization-3.example.test');
    } finally {
        restoreUdp();
    }
});

test('UDP: 0x20 case-mismatched response is rejected, then retried without 0x20', async () => {
    const queries = [];
    const restoreUdp = mockUdp((query, socket) => {
        queries.push(query);
        const lowered = { ...query, questions: [{ ...query.questions[0], name: query.questions[0].name.toLowerCase() }] };
        const forged = dnsPacket.encode({
            type: 'response',
            id: query.id,
            questions: lowered.questions,
            answers: [{ name: lowered.questions[0].name, type: 'NS', data: 'case-insensitive-server.test' }]
        });
        queueMicrotask(() => socket.emit('message', forged, { address: '192.0.2.1', port: 53 }));
    });

    try {
        const name = 'abcdefghijklmnopqrstuvwxyz.example.test';
        const result = await queryDirectlyUDP(name, '192.0.2.1', new Map(), 'NS', { useEdns: false, timeoutMs: 20 });
        assert.equal(queries.length, 2);
        assert.notEqual(queries[0].questions[0].name, name);
        assert.equal(queries[1].questions[0].name, name);
        assert.equal(result.caseRandomizationFallback, true);
        assert.equal(result.answers[0].data, 'case-insensitive-server.test');
    } finally {
        restoreUdp();
    }
});

test('queryDirectlyUDP rejects non-IP server addresses without throwing', async () => {
    const result = await queryDirectlyUDP('example.test', { toString: () => 'x' }, new Map(), 'A');
    assert.equal(result.error, 'SEND_ERROR');
    assert.equal(result.retryable, false);
});

test('TCP: messages with a mismatched ID are skipped before decoding', async () => {
    const originalCreateConnection = net.createConnection;
    net.createConnection = (options, onConnect) => {
        const socket = new EventEmitter();
        socket.destroy = () => {};
        socket.write = (buffer) => {
            const query = dnsPacket.streamDecode(buffer);
            const junk = Buffer.alloc(16, 0xff);
            junk.writeUInt16BE(14, 0);
            junk.writeUInt16BE((query.id + 1) % 65536, 2);
            const response = dnsPacket.streamEncode({
                type: 'response',
                id: query.id,
                questions: query.questions,
                answers: [{ name: 'tcp-junk.test', type: 'A', data: '192.0.2.12' }]
            });
            queueMicrotask(() => socket.emit('data', Buffer.concat([junk, response])));
        };
        queueMicrotask(onConnect);
        return socket;
    };

    try {
        const result = await queryDirectlyTCP('tcp-junk.test', '192.0.2.3', new Map(), 'A', { timeoutMs: 100 });
        assert.equal(result.error, undefined);
        assert.equal(result.answers[0].data, '192.0.2.12');
    } finally {
        net.createConnection = originalCreateConnection;
    }
});

test('UDP without 0x20 accepts responses whose question differs only in case', async () => {
    const restoreUdp = mockUdp((query, socket) => {
        const lowered = [{ ...query.questions[0], name: query.questions[0].name.toLowerCase() }];
        queueMicrotask(() => socket.emit('message', dnsPacket.encode({
            type: 'response',
            id: query.id,
            questions: lowered,
            answers: [{ name: lowered[0].name, type: 'NS', data: 'lowercasing-server.test' }]
        }), { address: '192.0.2.1', port: 53 }));
    });

    try {
        const result = await queryDirectlyUDP('Mixed-Case.Example.TEST', '192.0.2.1', new Map(), 'NS', {
            useEdns: false,
            use0x20: false,
            timeoutMs: 50
        });
        assert.equal(result.error, undefined);
        assert.equal(result.answers[0].data, 'lowercasing-server.test');

        const fallback = await queryDirectlyUDP('Other-Mixed.Example.TEST', '192.0.2.1', new Map(), 'NS', {
            useEdns: false,
            timeoutMs: 20
        });
        assert.equal(fallback.error, undefined);
        assert.equal(fallback.caseRandomizationFallback, true);
    } finally {
        restoreUdp();
    }
});

test('budget exhaustion does not negatively cache the nameserver name', async () => {
    const hostname = 'ns.budget-negative.test';
    let queryCount = 0;
    const queryUDP = async (domain, serverIp, cache, qType) => {
        queryCount++;
        if (serverIp === ROOT_SERVER_BOOTSTRAP_IP) {
            return {
                authorities: [{ name: 'budget-negative.test', type: 'NS', data: 'ns1.budget-negative.test' }],
                additionals: [{ name: 'ns1.budget-negative.test', type: 'A', data: '192.0.2.91' }]
            };
        }
        return { flags: 1024, answers: [{ name: domain, type: qType, data: '192.0.2.92' }] };
    };

    assert.equal(await resolveHostnameIPv4Self(hostname, {
        queryDirectlyUDP: queryUDP,
        resolutionLimits: { maxQueriesPerResolution: 1 }
    }), null);
    assert.equal(await resolveHostnameIPv4Self(hostname, { queryDirectlyUDP: queryUDP }), '192.0.2.92');
    assert.equal(queryCount, 3);
});
