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
            onQuery(dnsPacket.decode(buffer), socket);
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

test('out-of-bailiwick glue is ignored and the next nameserver is resolved', async () => {
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
                        { name: 'ns1.glue-fallback.test', type: 'A', data: '192.0.2.11' },
                        { name: 'ns2.external.test', type: 'A', data: '192.0.2.12' }
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