import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import { EventEmitter } from 'node:events';
import net from 'node:net';
import test from 'node:test';
import dnsPacket from 'dns-packet';
import {
    cacheNameserverIPs,
    isPublicDnsServerAddress,
    queryDirectlyTCP,
    queryDirectlyUDP,
    resolveHostnameIPv4Self,
    resolveHostnameIPv6Self,
    resolveRecordFromRoot,
    resolveServerIPs,
    ROOT_SERVER_BOOTSTRAP_IP
} from '../index.js';

test('public DNS address policy rejects special-purpose and scoped addresses', () => {
    for (const address of ['198.41.0.4', '8.8.8.8', '2001:500:2::c', '2a00:1450:4001::1']) {
        assert.equal(isPublicDnsServerAddress(address), true, address);
    }
    for (const address of [
        undefined, null, 123, '', 'example.com', '10.0.0.1', '100.64.0.1',
        '127.0.0.1', '169.254.169.254', '192.0.2.1', '224.0.0.1',
        '::', '::1', '::ffff:8.8.8.8', '64:ff9b::808:808', '64:ff9b:1::1',
        'fc00::1', 'fe80::1', 'ff02::1', '2001::1', '2001:2::1',
        '2001:10::1', '2001:20::1', '2001:db8::1', '2002::1', '3fff::1',
        '4000::1', '100:0:0:1::1', '2001:500:2::c%eth0'
    ]) {
        assert.equal(isPublicDnsServerAddress(address), false, String(address));
    }
});

test('UDP and TCP reject addresses before creating sockets or using cached responses', async t => {
    t.mock.method(dgram, 'createSocket', () => assert.fail('UDP socket must not be created'));
    t.mock.method(net, 'createConnection', () => assert.fail('TCP socket must not be created'));
    const options = { isAllowedServerIP: isPublicDnsServerAddress };
    for (const query of [queryDirectlyUDP, queryDirectlyTCP]) {
        const cache = new Map();
        const result = await query('example.test', '127.0.0.1', cache, 'A', options);
        assert.equal(result.error, 'BLOCKED_ADDRESS');
        assert.equal(result.name, 'example.test');
        assert.equal(result.serverIp, '127.0.0.1');
        assert.equal(result.qType, 'A');
        assert.equal(result.retryable, false);
        assert.equal(cache.size, 0);
    }
});

test('default transport still permits local DNS and explicit policy checks precede cache hits', async t => {
    let sends = 0;
    t.mock.method(dgram, 'createSocket', () => {
        const socket = new EventEmitter();
        socket.bind = (options, callback) => queueMicrotask(callback);
        socket.close = () => {};
        socket.send = (buffer, offset, length, port, host, callback) => {
            sends++;
            callback(null);
            const query = dnsPacket.decode(buffer);
            queueMicrotask(() => socket.emit('message', dnsPacket.encode({
                type: 'response', id: query.id, questions: query.questions,
                answers: [{ name: query.questions[0].name, type: 'A', ttl: 30, data: '127.0.0.2' }]
            }), { address: host, port }));
        };
        return socket;
    });
    const cache = new Map();
    const options = { use0x20: false, useEdns: false };
    const response = await queryDirectlyUDP('local.test', '127.0.0.1', cache, 'A', options);
    assert.equal(response.answers[0].data, '127.0.0.2');
    assert.equal(sends, 1);
    let allowed = true;
    const policy = () => allowed;
    await queryDirectlyUDP('local.test', '127.0.0.1', cache, 'A', { ...options, isAllowedServerIP: policy });
    allowed = false;
    for (const query of [queryDirectlyUDP, queryDirectlyTCP]) {
        assert.equal((await query('local.test', '127.0.0.1', cache, 'A', {
            ...options, isAllowedServerIP: policy
        })).error, 'BLOCKED_ADDRESS');
    }
    assert.equal(sends, 2);
});

test('TCP fallback rechecks the selected policy', async t => {
    let allow = true;
    t.mock.method(net, 'createConnection', () => assert.fail('blocked TCP fallback must not connect'));
    t.mock.method(dgram, 'createSocket', () => {
        const socket = new EventEmitter();
        socket.bind = (options, callback) => queueMicrotask(callback);
        socket.close = () => {};
        socket.send = (buffer, offset, length, port, host, callback) => {
            callback(null);
            const query = dnsPacket.decode(buffer);
            allow = false;
            queueMicrotask(() => socket.emit('message', dnsPacket.encode({
                type: 'response', id: query.id, questions: query.questions,
                flags: dnsPacket.TRUNCATED_RESPONSE
            }), { address: host, port }));
        };
        return socket;
    });
    const result = await queryDirectlyUDP('fallback.test', '127.0.0.1', new Map(), 'A', {
        use0x20: false, isAllowedServerIP: () => allow
    });
    assert.equal(result.error, 'BLOCKED_ADDRESS');
    assert.equal(result.transport, 'tcp');
    assert.equal(result.retryFrom, 'udp-truncated');
});

test('root resolution rejects blocked glue and propagates policy through glueless NS resolution', async () => {
    const queries = [];
    const policy = isPublicDnsServerAddress;
    const result = await resolveRecordFromRoot('child.test', 'A', new Map(), {
        isAllowedServerIP: policy,
        queryDirectlyUDP: async (name, ip, cache, type, options) => {
            assert.equal(options.isAllowedServerIP, policy);
            assert.equal(policy(ip), true, ip);
            queries.push({ name, ip });
            if (name === 'ns.external.test') {
                return { answers: [{ name, type, ttl: 30, data: '8.8.8.8' }] };
            }
            if (ip === ROOT_SERVER_BOOTSTRAP_IP) {
                return {
                    authorities: [
                        { name: 'child.test', type: 'NS', data: 'ns.child.test' },
                        { name: 'child.test', type: 'NS', data: 'ns.external.test' }
                    ],
                    additionals: [{ name: 'ns.child.test', type: 'A', data: '10.0.0.53' }]
                };
            }
            return { answers: [{ name, type, data: '8.8.4.4' }] };
        }
    });
    assert.deepEqual(result, ['8.8.4.4']);
    assert.ok(queries.some(query => query.name === 'ns.external.test'));
    assert.ok(queries.some(query => query.ip === '8.8.8.8'));
});

test('blocked glue does not consume the referral candidate limit', async () => {
    const queries = [];
    const result = await resolveRecordFromRoot('child.test', 'A', new Map(), {
        isAllowedServerIP: isPublicDnsServerAddress,
        resolutionLimits: { maxCandidatesPerReferral: 1 },
        queryDirectlyUDP: async (name, ip, cache, type) => {
            queries.push(ip);
            if (ip === ROOT_SERVER_BOOTSTRAP_IP) {
                return {
                    authorities: [
                        { name: 'child.test', type: 'NS', data: 'ns1.child.test' },
                        { name: 'child.test', type: 'NS', data: 'ns2.child.test' },
                        { name: 'child.test', type: 'NS', data: 'ns3.child.test' }
                    ],
                    additionals: [
                        { name: 'ns1.child.test', type: 'A', data: '10.0.0.1' },
                        { name: 'ns2.child.test', type: 'A', data: '127.0.0.1' },
                        { name: 'ns3.child.test', type: 'A', data: '8.8.8.8' }
                    ]
                };
            }
            return { answers: [{ name, type, data: '8.8.4.4' }] };
        }
    });

    assert.deepEqual(result, ['8.8.4.4']);
    assert.deepEqual(queries, [ROOT_SERVER_BOOTSTRAP_IP, '8.8.8.8']);
});

test('a candidate rejected during selection does not consume the query budget', async () => {
    const queries = [];
    let blockedCandidateChecks = 0;
    const policy = ip => {
        if (ip === '10.0.0.1') return ++blockedCandidateChecks === 1;
        return isPublicDnsServerAddress(ip);
    };
    const result = await resolveRecordFromRoot('child.test', 'A', new Map(), {
        isAllowedServerIP: policy,
        resolutionLimits: { maxQueriesPerResolution: 2 },
        queryDirectlyUDP: async (name, ip, cache, type) => {
            queries.push(ip);
            if (ip === ROOT_SERVER_BOOTSTRAP_IP) {
                return {
                    authorities: [{ name: 'child.test', type: 'NS', data: 'ns1.child.test' }],
                    additionals: [
                        { name: 'ns1.child.test', type: 'A', data: '10.0.0.1' },
                        { name: 'ns1.child.test', type: 'A', data: '8.8.8.8' }
                    ]
                };
            }
            return { answers: [{ name, type, data: '8.8.4.4' }] };
        }
    });

    assert.deepEqual(result, ['8.8.4.4']);
    assert.deepEqual(queries, [ROOT_SERVER_BOOTSTRAP_IP, '8.8.8.8']);
});

test('a candidate rejected during selection does not consume the resolution depth', async () => {
    const queries = [];
    const zones = [
        'test', 'i.test', 'h.i.test', 'g.h.i.test', 'f.g.h.i.test',
        'e.f.g.h.i.test', 'd.e.f.g.h.i.test', 'c.d.e.f.g.h.i.test',
        'b.c.d.e.f.g.h.i.test'
    ];
    let blockedCandidateChecks = 0;
    const policy = ip => {
        if (ip === '10.0.0.1') return ++blockedCandidateChecks === 1;
        return true;
    };
    const result = await resolveRecordFromRoot('a.b.c.d.e.f.g.h.i.test', 'A', new Map(), {
        isAllowedServerIP: policy,
        queryDirectlyUDP: async (name, ip, cache, type) => {
            queries.push(ip);
            if (queries.length === 10) {
                return { answers: [{ name, type, data: '8.8.4.4' }] };
            }
            const zone = zones[queries.length - 1];
            const nsName = `ns.${zone}`;
            const addresses = queries.length === 9
                ? ['10.0.0.1', '8.8.8.10']
                : [`8.8.8.${queries.length}`];
            return {
                authorities: [{ name: zone, type: 'NS', data: nsName }],
                additionals: addresses.map(data => ({ name: nsName, type: 'A', data }))
            };
        }
    });

    assert.deepEqual(result, ['8.8.4.4']);
    assert.equal(queries.length, 10);
    assert.equal(queries[9], '8.8.8.10');
});

test('address policy filters literals, known addresses and nameserver cache results', async () => {
    const dependencies = {
        isAllowedServerIP: isPublicDnsServerAddress,
        knownAddresses: { 'known.test': ['10.0.0.1', '8.8.8.8', '2001:500:2::c'] },
        queryDirectlyUDP: async () => assert.fail('must use permitted known or cached address')
    };
    assert.equal(await resolveServerIPs('10.0.0.1', dependencies), null);
    assert.equal(await resolveHostnameIPv4Self('127.0.0.1', dependencies), null);
    assert.equal(await resolveHostnameIPv6Self('3fff::1', dependencies), null);
    assert.deepEqual(await resolveServerIPs('known.test', dependencies), ['8.8.8.8', '2001:500:2::c']);
    cacheNameserverIPs('cached.test', ['10.0.0.1', '8.8.8.8'], 30000, 'strict', dependencies);
    assert.deepEqual(await resolveServerIPs('cached.test', dependencies), ['8.8.8.8']);
});

test('nameserver caches are isolated between address policies', async () => {
    const query = async (name, ip, cache, type) => ({
        answers: [{ name, type, ttl: 30, data: type === 'A' ? '8.8.8.8' : '2001:500:2::c' }]
    });
    const permissive = { queryDirectlyUDP: query, isAllowedServerIP: () => true };
    cacheNameserverIPs('isolated.test', ['10.0.0.1'], 30000, 'strict', permissive);
    assert.deepEqual(await resolveServerIPs('isolated.test', permissive), ['10.0.0.1']);
    const restricted = { queryDirectlyUDP: query, isAllowedServerIP: isPublicDnsServerAddress };
    assert.deepEqual(await resolveServerIPs('isolated.test', restricted), ['8.8.8.8', '2001:500:2::c']);
});

test('nested query options support policy selection and top-level policy takes precedence', async () => {
    const reject = () => false;
    const allow = () => true;
    const options = { queryOptions: { isAllowedServerIP: reject } };
    assert.equal(await resolveServerIPs('8.8.8.8', options), null);
    assert.deepEqual(await resolveServerIPs('8.8.8.8', {
        ...options, isAllowedServerIP: allow
    }), ['8.8.8.8']);
    const calls = [];
    assert.deepEqual(await resolveRecordFromRoot('precedence.test', 'A', new Map(), {
        ...options,
        isAllowedServerIP: allow,
        queryDirectlyUDP: async (name, ip, cache, type, queryOptions) => {
            calls.push(queryOptions.isAllowedServerIP);
            return { answers: [{ name, type, data: '8.8.8.8' }] };
        }
    }), ['8.8.8.8']);
    assert.deepEqual(calls, [allow]);
});

test('different policies do not coalesce parallel UDP queries', async t => {
    let sends = 0;
    t.mock.method(dgram, 'createSocket', () => {
        const socket = new EventEmitter();
        socket.bind = (options, callback) => queueMicrotask(callback);
        socket.close = () => {};
        socket.send = (buffer, offset, length, port, host, callback) => {
            sends++;
            callback(null);
            const query = dnsPacket.decode(buffer);
            setImmediate(() => socket.emit('message', dnsPacket.encode({
                type: 'response', id: query.id, questions: query.questions,
                answers: [{ name: query.questions[0].name, type: 'A', ttl: 30, data: '8.8.8.8' }]
            }), { address: host, port }));
        };
        return socket;
    });
    const options = { use0x20: false, useEdns: false };
    const results = await Promise.all([
        queryDirectlyUDP('parallel-policy.test', '8.8.8.8', new Map(), 'A', {
            ...options, isAllowedServerIP: isPublicDnsServerAddress
        }),
        queryDirectlyUDP('parallel-policy.test', '8.8.8.8', new Map(), 'A', {
            ...options, isAllowedServerIP: () => true
        })
    ]);
    assert.equal(sends, 2);
    assert.ok(results.every(result => !result.error));
});
