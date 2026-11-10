import assert from 'node:assert/strict';
import test from 'node:test';
import net from 'node:net';
import dnsPacket from 'dns-packet';

import {
    queryDirectlyTCP,
    resolveHostnameIPv4Self,
    resolveRecordFromRoot,
    resolveServerIPs,
    ROOT_SERVER_IPS
} from '../index.js';

const AA = dnsPacket.AUTHORITATIVE_ANSWER;
const answer = (type, name, data) => ({
    flags: AA, rcode: 'NOERROR', answers: [{ type, name, ttl: 300, data }], authorities: [], additionals: []
});
const referral = (zone, ip) => ({
    flags: 0,
    rcode: 'NOERROR',
    answers: [],
    authorities: [{ type: 'NS', name: zone, ttl: 60, data: `ns.${zone}` }],
    additionals: [{ type: 'A', name: `ns.${zone}`, ttl: 60, data: ip }]
});

test('an IPv4-only resolution is not reused as the complete address list', async () => {
    const queryDirectlyUDP = async (name, serverIp, cache, qType) =>
        answer(qType, name, qType === 'A' ? '192.0.2.53' : '2001:db8::53');
    const dependencies = { queryDirectlyUDP, dnsResponseCache: new Map() };

    assert.equal(await resolveHostnameIPv4Self('ns.family-cache.test', dependencies), '192.0.2.53');
    assert.deepEqual(
        await resolveServerIPs('ns.family-cache.test', dependencies),
        ['192.0.2.53', '2001:db8::53']
    );
});

test('a transient AAAA failure is not cached as a complete address list', async () => {
    let failAaaa = true;
    const queryDirectlyUDP = async (name, serverIp, cache, qType) => (qType === 'AAAA' && failAaaa)
        ? { error: 'TIMEOUT', retryable: true }
        : answer(qType, name, qType === 'A' ? '192.0.2.53' : '2001:db8::53');
    const dependencies = { queryDirectlyUDP, dnsResponseCache: new Map() };

    assert.deepEqual(await resolveServerIPs('ns.flaky-aaaa.test', dependencies), ['192.0.2.53']);
    failAaaa = false;
    assert.deepEqual(
        await resolveServerIPs('ns.flaky-aaaa.test', dependencies),
        ['192.0.2.53', '2001:db8::53']
    );
});

test('an authoritative NODATA for AAAA is cached together with the A addresses', async () => {
    let sent = 0;
    const queryDirectlyUDP = async (name, serverIp, cache, qType) => {
        sent++;
        return qType === 'A'
            ? answer('A', name, '192.0.2.53')
            : { flags: AA, rcode: 'NOERROR', answers: [], authorities: [], additionals: [] };
    };
    const dependencies = { queryDirectlyUDP, dnsResponseCache: new Map() };

    assert.deepEqual(await resolveServerIPs('ns.v4-only.test', dependencies), ['192.0.2.53']);
    const sentAfterFirst = sent;
    assert.deepEqual(await resolveServerIPs('ns.v4-only.test', dependencies), ['192.0.2.53']);
    assert.equal(sent, sentAfterFirst);
});

test('a cached family is reused and only the missing family is resolved', async () => {
    let failA = false;
    const sent = { A: 0, AAAA: 0 };
    const queryDirectlyUDP = async (name, serverIp, cache, qType) => {
        sent[qType]++;
        if (qType === 'AAAA') return { flags: AA, rcode: 'NOERROR', answers: [], authorities: [], additionals: [] };
        return failA ? { error: 'TIMEOUT', retryable: true } : answer('A', name, '192.0.2.53');
    };
    const dependencies = { queryDirectlyUDP };

    assert.equal(await resolveHostnameIPv4Self('ns.partial-cache.test', dependencies), '192.0.2.53');
    failA = true;
    sent.A = 0;
    assert.deepEqual(await resolveServerIPs('ns.partial-cache.test', dependencies), ['192.0.2.53']);
    assert.deepEqual(sent, { A: 0, AAAA: 1 });
    assert.deepEqual(await resolveServerIPs('ns.partial-cache.test', dependencies), ['192.0.2.53']);
    assert.deepEqual(sent, { A: 0, AAAA: 1 });
});

test('a cached family is kept when resolving the missing family fails', async () => {
    let failing = false;
    const queryDirectlyUDP = async (name, serverIp, cache, qType) => failing
        ? { error: 'TIMEOUT', retryable: true }
        : answer(qType, name, qType === 'A' ? '192.0.2.53' : '2001:db8::53');
    const dependencies = { queryDirectlyUDP };

    assert.equal(await resolveHostnameIPv4Self('ns.partial-flaky.test', dependencies), '192.0.2.53');
    failing = true;
    assert.deepEqual(await resolveServerIPs('ns.partial-flaky.test', dependencies), ['192.0.2.53']);
    failing = false;
    assert.deepEqual(
        await resolveServerIPs('ns.partial-flaky.test', dependencies),
        ['192.0.2.53', '2001:db8::53']
    );
});

test('deep delegations with CNAME hops are not cut off by a fixed query count', async () => {
    const targets = {
        'www.a.example.com': ['CNAME', 'www.b.example.org'],
        'www.b.example.org': ['CNAME', 'www.c.example.net'],
        'www.c.example.net': ['A', '192.0.2.9']
    };
    const queryDirectlyUDP = async (name, serverIp) => {
        const labels = name.split('.');
        if (ROOT_SERVER_IPS.includes(serverIp)) return referral(labels.slice(-1).join('.'), '192.0.2.1');
        if (serverIp === '192.0.2.1') return referral(labels.slice(-2).join('.'), '192.0.2.2');
        if (serverIp === '192.0.2.2') return referral(labels.slice(-3).join('.'), '192.0.2.3');
        return answer(targets[name][0], name, targets[name][1]);
    };

    assert.deepEqual(
        await resolveRecordFromRoot('www.a.example.com', 'A', new Map(), { queryDirectlyUDP }),
        ['192.0.2.9']
    );
});

test('CNAME chains longer than maxCnameChain are abandoned', async () => {
    const queryDirectlyUDP = async (name) => {
        const index = Number(name.match(/^c(\d+)\./)[1]);
        return answer('CNAME', name, `c${index + 1}.chain.test`);
    };

    assert.deepEqual(
        await resolveRecordFromRoot('c0.chain.test', 'A', new Map(), {
            queryDirectlyUDP, resolutionLimits: { maxCnameChain: 3 }
        }),
        []
    );
});

test('an AA-flagged error response falls through to the next server', async () => {
    const asked = [];
    const queryDirectlyUDP = async (name, serverIp) => {
        asked.push(serverIp);
        return serverIp === ROOT_SERVER_IPS[0]
            ? { flags: AA, rcode: 'REFUSED', answers: [], authorities: [], additionals: [] }
            : answer('A', name, '192.0.2.7');
    };

    assert.deepEqual(
        await resolveRecordFromRoot('aa-refused.test', 'A', new Map(), { queryDirectlyUDP }),
        ['192.0.2.7']
    );
    assert.deepEqual(asked, ROOT_SERVER_IPS.slice(0, 2));
});

test('TCP: a connection closed without a response fails without waiting for the timeout', async () => {
    const server = net.createServer((socket) => {
        socket.on('error', () => {});
        socket.on('data', () => socket.end());
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));

    try {
        const startedAt = Date.now();
        const result = await queryDirectlyTCP('closed.example.test', '127.0.0.1', new Map(), 'A', {
            tcpPort: server.address().port,
            timeoutMs: 5000
        });
        assert.equal(result.error, 'SOCKET_ERROR');
        assert.equal(result.retryable, true);
        assert.ok(Date.now() - startedAt < 2000);
    } finally {
        server.close();
    }
});
