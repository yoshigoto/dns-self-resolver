import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import net from 'node:net';
import test from 'node:test';
import dnsPacket from 'dns-packet';

import {
    createDnsResponseCache,
    queryDirectlyUDP,
    resolveServerIPs,
    setCacheEntry
} from '../index.js';

const serverIp = '127.0.0.1';
const answerFor = (query, extra = {}) => ({
    type: 'response',
    id: query.id,
    questions: query.questions,
    answers: [{ name: query.questions[0].name, type: 'A', ttl: 60, data: '192.0.2.20' }],
    ...extra
});

// buildResponse(query) が返す DNS メッセージで応答する UDP サーバーを 127.0.0.1 に立てる
async function startUdpServer(t, buildResponse) {
    const server = dgram.createSocket('udp4');
    const state = { queries: 0, port: 0 };
    server.on('message', (message, rinfo) => {
        state.queries++;
        server.send(dnsPacket.encode(buildResponse(dnsPacket.decode(message))), rinfo.port, rinfo.address);
    });
    await new Promise(resolve => server.bind(0, serverIp, resolve));
    state.port = server.address().port;
    t.after(() => server.close());
    return state;
}

test('a cached UDP response keeps its transport', async (t) => {
    const udp = await startUdpServer(t, query => answerFor(query));
    const cache = new Map();
    const options = { udpPort: udp.port, timeoutMs: 1000 };

    await queryDirectlyUDP('plain.example.test', serverIp, cache, 'A', options);
    const cached = await queryDirectlyUDP('plain.example.test', serverIp, cache, 'A', options);

    assert.equal(cached.isCached, true);
    assert.equal(cached.transport, 'udp');
    assert.equal(udp.queries, 1);
});

test('a cached TCP fallback response keeps the fallback route information', async (t) => {
    const udp = await startUdpServer(t, query => ({
        type: 'response', id: query.id, flags: dnsPacket.TRUNCATED_RESPONSE, questions: query.questions
    }));
    const tcp = net.createServer((socket) => {
        socket.on('error', () => {});
        socket.on('data', data => socket.end(dnsPacket.streamEncode(answerFor(dnsPacket.streamDecode(data)))));
    });
    await new Promise(resolve => tcp.listen(0, serverIp, resolve));
    t.after(() => tcp.close());
    const cache = new Map();
    const options = { udpPort: udp.port, tcpPort: tcp.address().port, timeoutMs: 1000 };

    const first = await queryDirectlyUDP('truncated.example.test', serverIp, cache, 'A', options);
    const cached = await queryDirectlyUDP('truncated.example.test', serverIp, cache, 'A', options);

    assert.equal(first.retryFrom, 'udp-truncated');
    assert.equal(cached.isCached, true);
    assert.equal(cached.transport, 'tcp');
    assert.equal(cached.retryFrom, 'udp-truncated');
    assert.equal(cached.isFallback, true);
    assert.equal(udp.queries, 1);
});

test('a cached response obtained without EDNS keeps retryWithoutEdns', async (t) => {
    const udp = await startUdpServer(t, query => query.additionals.some(record => record.type === 'OPT')
        ? { type: 'response', id: query.id, flags: 1, questions: query.questions }
        : answerFor(query));
    const cache = new Map();
    const options = { udpPort: udp.port, timeoutMs: 1000 };

    const first = await queryDirectlyUDP('formerr.example.test', serverIp, cache, 'A', options);
    const cached = await queryDirectlyUDP('formerr.example.test', serverIp, cache, 'A', options);

    assert.equal(first.retryWithoutEdns, true);
    assert.equal(cached.isCached, true);
    assert.equal(cached.retryWithoutEdns, true);
    assert.equal(udp.queries, 2);
});

test('a cached response obtained without 0x20 keeps caseRandomizationFallback', async (t) => {
    const udp = await startUdpServer(t, query => answerFor({
        ...query,
        questions: [{ ...query.questions[0], name: query.questions[0].name.toLowerCase() }]
    }));
    const cache = new Map();
    const options = { udpPort: udp.port, timeoutMs: 100 };
    const name = 'case-insensitive-authoritative-server.example.test';

    const first = await queryDirectlyUDP(name, serverIp, cache, 'A', options);
    const cached = await queryDirectlyUDP(name, serverIp, cache, 'A', options);

    assert.equal(first.caseRandomizationFallback, true);
    assert.equal(cached.isCached, true);
    assert.equal(cached.caseRandomizationFallback, true);
    assert.equal(udp.queries, 2);
});

test('createDnsResponseCache applies its own entry limit', () => {
    const cache = createDnsResponseCache(2);
    for (const key of ['a', 'b', 'c']) setCacheEntry(cache, key, { rcode: 'NOERROR' });

    assert.deepEqual([...cache.keys()], ['b', 'c']);
    for (const invalid of [0, -1, 1.5, '2']) {
        assert.throws(() => createDnsResponseCache(invalid), TypeError);
    }
});

test('cacheScope shares the nameserver address cache between wrapper functions', async () => {
    let queries = 0;
    const createWrapper = () => async (name, ip, cache, qType) => {
        queries++;
        return {
            flags: dnsPacket.AUTHORITATIVE_ANSWER,
            rcode: 'NOERROR',
            answers: [{ type: qType, name, ttl: 300, data: qType === 'A' ? '192.0.2.53' : '2001:db8::53' }]
        };
    };
    const resolve = (name, dependencies) =>
        resolveServerIPs(name, { queryDirectlyUDP: createWrapper(), dnsResponseCache: new Map(), ...dependencies });

    await resolve('ns.unscoped.test', {});
    await resolve('ns.unscoped.test', {});
    assert.equal(queries, 4);

    queries = 0;
    await resolve('ns.scoped.test', { cacheScope: 'app' });
    assert.deepEqual(await resolve('ns.scoped.test', { cacheScope: 'app' }), ['192.0.2.53', '2001:db8::53']);
    assert.equal(queries, 2);
    await resolve('ns.scoped.test', { cacheScope: 'other' });
    assert.equal(queries, 4);

    await assert.rejects(resolve('ns.scoped.test', { cacheScope: '' }), TypeError);
});
