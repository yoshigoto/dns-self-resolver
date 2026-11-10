import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import { EventEmitter } from 'node:events';
import test from 'node:test';
import dnsPacket from 'dns-packet';

import { createQueryBudget, queryDirectlyUDP } from '../index.js';

const serverIp = '127.0.0.1';
const answerFor = query => ({
    type: 'response',
    id: query.id,
    questions: query.questions,
    answers: [{ name: query.questions[0].name, type: 'A', ttl: 60, data: '192.0.2.20' }]
});

// 受信した問い合わせを記録し、onQuery(reply, 受信数) に応答を任せる UDP サーバーを 127.0.0.1 に立てる
async function startUdpServer(t, onQuery = () => {}) {
    const server = dgram.createSocket('udp4');
    const state = { received: [], port: 0 };
    server.on('message', (message, rinfo) => {
        const query = dnsPacket.decode(message);
        state.received.push({ id: query.id, name: query.questions[0].name, port: rinfo.port, at: Date.now() });
        const reply = () => server.send(dnsPacket.encode(answerFor(query)), rinfo.port, rinfo.address);
        onQuery(reply, state.received.length);
    });
    await new Promise(resolve => server.bind(0, serverIp, resolve));
    state.port = server.address().port;
    t.after(() => server.close());
    return state;
}

const fastRetry = port => ({ udpPort: port, timeoutMs: 400, udpRetryIntervalMs: 30 });

test('a lost UDP query is retransmitted with the same ID, name case and source port', async (t) => {
    const udp = await startUdpServer(t, (reply, count) => { if (count === 2) reply(); });

    const result = await queryDirectlyUDP('lost-once.example.test', serverIp, new Map(), 'A', fastRetry(udp.port));

    assert.equal(result.answers[0].data, '192.0.2.20');
    assert.equal(result.udpAttempts, 2);
    assert.equal(udp.received.length, 2);
    const [first, second] = udp.received;
    assert.deepEqual([second.id, second.name, second.port], [first.id, first.name, first.port]);
});

test('an unresponsive server is tried three times with doubling intervals before TIMEOUT', async (t) => {
    const udp = await startUdpServer(t);

    const result = await queryDirectlyUDP('silent.example.test', serverIp, new Map(), 'A', fastRetry(udp.port));

    assert.equal(result.error, 'TIMEOUT');
    assert.equal(result.udpAttempts, 3);
    assert.equal(udp.received.length, 3);
    const [first, second, third] = udp.received.map(query => query.at);
    assert.ok(third - second > second - first);
});

test('a late response to the first transmission is accepted after a retransmission', async (t) => {
    const udp = await startUdpServer(t, (reply, count) => { if (count === 1) setTimeout(reply, 60); });

    const result = await queryDirectlyUDP('slow.example.test', serverIp, new Map(), 'A', fastRetry(udp.port));

    assert.equal(result.answers[0].data, '192.0.2.20');
    assert.equal(result.udpAttempts, 2);
});

test('an answered query is not retransmitted and has no udpAttempts', async (t) => {
    const udp = await startUdpServer(t, reply => reply());

    const result = await queryDirectlyUDP('answered.example.test', serverIp, new Map(), 'A', fastRetry(udp.port));
    await new Promise(resolve => setTimeout(resolve, 80));

    assert.equal(result.udpAttempts, undefined);
    assert.equal(udp.received.length, 1);
});

test('retransmissions consume the query budget and stop when it is exhausted', async (t) => {
    const udp = await startUdpServer(t);
    const queryBudget = createQueryBudget(2);

    const result = await queryDirectlyUDP('budget.example.test', serverIp, new Map(), 'A', {
        ...fastRetry(udp.port), queryBudget
    });

    assert.equal(result.error, 'TIMEOUT');
    assert.equal(udp.received.length, 2);
    assert.deepEqual(queryBudget, { remaining: 0, exhausted: true });
});

test('udpTries and timeoutMs bound the number of transmissions', async (t) => {
    const udp = await startUdpServer(t);

    await queryDirectlyUDP('single.example.test', serverIp, new Map(), 'A', { ...fastRetry(udp.port), udpTries: 1 });
    assert.equal(udp.received.length, 1);

    // 3 回目 (90 ms 後) は timeoutMs を超えるため送信しない
    await queryDirectlyUDP('short.example.test', serverIp, new Map(), 'A', { ...fastRetry(udp.port), timeoutMs: 60 });
    assert.equal(udp.received.length, 3);

    for (const invalid of [{ udpTries: 0 }, { udpTries: 1.5 }, { udpRetryIntervalMs: 0 }, { udpRetryIntervalMs: '1000' }]) {
        assert.throws(() => queryDirectlyUDP('invalid.example.test', serverIp, new Map(), 'A', invalid), TypeError);
    }
});

test('by default a query is sent at 0 s, 1 s and 3 s and times out at 5 s', async (t) => {
    const sentAt = [];
    t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
    t.mock.method(dgram, 'createSocket', () => {
        const socket = new EventEmitter();
        socket.close = () => {};
        socket.bind = (options, callback) => queueMicrotask(callback);
        socket.send = (buffer, offset, length, port, host, callback) => {
            sentAt.push(Date.now());
            callback(null);
        };
        return socket;
    });
    const flush = () => new Promise(resolve => setImmediate(resolve));

    let result = null;
    queryDirectlyUDP('default-schedule.example.test', '192.0.2.1', new Map(), 'A').then((value) => { result = value; });
    await flush();
    const startedAt = sentAt[0];
    for (const [tickMs, expectedSends] of [[999, 1], [1, 2], [1999, 2], [1, 3], [1999, 3]]) {
        t.mock.timers.tick(tickMs);
        await flush();
        assert.equal(sentAt.length, expectedSends);
        assert.equal(result, null);
    }
    t.mock.timers.tick(1);
    await flush();

    assert.deepEqual(sentAt.map(at => at - startedAt), [0, 1000, 3000]);
    assert.equal(result.error, 'TIMEOUT');
    assert.equal(result.udpAttempts, 3);
});
