import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import { EventEmitter } from 'node:events';
import net from 'node:net';
import test from 'node:test';
import dnsPacket from 'dns-packet';
import {
    createQueryBudget, queryDirectlyUDP, queryDirectlyTCP,
    resolveRecordFromRoot, resolveRecordFromServer, resolveServerIPs
} from '../index.js';

const serverIp = '127.0.0.1';
const defaults = { use0x20: false, timeoutMs: 50 };

function mockTransports(t, respond = () => ({})) {
    const sends = [];
    const connections = [];
    const reply = (query, transport) => ({
        type: 'response', id: query.id, questions: query.questions,
        answers: [{ name: query.questions[0].name, type: 'A', ttl: 30, data: '192.0.2.1' }],
        ...respond(query, transport, sends.length)
    });
    t.mock.method(dgram, 'createSocket', () => {
        const socket = new EventEmitter();
        socket.bind = (_options, callback) => queueMicrotask(callback);
        socket.close = () => {};
        socket.send = (buffer, offset, length, port, address, callback) => {
            const query = dnsPacket.decode(buffer);
            sends.push({ transport: 'udp', query });
            callback(null);
            queueMicrotask(() => socket.emit('message',
                dnsPacket.encode(reply(query, 'udp')), { address, port }));
        };
        return socket;
    });
    t.mock.method(net, 'createConnection', (_options, onConnect) => {
        const socket = new EventEmitter();
        socket.destroy = () => {};
        socket.write = buffer => {
            const query = dnsPacket.streamDecode(buffer);
            sends.push({ transport: 'tcp', query });
            queueMicrotask(() => socket.emit('data', dnsPacket.streamEncode(reply(query, 'tcp'))));
        };
        connections.push(socket);
        queueMicrotask(onConnect);
        return socket;
    });
    return { sends, connections };
}

test('query budgets require a non-negative safe integer', () => {
    for (const invalid of [-1, 1.5, NaN, Infinity, '1000', Number.MAX_SAFE_INTEGER + 1]) {
        assert.throws(() => createQueryBudget(invalid), TypeError);
    }
    assert.deepEqual(createQueryBudget(0), { remaining: 0, exhausted: false });
    assert.throws(() => queryDirectlyUDP('invalid.test', serverIp, new Map(), 'A',
        { queryBudget: { remaining: -1 } }), TypeError);
});

test('1000 transmissions are permitted, the 1001st is blocked, and cache hits remain free', async t => {
    const { sends } = mockTransports(t);
    const queryBudget = createQueryBudget(1000);
    const cache = new Map();
    const options = { ...defaults, queryBudget };
    for (let index = 0; index < 1000; index++) {
        const result = await queryDirectlyUDP(`${index}.limit.test`, serverIp, cache, 'A', options);
        assert.equal(result.error, undefined);
    }
    assert.equal(queryBudget.remaining, 0);
    assert.equal(queryBudget.exhausted, false);
    assert.equal((await queryDirectlyUDP('999.limit.test', serverIp, cache, 'A', options)).isCached, true);
    const result = await queryDirectlyUDP('1000.limit.test', serverIp, cache, 'A', options);
    assert.equal(result.error, 'QUERY_LIMIT_EXCEEDED');
    assert.equal(result.retryable, false);
    assert.equal(queryBudget.exhausted, true);
    assert.equal(sends.length, 1000);
    assert.equal((await queryDirectlyUDP('999.limit.test', serverIp, cache, 'A', options)).isCached, true);
    const freshBudget = createQueryBudget(1);
    assert.equal((await queryDirectlyUDP('1000.limit.test', serverIp, cache, 'A',
        { ...defaults, queryBudget: freshBudget })).error, undefined);
    assert.equal(freshBudget.remaining, 0);
});

for (const limit of [1, 2, 3]) {
    test(`EDNS retry and TCP fallback each consume a transmission (budget ${limit})`, async t => {
        const { sends, connections } = mockTransports(t, (query, transport) => {
            if (transport === 'tcp') return {};
            return query.additionals.length
                ? { flags: 1, answers: [] }
                : { flags: dnsPacket.TRUNCATED_RESPONSE, answers: [] };
        });
        const queryBudget = createQueryBudget(limit);
        const result = await queryDirectlyUDP(`retry-${limit}.test`, serverIp, new Map(), 'A',
            { ...defaults, queryBudget });
        assert.deepEqual(sends.map(send => send.transport), ['udp', 'udp', 'tcp'].slice(0, limit));
        assert.equal(connections.length, limit === 3 ? 1 : 0);
        assert.equal(result.error, limit === 3 ? undefined : 'QUERY_LIMIT_EXCEEDED');
        assert.equal(queryBudget.remaining, 0);
        assert.equal(queryBudget.exhausted, limit < 3);
        assert.equal(result.retryWithoutEdns, true);
    });
}

for (const limit of [1, 2]) {
    test(`0x20 retry consumes a transmission (budget ${limit})`, async t => {
        const { sends } = mockTransports(t, (query, transport, count) => count === 1
            ? { questions: query.questions.map(question => ({
                ...question,
                name: [...question.name].map(letter =>
                    letter === letter.toLowerCase() ? letter.toUpperCase() : letter.toLowerCase()).join('')
            })) }
            : {});
        const queryBudget = createQueryBudget(limit);
        const result = await queryDirectlyUDP(`case-${limit}.test`, serverIp, new Map(), 'A',
            { timeoutMs: 10, queryBudget });
        assert.equal(sends.length, limit);
        assert.equal(result.caseRandomizationFallback, true);
        assert.equal(result.error, limit === 1 ? 'QUERY_LIMIT_EXCEEDED' : undefined);
    });
}

test('coalesced queries share one transmission only within the same budget', async t => {
    const { sends } = mockTransports(t);
    const queryBudget = createQueryBudget(1);
    const options = { ...defaults, queryBudget };
    const results = await Promise.all([
        queryDirectlyUDP('shared.test', serverIp, new Map(), 'A', options),
        queryDirectlyUDP('shared.test', serverIp, new Map(), 'A', options)
    ]);
    assert.ok(results.every(result => !result.error));
    assert.equal(sends.length, 1);
    assert.equal(queryBudget.remaining, 0);
    assert.equal(queryBudget.exhausted, false);
    const otherBudget = createQueryBudget(1);
    const separated = await Promise.all([
        queryDirectlyUDP('isolated.test', serverIp, new Map(), 'A', options),
        queryDirectlyUDP('isolated.test', serverIp, new Map(), 'A', { ...defaults, queryBudget: otherBudget })
    ]);
    assert.equal(separated[0].error, 'QUERY_LIMIT_EXCEEDED');
    assert.equal(separated[1].error, undefined);
    assert.equal(otherBudget.remaining, 0);
    assert.equal(sends.length, 2);
    const independentBudgets = [createQueryBudget(1), createQueryBudget(1)];
    const independent = await Promise.all(independentBudgets.map(queryBudget =>
        queryDirectlyUDP('independent.test', serverIp, new Map(), 'A', { ...defaults, queryBudget })));
    assert.ok(independent.every(result => !result.error));
    assert.ok(independentBudgets.every(budget => budget.remaining === 0));
    assert.equal(sends.length, 4);
});

test('cancelled, invalid and policy-blocked queries do not consume transmissions', async t => {
    const { sends, connections } = mockTransports(t);
    const controller = new AbortController();
    const queryBudget = createQueryBudget(1);
    const options = { ...defaults, queryBudget };
    controller.abort();
    for (const query of [queryDirectlyUDP, queryDirectlyTCP]) {
        assert.equal((await query('cancelled.test', serverIp, new Map(), 'A',
            { ...options, signal: controller.signal })).error, 'ABORTED');
        assert.equal((await query('invalid.test', 'hostname', new Map(), 'A', options)).error, 'SEND_ERROR');
        assert.equal((await query('blocked.test', serverIp, new Map(), 'A',
            { ...options, isAllowedServerIP: () => false })).error, 'BLOCKED_ADDRESS');
    }
    const pending = queryDirectlyUDP('cancel-bind.test', serverIp, new Map(), 'A',
        { ...options, signal: new AbortController().signal });
    // Exhaust the budget while the UDP socket is binding.
    queryBudget.remaining = 0;
    assert.equal((await pending).error, 'QUERY_LIMIT_EXCEEDED');
    assert.equal(sends.length, 0);
    assert.equal(connections.length, 0);
});

test('cancelling during UDP bind or TCP connect closes the socket without consuming budget', async t => {
    const { sends } = mockTransports(t);
    for (const query of [queryDirectlyUDP, queryDirectlyTCP]) {
        const controller = new AbortController();
        const queryBudget = createQueryBudget(1);
        const pending = query('cancel-before-send.test', serverIp, new Map(), 'A',
            { ...defaults, queryBudget, signal: controller.signal });
        controller.abort();
        assert.equal((await pending).error, 'ABORTED');
        assert.equal(queryBudget.remaining, 1);
    }
    assert.equal(sends.length, 0);
});

test('TCP rechecks the shared budget after connecting and cache hits are free', async t => {
    const { sends } = mockTransports(t);
    const queryBudget = createQueryBudget(1);
    const cache = new Map();
    const options = { ...defaults, queryBudget };
    const pending = queryDirectlyTCP('tcp-race.test', serverIp, cache, 'A', options);
    queryBudget.remaining = 0;
    assert.equal((await pending).error, 'QUERY_LIMIT_EXCEEDED');
    assert.equal(sends.length, 0);
    const fresh = createQueryBudget(1);
    const successful = { ...defaults, queryBudget: fresh };
    assert.equal((await queryDirectlyTCP('tcp-cache.test', serverIp, cache, 'A', successful)).error, undefined);
    assert.equal((await queryDirectlyTCP('tcp-cache.test', serverIp, cache, 'A', successful)).isCached, true);
    assert.equal(sends.length, 1);
    assert.equal(fresh.exhausted, false);
});

test('root and nested NS resolution forward the budget without negative-caching a limit failure', async t => {
    const { sends } = mockTransports(t, query => {
        const { name, type } = query.questions[0];
        if (name === 'nested-budget.test') return {
            answers: [], authorities: [{ name, type: 'NS', ttl: 30, data: 'ns.glueless-budget.test' }]
        };
        return { flags: dnsPacket.AUTHORITATIVE_ANSWER,
            answers: type === 'A' ? [{ name, type, ttl: 30, data: '192.0.2.1' }] : [] };
    });
    const queryBudget = createQueryBudget(1);
    assert.deepEqual(await resolveRecordFromRoot('nested-budget.test', 'A', new Map(),
        { queryBudget, queryOptions: defaults }), []);
    assert.equal(queryBudget.exhausted, true);
    assert.equal(sends.length, 1);
    const deps = { queryBudget: createQueryBudget(0), queryOptions: defaults };
    assert.equal(await resolveServerIPs('uncached-budget.test', deps), null);
    assert.equal(deps.queryBudget.exhausted, true);
    const result = await resolveServerIPs('uncached-budget.test',
        { ...deps, queryBudget: createQueryBudget(2) });
    assert.deepEqual(result, ['192.0.2.1']);
    assert.equal(sends.length, 3);
});

test('partial A-only results after a send limit do not hide AAAA on a later resolution', async t => {
    const { sends } = mockTransports(t, query => {
        const { name, type } = query.questions[0];
        return { flags: dnsPacket.AUTHORITATIVE_ANSWER,
            answers: [{ name, type, ttl: 30, data: type === 'A' ? '192.0.2.1' : '2001:db8::1' }] };
    });
    const queryBudget = createQueryBudget(1);
    const dependencies = { queryOptions: { ...defaults, queryBudget }, dnsResponseCache: new Map() };
    assert.deepEqual(await resolveServerIPs('partial-budget.test', dependencies), ['192.0.2.1']);
    assert.equal(queryBudget.exhausted, true);
    const fresh = createQueryBudget(1);
    assert.deepEqual(await resolveServerIPs('partial-budget.test', {
        ...dependencies, queryBudget: fresh
    }), ['192.0.2.1', '2001:db8::1']);
    assert.equal(sends.length, 2);
    assert.equal(fresh.remaining, 0);
    assert.equal(fresh.exhausted, false);
});

test('direct parallel A/AAAA retrieval shares one transmission budget', async t => {
    const { sends } = mockTransports(t);
    const queryBudget = createQueryBudget(1);
    assert.deepEqual(await resolveRecordFromServer('direct-budget.test', serverIp,
        ['A', 'AAAA'], new Map(), { ...defaults, queryBudget }), ['192.0.2.1']);
    assert.equal(queryBudget.exhausted, true);
    assert.equal(sends.length, 1);
});
