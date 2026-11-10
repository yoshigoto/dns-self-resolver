import assert from 'node:assert/strict';
import os from 'node:os';
import test from 'node:test';
import dnsPacket from 'dns-packet';

import {
    isPublicDnsServerAddress,
    resolveRecordFromRoot,
    ROOT_SERVERS,
    ROOT_SERVER_IPS,
    ROOT_SERVER_IPV6_ADDRESSES,
    setDefaultRootServers
} from '../index.js';

const AA = dnsPacket.AUTHORITATIVE_ANSWER;
const answer = (name) => ({
    flags: AA, rcode: 'NOERROR', answers: [{ type: 'A', name, ttl: 300, data: '192.0.2.7' }], authorities: [], additionals: []
});

function withInterfaces(t, addresses) {
    t.mock.method(os, 'networkInterfaces', () => ({
        eth0: addresses.map(address => ({ address, family: address.includes(':') ? 'IPv6' : 'IPv4', internal: false }))
    }));
}

test('root hints list 13 servers with distinct public IPv4 and IPv6 addresses', () => {
    const all = [...ROOT_SERVER_IPS, ...ROOT_SERVER_IPV6_ADDRESSES];
    assert.equal(ROOT_SERVERS.length, 13);
    assert.equal(new Set(all).size, 26);
    assert.ok(all.every(isPublicDnsServerAddress));
    assert.deepEqual(ROOT_SERVERS[1], { name: 'b.root-servers.net', ipv4: '170.247.170.2', ipv6: '2801:1b8:10::b' });
});

test('the first root server varies between resolutions and IPv6 is skipped without a global IPv6 address', async (t) => {
    withInterfaces(t, ['192.0.2.10', 'fe80::1']);
    const firstAsked = new Set();
    for (let i = 0; i < 40; i++) {
        await resolveRecordFromRoot(`spread-${i}.test`, 'A', new Map(), {
            queryDirectlyUDP: async (name, serverIp) => {
                firstAsked.add(serverIp);
                return answer(name);
            }
        });
    }
    assert.ok(firstAsked.size > 1);
    assert.ok([...firstAsked].every(ip => ROOT_SERVER_IPS.includes(ip)));
});

test('IPv6 root servers are candidates when the host has a global IPv6 address', async (t) => {
    withInterfaces(t, ['192.0.2.10', '2001:db8::10']);
    const asked = [];
    const records = await resolveRecordFromRoot('dual-stack.test', 'A', new Map(), {
        queryDirectlyUDP: async (name, serverIp) => {
            asked.push(serverIp);
            return { flags: 0, rcode: 'NOERROR', answers: [], authorities: [], additionals: [] };
        }
    });
    assert.deepEqual(records, []);
    assert.deepEqual([...asked].sort(), [...ROOT_SERVER_IPS, ...ROOT_SERVER_IPV6_ADDRESSES].sort());
});

test('a root server that failed to respond is tried last on later resolutions', async (t) => {
    withInterfaces(t, ['192.0.2.10']);
    let failed = null;
    await resolveRecordFromRoot('backoff-seed.test', 'A', new Map(), {
        queryDirectlyUDP: async (name, serverIp) => {
            if (failed === null) failed = serverIp;
            return serverIp === failed ? { error: 'TIMEOUT', retryable: true } : answer(name);
        }
    });

    for (let i = 0; i < 30; i++) {
        const asked = [];
        await resolveRecordFromRoot(`backoff-${i}.test`, 'A', new Map(), {
            queryDirectlyUDP: async (name, serverIp) => {
                asked.push(serverIp);
                return { error: 'QUERY_EXCEPTION' };
            }
        });
        assert.equal(asked.length, ROOT_SERVER_IPS.length);
        assert.equal(asked.at(-1), failed);
    }
});

test('rootServers and setDefaultRootServers replace the hints and keep the given order', async (t) => {
    t.after(() => setDefaultRootServers(null));
    const run = async (dependencies) => {
        const asked = [];
        await resolveRecordFromRoot('override.test', 'A', new Map(), {
            ...dependencies,
            queryDirectlyUDP: async (name, serverIp) => {
                asked.push(serverIp);
                return { error: 'TIMEOUT', retryable: true };
            }
        });
        return asked;
    };

    assert.deepEqual(await run({ rootServers: ['192.0.2.2', '192.0.2.1'] }), ['192.0.2.2', '192.0.2.1']);
    setDefaultRootServers(['192.0.2.3', '2001:db8::3']);
    assert.deepEqual(await run({}), ['192.0.2.3', '2001:db8::3']);
    assert.deepEqual(await run({ rootServers: ['192.0.2.4'] }), ['192.0.2.4']);

    await assert.rejects(run({ rootServers: ['ns.example.test'] }), TypeError);
    assert.throws(() => setDefaultRootServers([]), TypeError);
});
