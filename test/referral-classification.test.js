import assert from 'node:assert/strict';
import test from 'node:test';
import {
    classifyReferralAddressRecords,
    getReferralAddressRecords,
    isSubdomainOrEqual,
    normalizeDnsName,
    resolveRecordFromRoot,
    ROOT_SERVER_BOOTSTRAP_IP
} from '../index.js';

const additionals = [
    { name: 'NS.External.NET.', type: 'A', data: '192.0.2.1' },
    { name: 'ns.child.example.com', type: 'AAAA', data: '2001:db8::2' },
    { name: 'ns.sibling.example.com', type: 'A', data: '192.0.2.3' },
    { name: 'NS.Child.Example.COM.', type: 'A', data: '192.0.2.4' },
    { name: 'not-an-ns.child.example.com', type: 'A', data: '192.0.2.5' },
    { name: 'ns.child.example.com', type: 'TXT', data: 'not an address' },
    { name: '.', type: 'OPT', udpPayloadSize: 1232 }
];
const nsNames = ['ns.external.net', 'NS.Child.Example.COM.', 'NS.Sibling.Example.COM.'];

test('classification normalizes names and preserves records, order and response sections', () => {
    const before = structuredClone(additionals);
    const classified = classifyReferralAddressRecords(
        additionals, nsNames, 'CHILD.EXAMPLE.COM.', 'EXAMPLE.COM.'
    );
    assert.deepEqual(classified, {
        inDomainGlueRecords: [additionals[1], additionals[3]],
        siblingGlueRecords: [additionals[2]],
        unrelatedAddressRecords: [additionals[0]]
    });
    assert.equal(classified.inDomainGlueRecords[0], additionals[1]);
    assert.deepEqual(additionals, before);
});

test('classification uses the actual parent zone rather than assuming a single-label zone cut', () => {
    const records = [
        { name: 'ns.sibling.example.com', type: 'A', data: '192.0.2.1' },
        { name: 'notexample.com', type: 'AAAA', data: '2001:db8::2' }
    ];
    const classified = classifyReferralAddressRecords(
        records, records.map(record => record.name), 'child.sub.example.com', 'example.com'
    );
    assert.deepEqual(classified.siblingGlueRecords, [records[0]]);
    assert.deepEqual(classified.unrelatedAddressRecords, [records[1]]);
    assert.deepEqual(classifyReferralAddressRecords(
        records, records.map(record => record.name), 'child.sub.example.com'
    ).unrelatedAddressRecords, records);
});

test('root parent representations classify out-of-domain NS addresses as sibling without selecting them', () => {
    const records = [{ name: 'a.gtld-servers.net', type: 'A', data: '192.0.2.53' }];
    for (const parentZone of ['.', '']) {
        assert.deepEqual(classifyReferralAddressRecords(
            records, ['A.GTLD-SERVERS.NET.'], 'com', parentZone
        ), {
            inDomainGlueRecords: [],
            siblingGlueRecords: records,
            unrelatedAddressRecords: []
        });
        assert.deepEqual(getReferralAddressRecords(
            records, ['a.gtld-servers.net'], 'com', 'in-domain-only', parentZone
        ), []);
    }
    assert.deepEqual(getReferralAddressRecords(
        records, ['a.gtld-servers.net'], 'com', 'strict', '.'
    ), records);
});

test('selection is independent of classification and keeps the original additional order', () => {
    assert.deepEqual(getReferralAddressRecords(
        additionals, nsNames, 'child.example.com', 'in-domain-only', '.'
    ), [additionals[1], additionals[3]]);
    assert.deepEqual(getReferralAddressRecords(
        additionals, nsNames, 'child.example.com', 'strict', '.'
    ), additionals.slice(0, 4));
    assert.deepEqual(getReferralAddressRecords(
        additionals, nsNames, 'child.example.com', 'allow-sibling', 'example.com'
    ), [additionals[1], additionals[2], additionals[3]]);
    assert.throws(() => getReferralAddressRecords(
        additionals, nsNames, 'child.example.com', 'unsupported', '.'
    ), /未対応の gluePolicy/);
});

test('existing strict and allow-sibling policies retain their selection semantics', () => {
    for (const serverZone of ['.', '', 'example.com', 'EXAMPLE.COM.', 'child.example.com', 'external.net']) {
        for (const policy of ['strict', 'allow-sibling']) {
            const expected = additionals.filter(record =>
                (record.type === 'A' || record.type === 'AAAA') &&
                nsNames.some(name => normalizeDnsName(name) === normalizeDnsName(record.name)) &&
                (policy === 'strict'
                    ? serverZone === '.' || isSubdomainOrEqual(record.name, 'child.example.com')
                    : !normalizeDnsName(serverZone) || isSubdomainOrEqual(record.name, serverZone))
            );
            assert.deepEqual(getReferralAddressRecords(
                additionals, nsNames, 'child.example.com', policy, serverZone
            ), expected, `${policy}: ${serverZone}`);
        }
    }
});

test('in-domain-only excludes root out-of-domain glue but permits self-resolved NS addresses', async () => {
    const queries = [];
    const result = await resolveRecordFromRoot('com', 'A', new Map(), {
        gluePolicy: 'in-domain-only',
        queryDirectlyUDP: async (name, ip, cache, type) => {
            queries.push(ip);
            if (ip === ROOT_SERVER_BOOTSTRAP_IP) {
                return {
                    authorities: [{ name: 'com', type: 'NS', data: 'a.gtld-servers.net' }],
                    additionals: [{ name: 'a.gtld-servers.net', type: 'A', data: '192.0.2.53' }]
                };
            }
            assert.equal(ip, '192.0.2.54');
            return { answers: [{ name, type, data: '192.0.2.55' }] };
        },
        resolveHostnameIPv4Self: async name => {
            assert.equal(name, 'a.gtld-servers.net');
            return '192.0.2.54';
        }
    });
    assert.deepEqual(result, ['192.0.2.55']);
    assert.deepEqual(queries, [ROOT_SERVER_BOOTSTRAP_IP, '192.0.2.54']);
});

test('empty or unmatched referral addresses are not classified or selected', () => {
    const empty = { inDomainGlueRecords: [], siblingGlueRecords: [], unrelatedAddressRecords: [] };
    assert.deepEqual(classifyReferralAddressRecords([], [], 'child.example.com', '.'), empty);
    assert.deepEqual(classifyReferralAddressRecords(additionals, [], 'child.example.com', '.'), empty);
    assert.deepEqual(getReferralAddressRecords(additionals, [], 'child.example.com', 'strict', '.'), []);
});
