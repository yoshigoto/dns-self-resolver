import assert from 'node:assert/strict';
import test from 'node:test';
import {
    getReferralNameserverCandidates, getReferralAddressRecords, isValidReferral,
    isSubdomainOrEqual, normalizeDnsName
} from '../index.js';

test('default referral validity requires a query ancestor strictly below the server zone', () => {
    for (const [zone, parent, query, expected] of [
        ['com', '.', 'www.example.com', true],
        ['com', '', 'www.example.com', true],
        ['EXAMPLE.COM.', 'COM.', 'WWW.EXAMPLE.COM.', true],
        ['example.com', 'com', 'example.com', true],
        ['com', 'com', 'www.example.com', false],
        ['com', 'example.com', 'www.example.com', false],
        ['other.com', 'com', 'www.example.com', false],
        ['child.example.com', 'com', 'example.com', false],
        ['example.com', 'notexample.com', 'www.example.com', false],
        ['.', '.', 'www.example.com', false],
        ['', '.', 'www.example.com', false]
    ]) {
        assert.equal(isValidReferral(zone, parent, query), expected, `${zone}/${parent}/${query}`);
    }
});

test('exact and related policies retain the checker discovery and tracing distinctions', () => {
    const exact = { queryNamePolicy: 'exact', requireBelowServerZone: false };
    const related = { queryNamePolicy: 'related', requireBelowServerZone: false };
    assert.equal(isValidReferral('EXAMPLE.COM.', 'example.com', 'example.com', exact), true);
    assert.equal(isValidReferral('com', '.', 'example.com', exact), false);
    assert.equal(isValidReferral('child.example.com', '.', 'example.com', exact), false);
    assert.equal(isValidReferral('com', 'example.com', 'example.com', related), true);
    assert.equal(isValidReferral('child.example.com', 'example.com', 'example.com', related), true);
    assert.equal(isValidReferral('other.com', '.', 'example.com', related), false);
    assert.equal(isValidReferral('notexample.com', '.', 'example.com', related), false);
    assert.throws(() => isValidReferral('com', '.', 'example.com', { queryNamePolicy: 'unknown' }), TypeError);
    assert.throws(() => isValidReferral('com', '.', 'example.com', { requireBelowServerZone: 'false' }), TypeError);
});

test('default validity matches the former resolver predicate for normalized referral zones', () => {
    const names = ['', 'com', 'example.com', 'child.example.com', 'other.com', 'notexample.com'];
    for (const zone of names) {
        for (const parent of ['.', ...names]) {
            for (const query of names) {
                const expected = !!zone && isSubdomainOrEqual(query, zone) &&
                    (parent === '.' || !normalizeDnsName(parent) ||
                        (zone !== normalizeDnsName(parent) && isSubdomainOrEqual(zone, parent)));
                assert.equal(isValidReferral(zone, parent, query), expected);
            }
        }
    }
});

const nsRecords = [
    { name: 'child.example.com', type: 'NS', data: 'NS2.Child.Example.COM.' },
    { name: 'child.example.com', type: 'NS', data: 'ns1.child.example.com' },
    { name: 'child.example.com', type: 'NS', data: 'ns.external.net' },
    { name: 'child.example.com', type: 'NS', data: 'NS1.Child.Example.COM.' },
    { name: 'child.example.com', type: 'SOA', data: {} }
];
const additionals = [
    { name: 'ns1.child.example.com', type: 'AAAA', data: '2001:db8::1' },
    { name: 'ns.external.net', type: 'A', data: '192.0.2.3' },
    { name: 'ns1.child.example.com', type: 'A', data: '192.0.2.1' },
    { name: 'ns2.child.example.com', type: 'A', data: '192.0.2.2' },
    { name: 'ns1.child.example.com', type: 'A', data: '192.0.2.1' },
    { name: 'ns1.child.example.com', type: 'TXT', data: 'not an address' },
    { name: 'other.child.example.com', type: 'A', data: '192.0.2.4' }
];

test('candidate assembly preserves NS order, address order, duplicates, originals and glueless names', () => {
    const before = structuredClone({ nsRecords, additionals });
    const result = getReferralNameserverCandidates(nsRecords, additionals, 'child.example.com');
    assert.deepEqual(result.candidates.map(candidate => candidate.nsName),
        ['ns2.child.example.com', 'ns1.child.example.com', 'ns.external.net', 'ns1.child.example.com']);
    assert.deepEqual(result.addressRecords, [additionals[0], additionals[2], additionals[3], additionals[4]]);
    assert.deepEqual(result.candidates[0].addressRecords, [additionals[3]]);
    assert.deepEqual(result.candidates[1].addressRecords, [additionals[0], additionals[2], additionals[4]]);
    assert.deepEqual(result.candidates[2].addressRecords, []);
    assert.equal(result.candidates[0].nsRecord, nsRecords[0]);
    assert.equal(result.candidates[1].addressRecords[0], additionals[0]);
    assert.deepEqual({ nsRecords, additionals }, before);
});

test('candidate address selection matches existing selectors across all glue and address-family policies', () => {
    for (const gluePolicy of ['strict', 'in-domain-only', 'allow-sibling']) {
        for (const serverZone of ['.', '', 'example.com', 'child.example.com']) {
            for (const addressTypes of [['A'], ['AAAA'], ['A', 'AAAA'], []]) {
                const result = getReferralNameserverCandidates(nsRecords, additionals, 'child.example.com',
                    { gluePolicy, serverZone, addressTypes });
                const expected = getReferralAddressRecords(additionals, nsRecords.map(record => record.data),
                    'child.example.com', gluePolicy, serverZone).filter(record => addressTypes.includes(record.type));
                assert.deepEqual(result.addressRecords, expected);
                for (const candidate of result.candidates) {
                    assert.deepEqual(candidate.addressRecords, expected.filter(record =>
                        normalizeDnsName(record.name) === candidate.nsName));
                }
            }
        }
    }
});

test('candidate assembly does not silently drop blocked or malformed address data before diagnostics', () => {
    const records = [
        { name: 'ns.child.example.com', type: 'A', data: '10.0.0.1' },
        { name: 'ns.child.example.com', type: 'A', data: 'not-an-ip' }
    ];
    const ns = [{ name: 'child.example.com', type: 'NS', data: records[0].name }];
    assert.deepEqual(getReferralNameserverCandidates(ns, records, 'child.example.com').addressRecords, records);
    assert.deepEqual(getReferralNameserverCandidates([], records, 'child.example.com'),
        { addressRecords: [], candidates: [] });
    assert.throws(() => getReferralNameserverCandidates(ns, records, 'child.example.com',
        { addressTypes: ['TXT'] }), TypeError);
    assert.throws(() => getReferralNameserverCandidates(ns, records, 'child.example.com',
        { gluePolicy: 'unknown' }), /gluePolicy/);
});
