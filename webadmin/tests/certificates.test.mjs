import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { build } from 'esbuild';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { certificate, toPem } from './certificates.mjs';

// Exercise the browser modules without requiring the host's DOM toast service.
const { outputFiles } = await build({
    stdin: {
        contents: "export * from './web/certificateUtils.js'; export * from './web/verificationUtils.js'; export * from './web/expiryWarning.js'; export * from './web/caService.js';",
        resolveDir: path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
    },
    bundle: true, format: 'esm', platform: 'browser', write: false,
    plugins: [{ name: 'notifications', setup(builder) {
        builder.onResolve({ filter: /^@oie\/web-ui$/ }, () => ({ path: 'notifications', namespace: 'test' }));
        builder.onLoad({ filter: /.*/, namespace: 'test' }, () => ({ contents: 'export function toast() {}' }));
    } }]
});
const utils = await import(`data:text/javascript;base64,${Buffer.from(outputFiles[0].text).toString('base64')}`);
const rsa = await certificate('rsa.example');
const ec = await certificate('ec.example', { type: 'EC' });
const root = await certificate('Root CA', { ca: true });
const intermediate = await certificate('Intermediate CA', { ca: true, issuer: root });
const leaf = await certificate('leaf.example', { issuer: intermediate });

for (const [type, fixture, bits] of [['RSA', rsa, 2048], ['ECDSA', ec, 256]]) {
    test(`${type}: PEM and bare DER retain details and fingerprints`, async () => {
        const reference = new X509Certificate(fixture.pem);
        for (const input of [fixture.pem, reference.raw.toString('base64')]) {
            const details = await utils.parseCertificate(input);
            assert.equal(details.error, undefined);
            assert.equal(details.subject.CN, type === 'RSA' ? 'rsa.example' : 'ec.example');
            assert.equal(details.version, 3);
            assert.equal(details.serialNumber, reference.serialNumber);
            assert.equal(details.fingerprintSha1, reference.fingerprint.replaceAll(':', ''));
        }
        const verified = await utils.verifyCertificate(fixture.pem);
        assert.equal(verified.success, true, verified.error);
        assert.equal(verified.certDetails.publicKeyAlgorithm, type);
        assert.equal(verified.certDetails.keySize, bits);
        assert.equal(verified.certDetails.fingerprintSha1, reference.fingerprint);
        assert.equal(verified.certDetails.fingerprintSha256, reference.fingerprint256);
        assert.equal(utils.base64ToPem(fixture.pem), fixture.pem);
        assert.equal(utils.base64ToPrivateKeyPem(fixture.privateKeyPem), fixture.privateKeyPem);
    });

    test(`${type}: PKCS#8 and legacy private keys match; unrelated keys fail`, async () => {
        const other = await certificate('other.example', { type: type === 'RSA' ? 'RSA' : 'EC' });
        for (const key of [fixture.privateKeyPem, fixture.legacyKeyPem]) {
            assert.equal(utils.isValidPemPrivateKey(key), true);
            const matched = await utils.verifyCertificate(fixture.pem, key);
            assert.equal(matched.success, true, matched.keyValidation?.message || matched.error);
            assert.equal(matched.keyValidation.isValid, true);
            const mismatch = await utils.verifyCertificate(other.pem, key);
            assert.equal(mismatch.success, false);
            assert.equal(mismatch.keyValidation.isValid, false);
        }
    });
}

test('SEC1 with EC PARAMETERS and P-384/P-521 key pairs are supported', async () => {
    const parameters = toPem(new asn1js.ObjectIdentifier({ value: '1.2.840.10045.3.1.7' }).toBER(false), 'EC PARAMETERS');
    const key = parameters + ec.legacyKeyPem;
    assert.equal(utils.isValidPemPrivateKey(key), true);
    assert.equal((await utils.verifyCertificate(ec.pem, key)).success, true);
    for (const namedCurve of ['P-384', 'P-521']) {
        const fixture = await certificate(namedCurve, { type: 'EC', namedCurve });
        const result = await utils.verifyCertificate(fixture.pem, fixture.legacyKeyPem);
        assert.equal(result.success, true, result.keyValidation?.message);
        assert.equal(result.certDetails.keySize, Number(namedCurve.slice(2)));
    }
});

test('Malformed certificate/key and unsupported DSA keys fail without throwing', async () => {
    for (const input of ['', 'not PEM', toPem(new Uint8Array([1, 2, 3])), '-----BEGIN CERTIFICATE-----\n!\n-----END CERTIFICATE-----']) {
        assert.equal(utils.isValidPemCertificate(input), false);
        assert.ok((await utils.parseCertificate(input)).error);
        assert.equal((await utils.verifyCertificate(input)).success, false);
    }
    for (const type of ['PRIVATE KEY', 'RSA PRIVATE KEY', 'EC PRIVATE KEY', 'DSA PRIVATE KEY']) {
        const key = toPem(new Uint8Array([1, 2, 3]), type);
        assert.equal(utils.isValidPemPrivateKey(key), false);
        assert.equal((await utils.verifyCertificate(rsa.pem, key)).success, false);
    }
    assert.equal((await utils.verifyCertificate(rsa.pem, ec.privateKeyPem)).keyValidation.isValid, false);
});

test('Ordered RSA chain verifies; reversed chain and wrong issuer signatures fail', async () => {
    const chain = [leaf.pem, intermediate.pem, root.pem].join('\n');
    assert.equal(utils.isValidPemCertificate(chain), true);
    const result = await utils.verifyCertificate(chain);
    assert.equal(result.success, true, result.error);
    assert.equal(result.certificates.length, 3);
    assert.equal(result.chainDetails.length, 3);
    const parsed = await utils.parseCertificateChainFromPem(chain);
    assert.deepEqual(parsed.map(c => c.type), ['End-entity', 'Intermediate', 'Root CA']);
    assert.deepEqual(parsed.map(c => c.alias), ['leaf.example', 'Intermediate CA', 'Root CA']);
    assert.equal((await utils.verifyCertificate([root.pem, intermediate.pem, leaf.pem].join('\n'))).success, false);
    const wrongIssuer = await certificate('Intermediate CA', { ca: true, issuer: root });
    const badSignature = await utils.verifyCertificate([leaf.pem, wrongIssuer.pem, root.pem].join('\n'));
    assert.equal(badSignature.success, false);
    assert.ok(badSignature.chainValidation.errors.some(e => e.includes('signature verification failed')));
});

test('ECDSA certificate chain verifies with the issuer key', async () => {
    const issuer = await certificate('EC root', { ca: true, type: 'EC' });
    const child = await certificate('EC leaf', { issuer, type: 'EC' });
    const result = await utils.verifyCertificate(child.pem + issuer.pem);
    assert.equal(result.success, true, result.error);
});

test('SANs, key usages and certificate type survive the ASN.1 migration', async () => {
    const altNames = new pkijs.AltName({ altNames: [
        new pkijs.GeneralName({ type: 2, value: 'san.example' }),
        new pkijs.GeneralName({ type: 7, value: new asn1js.OctetString({ valueHex: new Uint8Array([127, 0, 0, 1]).buffer }) }),
        new pkijs.GeneralName({ type: 7, value: new asn1js.OctetString({ valueHex: new Uint8Array([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).buffer }) }),
        new pkijs.GeneralName({ type: 1, value: 'test@example.org' }),
        new pkijs.GeneralName({ type: 6, value: 'https://san.example' }),
        new pkijs.GeneralName({ type: 4, value: root.cert.subject })
    ] });
    const fixture = await certificate('extensions.example', { extensions: [
        new pkijs.Extension({ extnID: '2.5.29.17', extnValue: altNames.toSchema().toBER(false) }),
        new pkijs.Extension({ extnID: '2.5.29.15', critical: true, extnValue: new asn1js.BitString({ valueHex: new Uint8Array([0xa0]).buffer, unusedBits: 5 }).toBER(false) }),
        new pkijs.Extension({ extnID: '2.5.29.37', extnValue: new pkijs.ExtKeyUsage({ keyPurposes: ['1.3.6.1.5.5.7.3.1'] }).toSchema().toBER(false) })
    ] });
    const details = await utils.parseCertificate(fixture.pem);
    assert.equal(details.type, 'Server Certificate');
    assert.deepEqual(details.subjectAltNames, {
        dns: ['san.example'], ip: ['127.0.0.1', '2001:db8:0:0:0:0:0:1'],
        email: ['test@example.org'], uri: ['https://san.example'], dn: ['CN=Root CA']
    });
    assert.deepEqual(details.extensions.find(e => e.name === 'keyUsage').names, ['digitalSignature', 'keyEncipherment']);
    assert.equal(details.extensions.find(e => e.name === 'keyUsage').critical, true);
    const verified = await utils.verifyCertificate(fixture.pem);
    assert.equal(verified.certDetails.sans.length, 6);
});

test('Expired and not-yet-valid certificates retain their status', async () => {
    const expired = await certificate('expired.example', { notAfter: '2025-01-02' });
    const future = await certificate('future.example', { notBefore: '2098-01-01', notAfter: '2099-01-01' });
    assert.match((await utils.verifyCertificate(expired.pem)).certDetails.status, /Expired/);
    assert.match((await utils.verifyCertificate(future.pem)).certDetails.status, /Not yet valid/);
});

test('Web Crypto digest/import/sign/verify failures produce errors, never success', async () => {
    for (const method of ['digest', 'importKey', 'sign', 'verify']) {
        const original = crypto.subtle[method];
        try {
            crypto.subtle[method] = async () => { throw new Error(`test ${method} failure`); };
            const result = await utils.verifyCertificate(rsa.pem, rsa.privateKeyPem);
            assert.equal(result.success, false, method);
            if (method === 'digest') assert.ok((await utils.parseCertificate(rsa.pem)).error);
            else assert.equal(result.keyValidation.isValid, false, method);
        } finally {
            crypto.subtle[method] = original;
        }
    }
    assert.equal((await utils.verifyCertificate(rsa.pem, rsa.privateKeyPem)).success, true);
});

test('parseCertificate reads the leaf of a full PEM chain (no atob failure)', async () => {
    const chain = [leaf.pem, intermediate.pem, root.pem].join(String.fromCharCode(10));
    const details = await utils.parseCertificate(chain);
    assert.equal(details.error, undefined);
    assert.match(details.subjectStr, /leaf\.example/);
    assert.equal(details.fingerprintSha1, (await utils.parseCertificate(leaf.pem)).fingerprintSha1);
});

const DAY = 86400000;
const entry = (alias, notAfter, store = 'private') => ({ alias, store, parsedCertificate: { raw: { notAfter: { value: notAfter } } } });

test('expiringCertificates keeps the expired and those inside the window, soonest first', () => {
    const now = new Date('2026-06-01T00:00:00Z');
    const found = utils.expiringCertificates([
        entry('far', new Date(now.getTime() + 31 * DAY + 1000)),
        entry('soon', new Date(now.getTime() + 10 * DAY + 3600000)),
        entry('edge', new Date(now.getTime() + 30 * DAY + 1000)),
        entry('gone', new Date(now.getTime() - 3 * DAY - 3600000)),
        { alias: 'unparsed', store: 'trusted', parsedCertificate: { error: 'x' } }
    ], now, 30);
    assert.deepEqual(found.map(f => [f.alias, f.days, f.expired]), [['gone', -3, true], ['soon', 10, false], ['edge', 30, false]]);
});

test('checkExpiry warns once, as an error when anything has expired, and skips unreadable stores', async () => {
    const now = new Date('2026-06-01T00:00:00Z');
    const sent = [];
    const findings = await utils.checkExpiry({
        fetchStores: [
            async () => [entry('gone', new Date(now.getTime() - DAY - 1000)), entry('soon', new Date(now.getTime() + 5 * DAY + 1000), 'trusted')],
            async () => { throw new Error('store unavailable'); }
        ],
        notify: (message, level) => sent.push({ message, level }),
        now
    });
    assert.equal(findings.length, 2);
    assert.equal(sent.length, 1);
    assert.equal(sent[0].level, 'error');
    assert.match(sent[0].message, /2 certificates have expired or will expire within 30 days/);
    assert.match(sent[0].message, /gone \(expired 1 day\(s\) ago\), soon \(expires in 5 day\(s\)\)/);
});

test('checkExpiry says nothing when every certificate is comfortably valid', async () => {
    const now = new Date('2026-06-01T00:00:00Z');
    const sent = [];
    await utils.checkExpiry({ fetchStores: [async () => [entry('ok', new Date(now.getTime() + 90 * DAY))]], notify: m => sent.push(m), now });
    assert.deepEqual(sent, []);
});

const keyPair = async (alias, fixture) => {
    const parsed = await utils.parseCertificate(fixture.pem);
    return { alias, store: 'private', type: parsed.type, validTo: parsed.validTo, parsedCertificate: parsed };
};

test('CA requests are encoded as the server\'s <map> and answers decoded from it', () => {
    const xml = utils.encodeMap({ subject: 'CN=A & B <CA>', alias: '', validityDays: undefined, replace: 'true', pathLength: null });
    assert.equal(xml, '<map><entry><string>subject</string><string>CN=A &amp; B &lt;CA&gt;</string></entry>'
        + '<entry><string>replace</string><string>true</string></entry></map>');

    const answer = utils.decodeMap('<map><entry><string>ok</string><string>true</string></entry>'
        + '<entry><string>alias</string><string>Lab &amp; Root</string></entry>'
        + '<entry><string>updatedChains</string><string/></entry>'
        + '<entry><string>certificate</string><string>-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n</string></entry></map>');
    assert.deepEqual(Object.keys(answer), ['ok', 'alias', 'updatedChains', 'certificate']);
    assert.equal(answer.alias, 'Lab & Root');
    assert.equal(answer.updatedChains, '');
    assert.match(answer.certificate, /^-----BEGIN CERTIFICATE-----\nMIIB/);
    assert.deepEqual(utils.decodeMap('not xml'), {});
});

test('error bodies read as plain sentences, with a fallback', () => {
    assert.equal(utils.errorText('The CA "x" expired.', 400), 'The CA "x" expired.');
    assert.equal(utils.errorText('<html><body><h1>Server Error</h1></body></html>', 500), 'Server Error');
    assert.equal(utils.errorText('', 502), 'The request failed (HTTP 502).');
});

test('validity and path length are whole numbers, and blank means the server default', () => {
    assert.equal(utils.daysValue(' '), undefined);
    assert.equal(utils.daysValue('825'), '825');
    assert.throws(() => utils.daysValue('0'), /at least 1/);
    assert.throws(() => utils.daysValue('2.5'), /whole number/);
    assert.equal(utils.pathLengthValue(''), undefined);
    assert.equal(utils.pathLengthValue('0'), '0');
    assert.throws(() => utils.pathLengthValue('-1'), /whole number/);
});

test('only CA key pairs are offered to sign, longest-lived first, and expired ones are flagged', async () => {
    const entries = [
        await keyPair('inter', intermediate),
        await keyPair('root', root),
        { ...(await keyPair('leaf', leaf)), alias: 'leaf' },
        { ...(await keyPair('trusted-root', root)), store: 'trusted' }
    ];
    assert.deepEqual(entries.map((e) => [e.alias, utils.isCaEntry(e)]),
        [['inter', true], ['root', true], ['leaf', false], ['trusted-root', false]]);

    const offered = utils.authorities(entries);
    assert.deepEqual(offered.map((a) => a.alias).sort(), ['inter', 'root']);
    assert.ok(offered.every((a) => a.notAfter instanceof Date && a.expired === false));

    const later = new Date(offered[0].notAfter.getTime() + 86400000);
    assert.ok(utils.authorities(entries, later).every((a) => a.expired));
});

test('renewal is due when a CA has expired or is within the warning window', async () => {
    const entry = await keyPair('root', root);
    const end = entry.parsedCertificate.raw.notAfter.value;
    const day = 86400000;

    assert.deepEqual(utils.renewalStatus(entry, new Date(end.getTime() - 400 * day)), { days: 400, expired: false, due: false });
    assert.equal(utils.renewalStatus(entry, new Date(end.getTime() - 89 * day)).due, true);
    assert.deepEqual(utils.renewalStatus(entry, new Date(end.getTime() + 3 * day + 1000)), { days: -3, expired: true, due: true });
    assert.equal(utils.renewalStatus({ validTo: 'Unknown' }), null);
});

test('an issued certificate is shown as ending with its CA when that comes first', () => {
    const now = new Date('2026-06-01T00:00:00Z');
    const caEnd = new Date('2027-01-01T00:00:00Z');

    assert.deepEqual(utils.effectiveEnd(100, caEnd, now), { end: new Date('2026-09-09T00:00:00Z'), capped: false });
    assert.deepEqual(utils.effectiveEnd(825, caEnd, now), { end: caEnd, capped: true });
});

test('a subject suggests its CN as the alias', () => {
    assert.equal(utils.commonNameOf('CN=Lab Root CA, O=Example'), 'Lab Root CA');
    assert.equal(utils.commonNameOf('O=Example, CN=host.example.org'), 'host.example.org');
    assert.equal(utils.commonNameOf('host.example.org'), 'host.example.org');
    assert.equal(utils.commonNameOf('O=Example'), '');
});
