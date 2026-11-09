/*
 * SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 NovaMap Health Limited <https://novamap.health>
 *
 * Certificate authority operations: create a CA, renew a CA, issue a leaf from a CA.
 *
 * The server takes and returns a flat map of strings. A Map parameter has to arrive
 * XStream-shaped (`<map><entry><string>k</string><string>v</string></entry></map>`) --
 * plain JSON gives a 500 -- so this talks XML rather than going through the host's JSON
 * api helper. Free of host imports (@oie/*) so the pure parts can be tested on their own.
 */

const BASE = '/api/tlsmanager/ca';

/** Entry types tlsService reports for a certificate that may sign others. */
const CA_TYPES = new Set(['Root CA', 'Intermediate']);

/** Default validity, in days, offered for each kind of certificate. Mirrors the server. */
export const DEFAULT_CA_DAYS = 3650;
export const DEFAULT_LEAF_DAYS = 825;

export const KEY_TYPES = [
    { value: 'RSA_2048', label: 'RSA 2048' },
    { value: 'RSA_3072', label: 'RSA 3072' },
    { value: 'RSA_4096', label: 'RSA 4096' },
    { value: 'EC_P256', label: 'EC P-256' },
    { value: 'EC_P384', label: 'EC P-384' }
];

const DAY_MS = 86_400_000;

const escapeXml = (v) => String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const unescapeXml = (v) => v
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'")
    .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n)))
    .replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCodePoint(parseInt(n, 16)))
    .replace(/&amp;/g, '&');

/**
 * A request as the server's `<map>` body. A key whose value is undefined, null or blank is
 * left out: the server reads an absent key as "not supplied".
 */
export function encodeMap(obj) {
    const entries = Object.keys(obj)
        .filter((k) => obj[k] !== undefined && obj[k] !== null && String(obj[k]).trim() !== '')
        .map((k) => `<entry><string>${escapeXml(k)}</string><string>${escapeXml(obj[k])}</string></entry>`)
        .join('');
    return `<map>${entries}</map>`;
}

/** The server's `<map>` answer as a plain object of strings. Anything else yields {}. */
export function decodeMap(xml) {
    const out = {};
    const text = String(xml || '');
    const entry = /<entry>([\s\S]*?)<\/entry>/g;
    const str = /<string(?:\s*\/>|>([\s\S]*?)<\/string>)/g;
    let e;
    while ((e = entry.exec(text)) !== null) {
        const parts = [];
        let s;
        str.lastIndex = 0;
        while ((s = str.exec(e[1])) !== null) parts.push(unescapeXml(s[1] || ''));
        if (parts.length >= 1) out[parts[0]] = parts[1] || '';
    }
    return out;
}

/** The reason in an error body, which is plain text from this plugin but markup from the engine. */
export function errorText(body, status) {
    const text = String(body || '').replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
    return text || `The request failed (HTTP ${status}).`;
}

async function post(path, request) {
    const res = await fetch(BASE + path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/xml', Accept: 'application/xml', 'X-Requested-With': 'oie-webadmin' },
        credentials: 'same-origin',
        body: encodeMap(request)
    });
    const body = await res.text();
    if (!res.ok) {
        const error = new Error(errorText(body, res.status));
        error.status = res.status;
        throw error;
    }
    return decodeMap(body);
}

/** Splits a validity typed as a number of days into the request value; blank means the server default. */
export function daysValue(text) {
    const t = String(text ?? '').trim();
    if (!t) return undefined;
    if (!/^\d+$/.test(t) || Number(t) < 1) throw new Error('Validity must be a whole number of days, at least 1.');
    return t;
}

/** Path length: blank means no limit. */
export function pathLengthValue(text) {
    const t = String(text ?? '').trim();
    if (!t) return undefined;
    if (!/^\d+$/.test(t)) throw new Error('Path length must be a whole number, 0 or more.');
    return t;
}

/**
 * Creates a CA key pair. Request: { subject, alias?, keyType?, validityDays?, pathLength?,
 * issuerAlias? (blank = self-signed root), replace? }.
 */
export const createCertificateAuthority = (request) => post('/create', request);

/** Renews a CA key pair. Request: { alias, validityDays?, issuerAlias? }. */
export const renewCertificateAuthority = (request) => post('/renew', request);

/**
 * Issues a leaf certificate from a CA key pair. Request: { caAlias, subject, alias?,
 * subjectAltNames? (comma or line separated), keyType?, validityDays?, replace? }.
 */
export const issueCertificate = (request) => post('/issue', request);

/** True for a key pair entry whose certificate may sign others. */
export function isCaEntry(cert) {
    return !!cert && cert.store === 'private' && CA_TYPES.has(cert.type);
}

/**
 * The key pairs that can sign, soonest-to-expire last so the longest-lived is offered first.
 * Expired ones are kept (they must be renewable) and flagged.
 */
export function authorities(certs, now = new Date()) {
    return (certs || [])
        .filter(isCaEntry)
        .map((c) => {
            const notAfter = c.parsedCertificate?.raw?.notAfter?.value;
            const end = notAfter instanceof Date ? notAfter : new Date(c.validTo);
            const valid = !Number.isNaN(end.getTime());
            return { alias: c.alias, subject: c.subject, type: c.type, notAfter: valid ? end : null, expired: valid && end < now };
        })
        .sort((a, b) => (b.notAfter?.getTime() ?? 0) - (a.notAfter?.getTime() ?? 0));
}

/**
 * Days left on a CA (negative when expired) and whether renewal is due, i.e. expired or
 * inside `warnDays`. Null when the end date is not known.
 */
export function renewalStatus(cert, now = new Date(), warnDays = 90) {
    const notAfter = cert?.parsedCertificate?.raw?.notAfter?.value;
    const end = notAfter instanceof Date ? notAfter : new Date(cert?.validTo);
    if (Number.isNaN(end.getTime())) return null;
    const ms = end.getTime() - now.getTime();
    const days = ms < 0 ? -Math.floor(-ms / DAY_MS) : Math.floor(ms / DAY_MS);
    return { days, expired: ms < 0, due: ms < 0 || days <= warnDays };
}

/** How long the issued certificate will really last, given the CA's end date. */
export function effectiveEnd(days, issuerNotAfter, now = new Date()) {
    const wanted = new Date(now.getTime() + days * DAY_MS);
    if (issuerNotAfter instanceof Date && issuerNotAfter < wanted) return { end: issuerNotAfter, capped: true };
    return { end: wanted, capped: false };
}

/** A subject suggestion: the CN of "CN=x, O=y", or the text itself when it has no attributes. */
export function commonNameOf(subject) {
    const m = /(?:^|,)\s*CN\s*=\s*((?:\\,|[^,])*)/i.exec(subject || '');
    if (m) return m[1].replace(/\\,/g, ',').trim();
    return subject && !subject.includes('=') ? subject.trim() : '';
}
