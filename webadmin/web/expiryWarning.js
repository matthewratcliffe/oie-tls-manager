/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * Certificate expiry warning shown once per console session, after sign-in.
 *
 * Kept free of host imports (@oie/*): the fetchers, the toast and the clock are passed in,
 * so the date arithmetic can be tested on its own.
 */

/** Days before expiry at which a certificate starts to be reported. */
export const WARN_DAYS = 30;

const DAY_MS = 86_400_000;
const MAX_LISTED = 5;

/**
 * Certificates that have expired or expire within `warnDays`, soonest first.
 *
 * @param {Array} certs - entries from tlsService, each with `parsedCertificate.raw.notAfter`
 * @param {Date} [now]
 * @param {number} [warnDays]
 * @returns {Array<{alias: string, store: string, notAfter: Date, days: number, expired: boolean}>}
 */
export function expiringCertificates(certs, now = new Date(), warnDays = WARN_DAYS) {
  const findings = []
  for (const cert of certs || []) {
    const notAfter = cert?.parsedCertificate?.raw?.notAfter?.value
    if (!(notAfter instanceof Date) || Number.isNaN(notAfter.getTime())) continue

    const ms = notAfter.getTime() - now.getTime()
    const expired = ms < 0
    // Whole days, rounded toward zero: 29.5 days left reads 29, 3.1 days past reads -3.
    const days = expired ? -Math.floor(-ms / DAY_MS) : Math.floor(ms / DAY_MS)
    if (expired || days <= warnDays) {
      findings.push({ alias: String(cert.alias ?? ''), store: cert.store, notAfter, days, expired })
    }
  }
  return findings.sort((a, b) => a.notAfter - b.notAfter)
}

/** The toast text and level for a non-empty list of findings. */
export function describeExpiring(findings, warnDays = WARN_DAYS) {
  const expired = findings.filter((f) => f.expired).length
  const level = expired > 0 ? 'error' : 'warn'
  const listed = findings.slice(0, MAX_LISTED).map((f) => {
    if (f.expired) return `${f.alias} (expired ${f.days === 0 ? 'today' : `${-f.days} day(s) ago`})`
    return `${f.alias} (${f.days === 0 ? 'expires today' : `expires in ${f.days} day(s)`})`
  })
  const more = findings.length > MAX_LISTED ? `, and ${findings.length - MAX_LISTED} more` : ''
  const noun = findings.length === 1 ? 'certificate has' : 'certificates have'
  return {
    level,
    message: `TLS Manager: ${findings.length} ${noun} expired or will expire within ${warnDays} days: `
      + `${listed.join(', ')}${more}. See Settings → TLS Manager.`,
  }
}

/**
 * Fetch the key pair and trusted stores and warn if anything is expired or expiring.
 *
 * A store that cannot be read is skipped rather than failing the check: this runs
 * unprompted, so it must never put an error in front of someone who asked for nothing.
 *
 * @param {{fetchStores: Array<() => Promise<Array>>, notify: (message: string, level: string) => void,
 *          now?: Date, warnDays?: number}} deps
 * @returns {Promise<Array>} the findings
 */
export async function checkExpiry({ fetchStores, notify, now = new Date(), warnDays = WARN_DAYS }) {
  const lists = await Promise.all(fetchStores.map((fetch) => Promise.resolve().then(fetch).catch(() => [])))
  const findings = expiringCertificates(lists.flat(), now, warnDays)
  if (findings.length > 0) {
    const { level, message } = describeExpiring(findings, warnDays)
    notify(message, level)
  }
  return findings
}
