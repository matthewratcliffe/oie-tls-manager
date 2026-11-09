/*
 * SPDX-License-Identifier: MPL-2.0
 */

package org.openintegrationengine.tlsmanager.server;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * Finds certificates in a keystore that have expired or will within a window.
 *
 * <p>For a key pair it is the leaf (first certificate of the chain) that is checked, since
 * that is the one a peer is shown and the one that stops working on its date.
 */
final class CertificateExpiry {

    /** Days before expiry at which a certificate starts to be reported, unless configured. */
    static final int DEFAULT_WARN_DAYS = 30;

    /** One certificate that is expired or inside the warning window. */
    record Finding(String store, String alias, String subject, Instant notAfter, long daysLeft,
                   boolean expired) {

        String describe() {
            LocalDate date = LocalDate.ofInstant(notAfter, ZoneOffset.UTC);
            if (expired()) {
                return "TLS certificate '%s' (%s) EXPIRED on %s, %d day(s) ago [%s]"
                    .formatted(alias, store, date, -daysLeft, subject);
            }
            return "TLS certificate '%s' (%s) expires in %d day(s), on %s [%s]"
                .formatted(alias, store, daysLeft, date, subject);
        }
    }

    private CertificateExpiry() {
    }

    /**
     * The window from the environment, falling back to {@link #DEFAULT_WARN_DAYS} when it is
     * unset or not a positive number.
     */
    static int warnDays(String configured) {
        if (configured == null || configured.isBlank()) {
            return DEFAULT_WARN_DAYS;
        }
        try {
            int days = Integer.parseInt(configured.trim());
            return days > 0 ? days : DEFAULT_WARN_DAYS;
        } catch (NumberFormatException e) {
            return DEFAULT_WARN_DAYS;
        }
    }

    /** Expired or expiring certificates in the store, soonest first. */
    static List<Finding> scan(String storeName, KeyStore keyStore, Instant now, int warnDays) {
        List<Finding> findings = new ArrayList<>();
        try {
            for (String alias : Collections.list(keyStore.aliases())) {
                Certificate certificate = keyStore.isKeyEntry(alias)
                    ? firstOf(keyStore.getCertificateChain(alias))
                    : keyStore.getCertificate(alias);
                if (!(certificate instanceof X509Certificate x509)) {
                    continue;
                }
                Instant notAfter = x509.getNotAfter().toInstant();
                boolean expired = notAfter.isBefore(now);
                // Whole days, rounded toward zero: 29.5 days left reads 29, and a certificate
                // that expired 3.1 days ago reads -3.
                long seconds = Duration.between(now, notAfter).toSeconds();
                long daysLeft = expired ? -(-seconds / 86_400L) : seconds / 86_400L;
                if (expired || daysLeft <= warnDays) {
                    findings.add(new Finding(storeName, alias,
                        x509.getSubjectX500Principal().getName(), notAfter, daysLeft, expired));
                }
            }
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Could not read the " + storeName + " store", e);
        }
        findings.sort(Comparator.comparing(Finding::notAfter));
        return findings;
    }

    private static Certificate firstOf(Certificate[] chain) {
        return chain == null || chain.length == 0 ? null : chain[0];
    }
}
