/*
 * SPDX-License-Identifier: MPL-2.0
 */

package org.openintegrationengine.tlsmanager.server;

import com.mirth.connect.server.controllers.ChannelController;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.openintegrationengine.tlsmanager.shared.PersistenceMode;
import org.openintegrationengine.tlsmanager.shared.models.LocalCertificate;
import org.openintegrationengine.tlsmanager.shared.models.TLSPluginConfiguration;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

/**
 * Expiry findings, and a service noticing that its stores were changed by someone else (a
 * restore from a backup, or another node writing to the shared database).
 */
class CertificateExpiryTest {

    private static final String ALIAS = "server";

    @TempDir
    Path directory;

    private CertificateService service;

    private TLSPluginConfiguration configuration;

    @BeforeEach
    void setUp() throws Exception {
        configuration = new TLSPluginConfiguration(PersistenceMode.FILESYSTEM,
            directory.resolve("truststore.p12").toString(), "truststorePass",
            directory.resolve("keystore.p12").toString(), "keystorePass", false);
        service = new CertificateService(null, mock(ChannelController.class));
        service.init(configuration);
        service.setLocalCertificates(List.of(local()));
    }

    @Test
    void reportsACertificateInsideTheWindowWithItsDaysLeft() throws Exception {
        Instant now = notAfter().minus(Duration.ofDays(10)).minus(Duration.ofHours(1));

        var findings = CertificateExpiry.scan("key pair", service.getExternalKeyStore(), now, 30);

        assertEquals(1, findings.size());
        assertEquals(10, findings.get(0).daysLeft());
        assertFalse(findings.get(0).expired());
        assertTrue(findings.get(0).describe().contains("expires in 10 day(s)"));
    }

    @Test
    void reportsAnExpiredCertificateAsExpired() throws Exception {
        Instant now = notAfter().plus(Duration.ofDays(3)).plus(Duration.ofHours(1));

        var findings = CertificateExpiry.scan("key pair", service.getExternalKeyStore(), now, 30);

        assertEquals(1, findings.size());
        assertTrue(findings.get(0).expired());
        assertEquals(-3, findings.get(0).daysLeft());
        assertTrue(findings.get(0).describe().contains("EXPIRED on"), findings.get(0).describe());
        assertTrue(findings.get(0).describe().contains("3 day(s) ago"), findings.get(0).describe());
    }

    @Test
    void ignoresACertificateOutsideTheWindow() throws Exception {
        Instant now = notAfter().minus(Duration.ofDays(31)).minus(Duration.ofHours(1));

        assertTrue(CertificateExpiry.scan("key pair", service.getExternalKeyStore(), now, 30).isEmpty());
    }

    @Test
    void theWindowComesFromTheEnvironmentOrDefaultsToThirtyDays() {
        assertEquals(30, CertificateExpiry.warnDays(null));
        assertEquals(30, CertificateExpiry.warnDays(" "));
        assertEquals(30, CertificateExpiry.warnDays("soon"));
        assertEquals(30, CertificateExpiry.warnDays("0"));
        assertEquals(45, CertificateExpiry.warnDays(" 45 "));
    }

    @Test
    void aStoreChangedByAnotherWriterIsReloaded() throws Exception {
        CertificateService other = new CertificateService(null, mock(ChannelController.class));
        other.init(configuration);
        other.setLocalCertificates(List.of());

        assertEquals(1, service.getExternalKeyStore().size(), "this service has not looked yet");
        service.refreshIfChanged(true);

        assertEquals(0, service.getExternalKeyStore().size());
    }

    private LocalCertificate local() throws IOException {
        LocalCertificate local = new LocalCertificate(ALIAS);
        local.setCertificate(resource("fullchain.pem"));
        local.setKey(resource("leaf.key"));
        return local;
    }

    private Instant notAfter() throws Exception {
        return ((X509Certificate) service.getExternalKeyStore().getCertificateChain(ALIAS)[0])
            .getNotAfter().toInstant();
    }

    private static String resource(String name) throws IOException {
        try (InputStream in = CertificateExpiryTest.class.getResourceAsStream("/certificates/" + name)) {
            return new String(Objects.requireNonNull(in, name).readAllBytes(), StandardCharsets.US_ASCII);
        }
    }
}
