/*
 * SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 NovaMap Health Limited <https://novamap.health>
 */

package org.openintegrationengine.tlsmanager.server;

import com.mirth.connect.server.controllers.ChannelController;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.openintegrationengine.tlsmanager.server.CertificateService.CaResult;
import org.openintegrationengine.tlsmanager.shared.PersistenceMode;
import org.openintegrationengine.tlsmanager.shared.models.TLSPluginConfiguration;
import org.openintegrationengine.tlsmanager.shared.models.TrustedCertificate;

import java.nio.file.Path;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

/** Creating, renewing and issuing from CAs held in the real, file-backed key pair and trust stores. */
class CertificateAuthorityServiceTest {

    @TempDir
    Path directory;

    private TLSPluginConfiguration configuration;
    private CertificateService service;

    @BeforeEach
    void setUp() {
        configuration = new TLSPluginConfiguration(PersistenceMode.FILESYSTEM,
            directory.resolve("truststore.p12").toString(), "truststorePass",
            directory.resolve("keystore.p12").toString(), "keystorePass", false);
        service = newService();
    }

    private CertificateService newService() {
        CertificateService created = new CertificateService(null, mock(ChannelController.class));
        created.init(configuration);
        return created;
    }

    private Certificate[] chain(String alias) throws Exception {
        return service.getExternalKeyStore().getCertificateChain(alias);
    }

    @Test
    void createsARootAndKeepsItAcrossARestart() throws Exception {
        CaResult created = service.createCa(null, "CN=Lab Root CA, O=Example", "EC_P256", null, null, null, false);

        assertEquals("Lab Root CA", created.alias());
        assertEquals(1, chain("Lab Root CA").length);
        assertTrue(CertificateAuthority.isSelfSigned((X509Certificate) chain("Lab Root CA")[0]));

        CertificateService restarted = newService();
        assertEquals(1, restarted.getExternalKeyStore().getCertificateChain("Lab Root CA").length);
        assertTrue(restarted.getExternalKeyStore().isKeyEntry("Lab Root CA"));
    }

    @Test
    void anExistingAliasIsNotOverwrittenUnlessAsked() {
        service.createCa("ca", "CN=First CA", "EC_P256", null, null, null, false);

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () ->
            service.createCa("ca", "CN=Second CA", "EC_P256", null, null, null, false));
        assertTrue(e.getMessage().contains("already exists"), e.getMessage());
        service.createCa("ca", "CN=Second CA", "EC_P256", null, null, null, true);
    }

    @Test
    void issuesALeafFromAnInstalledIntermediateWithTheFullChain() throws Exception {
        service.createCa("root", "CN=Lab Root CA", "EC_P256", null, null, null, false);
        service.createCa("inter", "CN=Lab Intermediate CA", "EC_P256", null, 0, "root", false);

        CaResult leaf = service.issueLeaf("inter", null, "CN=app.example.org", List.of("IP:10.0.0.5"),
            "EC_P256", 90, false);

        assertEquals("app.example.org", leaf.alias());
        Certificate[] stored = chain("app.example.org");
        assertEquals(3, stored.length, "leaf, intermediate, root");
        assertEquals(-1, ((X509Certificate) stored[0]).getBasicConstraints());
        assertEquals(3, service.getKeyStore("app.example.org").getCertificateChain("app.example.org").length,
            "TLS connectors present the intermediates");
    }

    @Test
    void issuingFromSomethingThatIsNotACaIsRefused() {
        service.createCa("root", "CN=Lab Root CA", "EC_P256", null, null, null, false);
        service.issueLeaf("root", "leaf", "CN=leaf.example.org", null, "EC_P256", null, false);

        assertThrows(IllegalArgumentException.class, () ->
            service.issueLeaf("leaf", null, "CN=other.example.org", null, null, null, false));
        assertThrows(IllegalArgumentException.class, () ->
            service.issueLeaf("missing", null, "CN=other.example.org", null, null, null, false));
    }

    @Test
    void renewingARootUpdatesChainsAndTrustedCopiesThatHeldTheOldCertificate() throws Exception {
        service.createCa("root", "CN=Lab Root CA", "EC_P256", 400, null, null, false);
        service.createCa("inter", "CN=Lab Intermediate CA", "EC_P256", 300, null, "root", false);
        service.issueLeaf("inter", "leaf", "CN=app.example.org", null, "EC_P256", 100, false);
        X509Certificate oldRoot = (X509Certificate) chain("root")[0];
        TrustedCertificate trusted = new TrustedCertificate("lab-root");
        trusted.setCertificate(CertificateService.pem(new X509Certificate[]{oldRoot}));
        TrustedCertificate unrelated = new TrustedCertificate("unrelated");
        unrelated.setCertificate(CertificateService.pem(
            new X509Certificate[]{(X509Certificate) chain("leaf")[0]}));
        service.setTrustedCertificates(List.of(trusted, unrelated));

        CaResult renewed = service.renewCa("root", 3650, null);

        X509Certificate newRoot = (X509Certificate) chain("root")[0];
        assertNotEquals(oldRoot.getSerialNumber(), newRoot.getSerialNumber());
        assertArrayEquals(oldRoot.getPublicKey().getEncoded(), newRoot.getPublicKey().getEncoded());
        assertTrue(newRoot.getNotAfter().after(oldRoot.getNotAfter()));
        assertEquals(Set.of("inter", "leaf"), new HashSet<>(renewed.updatedChains()));
        assertEquals(newRoot, chain("inter")[1], "the intermediate now presents the renewed root");
        assertEquals(newRoot, chain("leaf")[2], "and so does the leaf");
        assertEquals(List.of("lab-root"), renewed.updatedTrusted());
        assertEquals(newRoot, service.getExternalTrustStore().getCertificate("lab-root"));
        assertEquals(chain("leaf")[0], service.getExternalTrustStore().getCertificate("unrelated"),
            "an unrelated trusted certificate is left alone");

        // The leaf issued before the renewal still verifies under the renewed root.
        ((X509Certificate) chain("inter")[0]).verify(newRoot.getPublicKey());
        CertificateService restarted = newService();
        assertEquals(newRoot, restarted.getExternalKeyStore().getCertificateChain("inter")[1]);
    }

    @Test
    void renewingAnIntermediateFindsItsIssuerAmongTheKeyPairs() throws Exception {
        service.createCa("root", "CN=Lab Root CA", "EC_P256", null, null, null, false);
        service.createCa("inter", "CN=Lab Intermediate CA", "EC_P256", 100, null, "root", false);
        X509Certificate old = (X509Certificate) chain("inter")[0];

        service.renewCa("inter", 1000, null);

        X509Certificate renewed = (X509Certificate) chain("inter")[0];
        assertNotEquals(old.getSerialNumber(), renewed.getSerialNumber());
        assertEquals(2, chain("inter").length);
        renewed.verify(chain("root")[0].getPublicKey());
    }

    @Test
    void renewingAnIntermediateWhoseIssuerIsNotHeldSaysSo() throws Exception {
        service.createCa("root", "CN=Lab Root CA", "EC_P256", null, null, null, false);
        service.createCa("inter", "CN=Lab Intermediate CA", "EC_P256", null, null, "root", false);
        service.getExternalKeyStore().deleteEntry("root");

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> service.renewCa("inter", null, null));
        assertTrue(e.getMessage().contains("not held here"), e.getMessage());
    }

    @Test
    void renewingSomethingThatIsNotACaIsRefused() {
        service.createCa("root", "CN=Lab Root CA", "EC_P256", null, null, null, false);
        service.issueLeaf("root", "leaf", "CN=leaf.example.org", null, "EC_P256", null, false);

        assertThrows(IllegalArgumentException.class, () -> service.renewCa("leaf", null, "root"));
    }
}
