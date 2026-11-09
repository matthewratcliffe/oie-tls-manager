/*
 * SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 NovaMap Health Limited <https://novamap.health>
 */

package org.openintegrationengine.tlsmanager.server;

import org.junit.jupiter.api.Test;
import org.openintegrationengine.tlsmanager.server.CertificateAuthority.Issued;
import org.openintegrationengine.tlsmanager.server.CertificateAuthority.KeyType;

import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CertificateAuthorityTest {

    private static final Instant NOW = Instant.parse("2026-06-01T00:00:00Z");

    private static Issued root() throws Exception {
        return CertificateAuthority.createCa("CN=Test Root CA, O=Example", KeyType.EC_P256, 3650, null, null, null, NOW);
    }

    private static Issued intermediate(Issued root, Integer pathLength) throws Exception {
        return CertificateAuthority.createCa("CN=Test Intermediate CA, O=Example", KeyType.EC_P256, 1825, pathLength,
            root.privateKey(), root.chain(), NOW);
    }

    /** Full PKIX validation of the leaf up to the given trust anchor, at the given time. */
    private static void validate(X509Certificate[] chain, X509Certificate anchor, Instant at) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List<X509Certificate> path = List.of(chain).subList(0, chain.length - (isAnchor(chain[chain.length - 1], anchor) ? 1 : 0));
        PKIXParameters params = new PKIXParameters(Set.of(new TrustAnchor(anchor, null)));
        params.setRevocationEnabled(false);
        params.setDate(java.util.Date.from(at));
        CertPathValidator.getInstance("PKIX").validate(cf.generateCertPath(path), params);
    }

    private static boolean isAnchor(X509Certificate cert, X509Certificate anchor) {
        return cert.getSubjectX500Principal().equals(anchor.getSubjectX500Principal());
    }

    @Test
    void createsASelfSignedRootThatIsACa() throws Exception {
        Issued root = root();

        assertEquals(1, root.chain().length);
        assertTrue(CertificateAuthority.isSelfSigned(root.certificate()));
        assertTrue(CertificateAuthority.isCa(root.certificate()));
        assertTrue(CertificateAuthority.keyMatches(root.privateKey(), root.certificate().getPublicKey()));
        assertEquals(Integer.MAX_VALUE, root.certificate().getBasicConstraints(), "no path length limit");
        assertTrue(root.certificate().getKeyUsage()[5], "keyCertSign");
        assertFalse(root.cappedToIssuer());
        assertEquals(NOW.plus(Duration.ofDays(3650)), root.certificate().getNotAfter().toInstant());
    }

    @Test
    void createsAnIntermediateSignedByTheRoot() throws Exception {
        Issued root = root();
        Issued inter = intermediate(root, 0);

        assertEquals(2, inter.chain().length);
        assertTrue(CertificateAuthority.isIssuedBy(inter.certificate(), root.certificate()));
        assertFalse(CertificateAuthority.isSelfSigned(inter.certificate()));
        assertTrue(CertificateAuthority.isCa(inter.certificate()));
        assertEquals(0, inter.certificate().getBasicConstraints(), "path length 0: signs leaves only");
    }

    @Test
    void anIntermediateWithPathLengthZeroCannotSignAnotherCa() throws Exception {
        Issued inter = intermediate(root(), 0);

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () ->
            CertificateAuthority.createCa("CN=Sub CA", KeyType.EC_P256, null, null, inter.privateKey(), inter.chain(), NOW));
        assertTrue(e.getMessage().contains("path length 0"), e.getMessage());
    }

    @Test
    void anIssuersPathLengthLimitsTheChildsPathLength() throws Exception {
        Issued root = CertificateAuthority.createCa("CN=Limited Root", KeyType.EC_P256, null, 1, null, null, NOW);
        Issued inter = CertificateAuthority.createCa("CN=Child CA", KeyType.EC_P256, null, 5, root.privateKey(), root.chain(), NOW);

        assertEquals(0, inter.certificate().getBasicConstraints());
    }

    @Test
    void anIntermediateCannotShareItsIssuersSubject() throws Exception {
        Issued root = root();

        assertThrows(IllegalArgumentException.class, () ->
            CertificateAuthority.createCa("CN=Test Root CA, O=Example", KeyType.EC_P256, null, null,
                root.privateKey(), root.chain(), NOW));
    }

    @Test
    void anIntermediateIsCutShortToItsIssuersExpiry() throws Exception {
        Issued root = CertificateAuthority.createCa("CN=Short Root", KeyType.EC_P256, 100, null, null, null, NOW);
        Issued inter = CertificateAuthority.createCa("CN=Long Inter", KeyType.EC_P256, 1000, null,
            root.privateKey(), root.chain(), NOW);

        assertTrue(inter.cappedToIssuer());
        assertEquals(root.certificate().getNotAfter(), inter.certificate().getNotAfter());
    }

    @Test
    void issuesALeafThatValidatesThroughTheChain() throws Exception {
        Issued root = root();
        Issued inter = intermediate(root, 0);

        Issued leaf = CertificateAuthority.issueLeaf(inter.privateKey(), inter.chain(), "CN=host.example.org, O=Example",
            List.of(), KeyType.RSA_2048, null, NOW);

        X509Certificate cert = leaf.certificate();
        assertEquals(3, leaf.chain().length);
        assertEquals(-1, cert.getBasicConstraints(), "an end-entity certificate");
        assertEquals(List.of("1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"), cert.getExtendedKeyUsage());
        assertEquals(NOW.plus(Duration.ofDays(CertificateAuthority.DEFAULT_LEAF_DAYS)), cert.getNotAfter().toInstant());
        assertTrue(CertificateAuthority.isIssuedBy(cert, inter.certificate()));
        assertTrue(CertificateAuthority.keyMatches(leaf.privateKey(), cert.getPublicKey()));
        validate(leaf.chain(), root.certificate(), NOW.plusSeconds(60));
    }

    @Test
    void aHostNameCnBecomesADnsSanAndExplicitNamesWin() throws Exception {
        Issued ca = root();

        Collection<List<?>> implied = CertificateAuthority.issueLeaf(ca.privateKey(), ca.chain(), "host.example.org",
            null, null, null, NOW).certificate().getSubjectAlternativeNames();
        assertEquals(List.of(2, "host.example.org"), List.copyOf(implied).get(0));

        Collection<List<?>> explicit = CertificateAuthority.issueLeaf(ca.privateKey(), ca.chain(), "CN=whatever",
            List.of("DNS:a.example.org", "IP:10.1.2.3", "email:ops@example.org", "b.example.org"), null, null, NOW)
            .certificate().getSubjectAlternativeNames();
        assertEquals(4, explicit.size());
        assertTrue(explicit.contains(List.of(7, "10.1.2.3")));
        assertTrue(explicit.contains(List.of(2, "b.example.org")));
    }

    @Test
    void aLeafIsCutShortToItsCasExpiry() throws Exception {
        Issued ca = CertificateAuthority.createCa("CN=Soon CA", KeyType.EC_P256, 30, null, null, null, NOW);

        Issued leaf = CertificateAuthority.issueLeaf(ca.privateKey(), ca.chain(), "CN=leaf", null, null, 400, NOW);

        assertTrue(leaf.cappedToIssuer());
        assertEquals(ca.certificate().getNotAfter(), leaf.certificate().getNotAfter());
    }

    @Test
    void refusesToIssueFromAnExpiredCaOrOneThatIsNotACa() throws Exception {
        Issued ca = CertificateAuthority.createCa("CN=Old CA", KeyType.EC_P256, 10, null, null, null, NOW);
        Instant later = NOW.plus(Duration.ofDays(11));

        IllegalArgumentException expired = assertThrows(IllegalArgumentException.class, () ->
            CertificateAuthority.issueLeaf(ca.privateKey(), ca.chain(), "CN=x", null, null, null, later));
        assertTrue(expired.getMessage().contains("renew it"), expired.getMessage());

        Issued rootCa = root();
        Issued leaf = CertificateAuthority.issueLeaf(rootCa.privateKey(), rootCa.chain(), "CN=x", null, null, null, NOW);
        assertThrows(IllegalArgumentException.class, () ->
            CertificateAuthority.issueLeaf(leaf.privateKey(), leaf.chain(), "CN=y", null, null, null, NOW));
    }

    @Test
    void refusesAKeyThatDoesNotBelongToTheCa() throws Exception {
        Issued ca = root();
        Issued other = CertificateAuthority.createCa("CN=Other CA", KeyType.EC_P256, null, null, null, null, NOW);

        assertThrows(IllegalArgumentException.class, () ->
            CertificateAuthority.issueLeaf(other.privateKey(), ca.chain(), "CN=x", null, null, null, NOW));
    }

    @Test
    void renewingARootKeepsItsKeySubjectAndExtensionsAndExtendsItsLife() throws Exception {
        Issued root = root();
        Instant later = NOW.plus(Duration.ofDays(3000));

        Issued renewed = CertificateAuthority.renewCa(root.privateKey(), root.chain(), null, null, null, later);

        X509Certificate before = root.certificate();
        X509Certificate after = renewed.certificate();
        assertEquals(before.getSubjectX500Principal(), after.getSubjectX500Principal());
        assertArrayEquals(before.getPublicKey().getEncoded(), after.getPublicKey().getEncoded());
        assertNotEquals(before.getSerialNumber(), after.getSerialNumber());
        assertTrue(after.getNotAfter().after(before.getNotAfter()));
        assertEquals(later.plus(Duration.ofDays(3650)), after.getNotAfter().toInstant(), "keeps the old validity length");
        assertTrue(CertificateAuthority.isSelfSigned(after));
        assertTrue(CertificateAuthority.isCa(after));
        assertEquals(1, renewed.chain().length);
    }

    @Test
    void leavesIssuedBeforeARenewalKeepValidatingAgainstTheRenewedCa() throws Exception {
        Issued root = root();
        Issued leaf = CertificateAuthority.issueLeaf(root.privateKey(), root.chain(), "CN=old.example.org", null,
            null, 1000, NOW);
        Instant later = NOW.plus(Duration.ofDays(500));

        Issued renewed = CertificateAuthority.renewCa(root.privateKey(), root.chain(), null, null, null, later);

        validate(leaf.chain(), renewed.certificate(), later);
        // ... and a leaf issued afterwards by the renewed CA validates too.
        Issued fresh = CertificateAuthority.issueLeaf(renewed.privateKey(), renewed.chain(), "CN=new.example.org", null,
            null, null, later);
        validate(fresh.chain(), renewed.certificate(), later.plusSeconds(60));
    }

    @Test
    void renewsAnExpiredRoot() throws Exception {
        Issued root = CertificateAuthority.createCa("CN=Lapsed Root", KeyType.EC_P256, 10, null, null, null, NOW);
        Instant later = NOW.plus(Duration.ofDays(60));

        Issued renewed = CertificateAuthority.renewCa(root.privateKey(), root.chain(), 365, null, null, later);

        renewed.certificate().checkValidity(java.util.Date.from(later));
        assertEquals(later.plus(Duration.ofDays(365)), renewed.certificate().getNotAfter().toInstant());
    }

    @Test
    void renewingAnIntermediateNeedsAndUsesItsIssuer() throws Exception {
        Issued root = root();
        Issued inter = intermediate(root, 0);
        Instant later = NOW.plus(Duration.ofDays(1000));

        IllegalArgumentException missing = assertThrows(IllegalArgumentException.class, () ->
            CertificateAuthority.renewCa(inter.privateKey(), inter.chain(), null, null, null, later));
        assertTrue(missing.getMessage().contains("needs that CA's key pair"), missing.getMessage());

        Issued renewed = CertificateAuthority.renewCa(inter.privateKey(), inter.chain(), null,
            root.privateKey(), root.chain(), later);

        assertEquals(2, renewed.chain().length);
        assertTrue(CertificateAuthority.isIssuedBy(renewed.certificate(), root.certificate()));
        assertEquals(0, renewed.certificate().getBasicConstraints(), "path length kept");
        assertArrayEquals(inter.certificate().getPublicKey().getEncoded(), renewed.certificate().getPublicKey().getEncoded());
        validate(CertificateAuthority.issueLeaf(renewed.privateKey(), renewed.chain(), "CN=l.example.org", null, null,
            null, later).chain(), root.certificate(), later.plusSeconds(60));
    }

    @Test
    void renewingWithTheWrongIssuerOrKeyIsRefused() throws Exception {
        Issued root = root();
        Issued inter = intermediate(root, 0);
        Issued stranger = CertificateAuthority.createCa("CN=Stranger", KeyType.EC_P256, null, null, null, null, NOW);

        assertThrows(IllegalArgumentException.class, () ->
            CertificateAuthority.renewCa(inter.privateKey(), inter.chain(), null, stranger.privateKey(), stranger.chain(), NOW));
        assertThrows(IllegalArgumentException.class, () ->
            CertificateAuthority.renewCa(stranger.privateKey(), root.chain(), null, null, null, NOW));
    }

    @Test
    void renewingACertificateThatIsNotACaIsRefused() throws Exception {
        Issued root = root();
        Issued leaf = CertificateAuthority.issueLeaf(root.privateKey(), root.chain(), "CN=l.example.org", null, null, null, NOW);

        assertThrows(IllegalArgumentException.class, () ->
            CertificateAuthority.renewCa(leaf.privateKey(), leaf.chain(), null, root.privateKey(), root.chain(), NOW));
    }

    @Test
    void rsaCasSignToo() throws Exception {
        Issued root = CertificateAuthority.createCa("CN=RSA Root", KeyType.RSA_2048, null, null, null, null, NOW);

        Issued leaf = CertificateAuthority.issueLeaf(root.privateKey(), root.chain(), "CN=l", null, KeyType.EC_P384, null, NOW);

        assertEquals("SHA256withRSA", leaf.certificate().getSigAlgName());
        validate(leaf.chain(), root.certificate(), NOW.plusSeconds(60));
    }

    @Test
    void parsesKeyTypesAndSubjectsLeniently() {
        assertEquals(KeyType.RSA_3072, KeyType.parse("rsa-3072", null));
        assertEquals(KeyType.EC_P384, KeyType.parse("EC P-384", null));
        assertEquals(KeyType.EC_P256, KeyType.parse(" ", KeyType.EC_P256));
        assertThrows(IllegalArgumentException.class, () -> KeyType.parse("dsa", null));
        assertThrows(IllegalArgumentException.class, () -> CertificateAuthority.parseSubject(" "));
        assertEquals("host.example.org",
            CertificateAuthority.commonName(CertificateAuthority.parseSubject("host.example.org")));
    }
}
