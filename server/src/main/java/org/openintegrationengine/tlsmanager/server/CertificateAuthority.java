/*
 * SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 NovaMap Health Limited <https://novamap.health>
 */

package org.openintegrationengine.tlsmanager.server;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.net.InetAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Creates and renews certificate authorities, and issues leaf certificates from them.
 *
 * <p>Pure JDK and BouncyCastle, with nothing of the engine in it, so it is tested directly.
 * BouncyCastle is used only to build and sign certificates; no provider is registered.
 *
 * <ul>
 *   <li>{@link #createCa} makes a self-signed root, or an intermediate signed by a CA the
 *       caller already holds.</li>
 *   <li>{@link #renewCa} re-issues a CA certificate for the <em>same key and subject</em>
 *       with a new validity, so everything it has signed keeps validating.</li>
 *   <li>{@link #issueLeaf} makes a new key pair and a server-and-client end-entity
 *       certificate signed by a CA.</li>
 * </ul>
 *
 * <p>Nothing is ever issued past its issuer's expiry: the end date is cut to the issuer's
 * and the result says so.
 */
public final class CertificateAuthority {

    public static final int DEFAULT_CA_DAYS = 3650;
    public static final int DEFAULT_LEAF_DAYS = 825;

    /** Backdated so a peer whose clock runs a little behind still accepts the certificate. */
    private static final Duration BACKDATE = Duration.ofMinutes(5);

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final Pattern HOSTNAME = Pattern.compile(
        "(?i)^(\\*\\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$|^localhost$");
    private static final Pattern IP_LITERAL = Pattern.compile(
        "^(\\d{1,3}(\\.\\d{1,3}){3}|[0-9a-fA-F:]*:[0-9a-fA-F:.]*)$");

    /** Extensions renewCa rebuilds itself; every other extension is carried over as it was. */
    private static final Set<ASN1ObjectIdentifier> REBUILT_ON_RENEWAL = Set.of(
        Extension.basicConstraints, Extension.keyUsage,
        Extension.subjectKeyIdentifier, Extension.authorityKeyIdentifier);

    /** The key a new certificate is made for. */
    public enum KeyType {
        RSA_2048("RSA", 2048, null),
        RSA_3072("RSA", 3072, null),
        RSA_4096("RSA", 4096, null),
        EC_P256("EC", 256, "secp256r1"),
        EC_P384("EC", 384, "secp384r1");

        final String algorithm;
        final int size;
        final String curve;

        KeyType(String algorithm, int size, String curve) {
            this.algorithm = algorithm;
            this.size = size;
            this.curve = curve;
        }

        /** Parses a key type leniently; blank gives {@code fallback}. */
        public static KeyType parse(String value, KeyType fallback) {
            if (value == null || value.isBlank()) {
                return fallback;
            }
            // RSA_2048, rsa-2048, "RSA 2048", EC_P256, "EC P-256", EC256: compare letters and digits only.
            String norm = value.trim().toUpperCase(Locale.ROOT).replaceAll("[^A-Z0-9]+", "");
            for (KeyType t : values()) {
                if (t.name().replace("_", "").equals(norm) || t.name().replace("_P", "").equals(norm)) {
                    return t;
                }
            }
            throw new IllegalArgumentException("Key type \"" + value + "\" is not one of "
                + "RSA_2048, RSA_3072, RSA_4096, EC_P256 or EC_P384.");
        }
    }

    /**
     * What was made.
     *
     * @param certificate    the new certificate
     * @param privateKey     its private key (for a renewal, the key it already had)
     * @param chain          the new certificate first, then its issuer's chain
     * @param cappedToIssuer true when the end date was cut short to the issuer's
     */
    public record Issued(X509Certificate certificate, PrivateKey privateKey,
                         X509Certificate[] chain, boolean cappedToIssuer) {
    }

    private CertificateAuthority() {
    }

    // ------------------------------------------------------------------ inspection

    /**
     * True when this certificate may sign others: basicConstraints CA:true, or an X.509 v1
     * self-signed root, which predates the extension. A keyUsage that is present must also
     * allow keyCertSign.
     */
    public static boolean isCa(X509Certificate cert) {
        boolean ca = cert.getBasicConstraints() >= 0
            || (cert.getVersion() == 1 && isSelfSigned(cert));
        boolean[] usage = cert.getKeyUsage();
        return ca && (usage == null || (usage.length > 5 && usage[5]));
    }

    /** True when the certificate names itself as issuer and verifies under its own key. */
    public static boolean isSelfSigned(X509Certificate cert) {
        if (!cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
            return false;
        }
        try {
            cert.verify(cert.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /** True when {@code issuer} is the certificate that signed {@code cert}. */
    public static boolean isIssuedBy(X509Certificate cert, X509Certificate issuer) {
        if (!cert.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
            return false;
        }
        try {
            cert.verify(issuer.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /** True when the private key belongs to the public key: a signature made with one verifies with the other. */
    public static boolean keyMatches(PrivateKey privateKey, PublicKey publicKey) {
        try {
            byte[] data = new byte[32];
            RANDOM.nextBytes(data);
            Signature signer = Signature.getInstance(signatureAlgorithm(privateKey));
            signer.initSign(privateKey);
            signer.update(data);
            byte[] signature = signer.sign();
            Signature verifier = Signature.getInstance(signatureAlgorithm(privateKey));
            verifier.initVerify(publicKey);
            verifier.update(data);
            return verifier.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }

    // ------------------------------------------------------------------ operations

    /**
     * Creates a CA.
     *
     * @param subject      the CA's subject, e.g. {@code CN=Example Root CA, O=Example}
     * @param keyType      the new key; null for RSA 3072
     * @param validityDays null for {@value #DEFAULT_CA_DAYS} days
     * @param pathLength   how many CAs may sit below this one; null for no limit
     * @param issuerKey    null for a self-signed root, else the key of the CA that signs this one
     * @param issuerChain  that CA's certificate first, then its own chain; null for a root
     */
    public static Issued createCa(String subject, KeyType keyType, Integer validityDays, Integer pathLength,
                                  PrivateKey issuerKey, X509Certificate[] issuerChain, Instant now) throws Exception {
        X500Name subjectName = parseSubject(subject);
        if (pathLength != null && pathLength < 0) {
            throw new IllegalArgumentException("The path length cannot be negative.");
        }
        int days = days(validityDays, DEFAULT_CA_DAYS);
        KeyPair pair = generate(keyType == null ? KeyType.RSA_3072 : keyType);

        boolean root = issuerKey == null;
        PrivateKey signingKey = root ? pair.getPrivate() : issuerKey;
        X509Certificate issuerCert = root ? null : requireUsableCa(issuerChain, now, "sign a CA");
        X500Name issuerName = root ? subjectName : new JcaX509CertificateHolder(issuerCert).getSubject();

        Integer pathLimit = pathLength;
        Instant limit = null;
        if (!root) {
            if (subjectName.equals(issuerName)) {
                throw new IllegalArgumentException("An intermediate CA needs a different subject from its issuer, "
                    + "or certificate paths cannot be told apart.");
            }
            int issuerPath = issuerCert.getBasicConstraints();
            if (issuerPath == 0) {
                throw new IllegalArgumentException("\"" + name(issuerCert) + "\" has path length 0, so it can sign "
                    + "end certificates but not another CA.");
            }
            if (issuerPath != Integer.MAX_VALUE) {
                int allowed = issuerPath - 1;
                pathLimit = pathLimit == null ? allowed : Math.min(pathLimit, allowed);
            }
            limit = issuerCert.getNotAfter().toInstant();
        }

        Instant notBefore = backdated(now, issuerCert);
        Instant wanted = now.plus(Duration.ofDays(days));
        boolean capped = limit != null && wanted.isAfter(limit);
        Instant notAfter = capped ? limit : wanted;

        JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerName, serial(),
            Date.from(notBefore), Date.from(notAfter), subjectName, pair.getPublic());
        builder.addExtension(Extension.basicConstraints, true,
            pathLimit == null ? new BasicConstraints(true) : new BasicConstraints(pathLimit));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        builder.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(pair.getPublic()));
        builder.addExtension(Extension.authorityKeyIdentifier, false, root
            ? ext.createAuthorityKeyIdentifier(pair.getPublic())
            : ext.createAuthorityKeyIdentifier(issuerCert.getPublicKey()));

        X509Certificate cert = sign(builder, signingKey);
        cert.verify(root ? pair.getPublic() : issuerCert.getPublicKey());
        cert.checkValidity(Date.from(now));

        return new Issued(cert, pair.getPrivate(), chainOf(cert, root ? null : issuerChain), capped);
    }

    /**
     * Renews a CA: the same subject and key, a new serial number and a new validity period.
     * Keeping the key is what lets every certificate the CA has already signed carry on
     * validating, and every peer that trusts the CA keep trusting it.
     *
     * <p>A self-signed root signs its own renewal. An intermediate needs the key and chain of
     * the CA that issued it.
     *
     * @param key          the CA's current private key
     * @param current      the CA's current chain, certificate first
     * @param validityDays null to keep the length of the current validity period
     * @param issuerKey    null for a self-signed root
     * @param issuerChain  the issuing CA's certificate first, then its chain; null for a root
     */
    public static Issued renewCa(PrivateKey key, X509Certificate[] current, Integer validityDays,
                                 PrivateKey issuerKey, X509Certificate[] issuerChain, Instant now) throws Exception {
        if (current == null || current.length == 0) {
            throw new IllegalArgumentException("The CA has no certificate.");
        }
        X509Certificate old = current[0];
        if (!isCa(old)) {
            throw new IllegalArgumentException("\"" + name(old) + "\" is not a CA certificate, so there is "
                + "nothing to renew. Renew a certificate authority.");
        }
        if (!keyMatches(key, old.getPublicKey())) {
            throw new IllegalArgumentException("The private key does not belong to \"" + name(old) + "\".");
        }
        boolean root = isSelfSigned(old);
        PrivateKey signingKey = key;
        X509Certificate issuerCert = null;
        if (!root) {
            if (issuerKey == null || issuerChain == null || issuerChain.length == 0) {
                throw new IllegalArgumentException("\"" + name(old) + "\" was issued by \""
                    + old.getIssuerX500Principal().getName() + "\", so renewing it needs that CA's key pair.");
            }
            issuerCert = requireUsableCa(issuerChain, now, "renew \"" + name(old) + "\"");
            if (!old.getIssuerX500Principal().equals(issuerCert.getSubjectX500Principal())) {
                throw new IllegalArgumentException("\"" + name(old) + "\" was issued by \""
                    + old.getIssuerX500Principal().getName() + "\", not by \""
                    + issuerCert.getSubjectX500Principal().getName() + "\".");
            }
            signingKey = issuerKey;
        }

        long oldDays = Math.max(1, Duration.between(old.getNotBefore().toInstant(),
            old.getNotAfter().toInstant()).toDays());
        int days = validityDays == null ? (int) Math.min(oldDays, Integer.MAX_VALUE) : days(validityDays, 0);

        Instant notBefore = backdated(now, issuerCert);
        Instant wanted = now.plus(Duration.ofDays(days));
        Instant limit = issuerCert == null ? null : issuerCert.getNotAfter().toInstant();
        boolean capped = limit != null && wanted.isAfter(limit);
        Instant notAfter = capped ? limit : wanted;

        JcaX509CertificateHolder oldHolder = new JcaX509CertificateHolder(old);
        X500Name issuerName = root ? oldHolder.getSubject() : new JcaX509CertificateHolder(issuerCert).getSubject();
        JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerName, serial(),
            Date.from(notBefore), Date.from(notAfter), oldHolder.getSubject(), old.getPublicKey());

        int pathLength = old.getBasicConstraints();
        builder.addExtension(Extension.basicConstraints, true, pathLength == Integer.MAX_VALUE
            ? new BasicConstraints(true) : new BasicConstraints(pathLength));
        boolean[] usage = old.getKeyUsage();
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(usage == null
            ? KeyUsage.keyCertSign | KeyUsage.cRLSign : keyUsageBits(usage)));
        builder.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(old.getPublicKey()));
        builder.addExtension(Extension.authorityKeyIdentifier, false, root
            ? ext.createAuthorityKeyIdentifier(old.getPublicKey())
            : ext.createAuthorityKeyIdentifier(issuerCert.getPublicKey()));
        // Name constraints, policies and the like belong to the CA's identity: keep them.
        for (Object oid : oldHolder.getExtensionOIDs()) {
            ASN1ObjectIdentifier id = (ASN1ObjectIdentifier) oid;
            if (!REBUILT_ON_RENEWAL.contains(id)) {
                Extension carried = oldHolder.getExtension(id);
                builder.addExtension(id, carried.isCritical(), carried.getParsedValue());
            }
        }

        X509Certificate renewed = sign(builder, signingKey);
        renewed.verify(root ? old.getPublicKey() : issuerCert.getPublicKey());
        renewed.checkValidity(Date.from(now));

        return new Issued(renewed, key, chainOf(renewed, root ? null : issuerChain), capped);
    }

    /**
     * Issues a leaf: a new key pair and an end-entity certificate for it, signed by the CA.
     * The certificate is for both ends of a TLS link (serverAuth and clientAuth).
     *
     * @param caKey        the CA's private key
     * @param caChain      the CA's certificate first, then its own chain
     * @param subject      the new certificate's subject
     * @param altNames     subjectAltName entries: {@code DNS:host}, {@code IP:addr}, {@code email:x},
     *                     {@code URI:x}, or bare values typed by their shape. Left empty, a CN that
     *                     is a host name goes in as a DNS name, which TLS servers need.
     * @param keyType      null for RSA 2048
     * @param validityDays null for {@value #DEFAULT_LEAF_DAYS} days
     */
    public static Issued issueLeaf(PrivateKey caKey, X509Certificate[] caChain, String subject,
                                   List<String> altNames, KeyType keyType, Integer validityDays,
                                   Instant now) throws Exception {
        X509Certificate ca = requireUsableCa(caChain, now, "issue certificates");
        if (!keyMatches(caKey, ca.getPublicKey())) {
            throw new IllegalArgumentException("The private key does not belong to \"" + name(ca) + "\".");
        }
        X500Name subjectName = parseSubject(subject);
        GeneralNames sans = altNames(altNames, commonName(subjectName));
        KeyType type = keyType == null ? KeyType.RSA_2048 : keyType;
        int days = days(validityDays, DEFAULT_LEAF_DAYS);

        Instant notBefore = backdated(now, ca);
        Instant limit = ca.getNotAfter().toInstant();
        Instant wanted = now.plus(Duration.ofDays(days));
        boolean capped = wanted.isAfter(limit);
        Instant notAfter = capped ? limit : wanted;

        KeyPair pair = generate(type);
        JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            new JcaX509CertificateHolder(ca).getSubject(), serial(),
            Date.from(notBefore), Date.from(notAfter), subjectName, pair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage("RSA".equals(type.algorithm)
            ? KeyUsage.digitalSignature | KeyUsage.keyEncipherment : KeyUsage.digitalSignature));
        builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(
            new KeyPurposeId[]{KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth}));
        builder.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(pair.getPublic()));
        builder.addExtension(Extension.authorityKeyIdentifier, false, ext.createAuthorityKeyIdentifier(ca.getPublicKey()));
        if (sans != null) {
            builder.addExtension(Extension.subjectAlternativeName, false, sans);
        }

        X509Certificate cert = sign(builder, caKey);
        cert.verify(ca.getPublicKey());
        cert.checkValidity(Date.from(now));

        return new Issued(cert, pair.getPrivate(), chainOf(cert, caChain), capped);
    }

    // ------------------------------------------------------------------ helpers

    /** The CA certificate, checked to be able to sign and to be valid at {@code now}. */
    private static X509Certificate requireUsableCa(X509Certificate[] chain, Instant now, String purpose) {
        if (chain == null || chain.length == 0) {
            throw new IllegalArgumentException("The CA has no certificate.");
        }
        X509Certificate ca = chain[0];
        String caName = name(ca);
        if (!isCa(ca)) {
            throw new IllegalArgumentException("\"" + caName + "\" is not a CA certificate (no basicConstraints "
                + "CA:true, or keyUsage without keyCertSign), so it cannot " + purpose + ".");
        }
        if (!ca.getNotAfter().toInstant().isAfter(now)) {
            throw new IllegalArgumentException("The CA \"" + caName + "\" expired on " + ca.getNotAfter().toInstant()
                + "; renew it before using it to " + purpose + ".");
        }
        if (ca.getNotBefore().toInstant().isAfter(now)) {
            throw new IllegalArgumentException("The CA \"" + caName + "\" is not valid until "
                + ca.getNotBefore().toInstant() + ".");
        }
        return ca;
    }

    private static int days(Integer requested, int fallback) {
        if (requested == null) {
            return fallback;
        }
        if (requested < 1) {
            throw new IllegalArgumentException("The validity must be at least one day.");
        }
        return requested;
    }

    /** {@code now} less a few minutes, but never before the issuer's own start. */
    private static Instant backdated(Instant now, X509Certificate issuer) {
        Instant start = now.minus(BACKDATE);
        if (issuer != null && start.isBefore(issuer.getNotBefore().toInstant())) {
            return issuer.getNotBefore().toInstant();
        }
        return start;
    }

    private static X509Certificate sign(X509v3CertificateBuilder builder, PrivateKey key) throws Exception {
        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm(key)).build(key);
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    private static X509Certificate[] chainOf(X509Certificate cert, X509Certificate[] issuerChain) {
        int extra = issuerChain == null ? 0 : issuerChain.length;
        X509Certificate[] chain = new X509Certificate[extra + 1];
        chain[0] = cert;
        if (extra > 0) {
            System.arraycopy(issuerChain, 0, chain, 1, extra);
        }
        return chain;
    }

    private static int keyUsageBits(boolean[] usage) {
        // java.security's boolean[] is indexed by bit position from the most significant;
        // BouncyCastle's KeyUsage constants are the matching masks.
        int[] masks = {KeyUsage.digitalSignature, KeyUsage.nonRepudiation, KeyUsage.keyEncipherment,
            KeyUsage.dataEncipherment, KeyUsage.keyAgreement, KeyUsage.keyCertSign, KeyUsage.cRLSign,
            KeyUsage.encipherOnly, KeyUsage.decipherOnly};
        int bits = 0;
        for (int i = 0; i < usage.length && i < masks.length; i++) {
            if (usage[i]) {
                bits |= masks[i];
            }
        }
        return bits;
    }

    private static String name(X509Certificate cert) {
        return cert.getSubjectX500Principal().getName();
    }

    static KeyPair generate(KeyType type) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance(type.algorithm);
        if (type.curve != null) {
            gen.initialize(new ECGenParameterSpec(type.curve), RANDOM);
        } else {
            gen.initialize(type.size, RANDOM);
        }
        return gen.generateKeyPair();
    }

    /** Positive, non-zero, 159 bits of randomness: within RFC 5280's 20-octet limit. */
    static BigInteger serial() {
        byte[] bytes = new byte[20];
        RANDOM.nextBytes(bytes);
        bytes[0] &= 0x7f;
        bytes[0] |= 0x01;
        return new BigInteger(1, bytes);
    }

    /** The signing key decides the algorithm: SHA-256 with RSA, ECDSA matched to the curve. */
    static String signatureAlgorithm(PrivateKey key) {
        String alg = key.getAlgorithm();
        if ("RSA".equalsIgnoreCase(alg)) {
            return "SHA256withRSA";
        }
        if ("EC".equalsIgnoreCase(alg) || "ECDSA".equalsIgnoreCase(alg)) {
            int bits = key instanceof ECKey ec ? ec.getParams().getOrder().bitLength() : 256;
            return bits <= 256 ? "SHA256withECDSA" : bits <= 384 ? "SHA384withECDSA" : "SHA512withECDSA";
        }
        throw new IllegalArgumentException("The CA's key is " + alg + ", which this cannot sign with; "
            + "use an RSA or EC CA.");
    }

    /**
     * Parses a subject such as {@code CN=client1, O=Example, C=AU}. A bare name is taken as the CN.
     * Read through the JDK's X500Principal, which takes RFC 2253 order (most specific first, as
     * keytool and OpenSSL write it) and encodes it the conventional way round.
     */
    public static X500Name parseSubject(String subject) {
        if (subject == null || subject.isBlank()) {
            throw new IllegalArgumentException("A subject is required, e.g. CN=client1, O=Example.");
        }
        String s = subject.trim();
        if (!s.contains("=")) {
            s = "CN=" + escapeRdnValue(s);
        }
        try {
            X500Name name = X500Name.getInstance(new X500Principal(s).getEncoded());
            if (name.getRDNs().length == 0) {
                throw new IllegalArgumentException("empty");
            }
            return name;
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("The subject \"" + subject + "\" is not a distinguished name; "
                + "write it as CN=client1, O=Example, C=AU.", e);
        }
    }

    static String escapeRdnValue(String value) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            boolean edgeSpace = c == ' ' && (i == 0 || i == value.length() - 1);
            if (",+\"\\<>;=".indexOf(c) >= 0 || edgeSpace || (c == '#' && i == 0)) {
                sb.append('\\');
            }
            sb.append(c);
        }
        return sb.toString();
    }

    /** The subject's first CN, or null. */
    public static String commonName(X500Name name) {
        var cns = name.getRDNs(org.bouncycastle.asn1.x500.style.BCStyle.CN);
        if (cns.length == 0) {
            return null;
        }
        return org.bouncycastle.asn1.x500.style.IETFUtils.valueToString(cns[0].getFirst().getValue());
    }

    static GeneralNames altNames(List<String> entries, String commonName) {
        List<GeneralName> names = new ArrayList<>();
        if (entries != null) {
            for (String raw : entries) {
                if (raw != null && !raw.isBlank()) {
                    names.add(altName(raw.trim()));
                }
            }
        }
        if (names.isEmpty() && commonName != null && HOSTNAME.matcher(commonName).matches()) {
            names.add(new GeneralName(GeneralName.dNSName, commonName));
        }
        return names.isEmpty() ? null : new GeneralNames(names.toArray(new GeneralName[0]));
    }

    private static GeneralName altName(String entry) {
        int colon = entry.indexOf(':');
        String kind = colon > 0 ? entry.substring(0, colon).trim().toLowerCase(Locale.ROOT) : "";
        String value = colon > 0 ? entry.substring(colon + 1).trim() : entry;
        switch (kind) {
            case "dns":
                return new GeneralName(GeneralName.dNSName, value);
            case "ip":
                return ipName(value, entry);
            case "email":
            case "rfc822":
                return new GeneralName(GeneralName.rfc822Name, value);
            case "uri":
                return new GeneralName(GeneralName.uniformResourceIdentifier, value);
            default:
                // A bare value is typed by its shape; an IPv6 literal's colons look like a prefix.
                if (IP_LITERAL.matcher(entry).matches()) {
                    return ipName(entry, entry);
                }
                if (entry.contains("@")) {
                    return new GeneralName(GeneralName.rfc822Name, entry);
                }
                if (kind.isEmpty() || !kind.matches("[a-z0-9]+")) {
                    return new GeneralName(GeneralName.dNSName, entry);
                }
                throw new IllegalArgumentException("Subject alternative name \"" + entry
                    + "\": use DNS:, IP:, email: or URI:.");
        }
    }

    private static GeneralName ipName(String value, String entry) {
        try {
            // Numeric literals only: getByName resolves names, and must not here.
            if (!IP_LITERAL.matcher(value).matches()) {
                throw new IllegalArgumentException("not an address");
            }
            InetAddress.getByName(value);
            return new GeneralName(GeneralName.iPAddress, value);
        } catch (Exception e) {
            throw new IllegalArgumentException("Subject alternative name \"" + entry
                + "\" is not an IP address.", e);
        }
    }
}
