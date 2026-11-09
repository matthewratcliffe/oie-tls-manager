/*
 * SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2025 NovaMap Health Limited <https://novamap.health>
 */

package org.openintegrationengine.tlsmanager.server;

import com.mirth.connect.client.core.api.MirthApiException;
import com.mirth.connect.connectors.http.HttpDispatcherProperties;
import com.mirth.connect.connectors.tcp.TcpDispatcherProperties;
import com.mirth.connect.connectors.ws.WebServiceDispatcherProperties;
import com.mirth.connect.donkey.model.channel.ConnectorPluginProperties;
import com.mirth.connect.donkey.model.channel.ConnectorProperties;
import com.mirth.connect.model.Channel;
import com.mirth.connect.model.Connector;
import com.mirth.connect.server.controllers.ChannelController;
import com.mirth.connect.server.util.TemplateValueReplacer;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.openintegrationengine.tlsmanager.server.backend.DatabaseTrustStoreBackend;
import org.openintegrationengine.tlsmanager.server.backend.FileTrustStoreBackend;
import org.openintegrationengine.tlsmanager.server.backend.SystemTrustStoreBackend;
import org.openintegrationengine.tlsmanager.server.backend.TrustStoreBackend;
import org.openintegrationengine.tlsmanager.server.util.ConnectionUtils;
import org.openintegrationengine.tlsmanager.shared.PersistenceMode;
import org.openintegrationengine.tlsmanager.shared.models.ConnectionTestResult;
import org.openintegrationengine.tlsmanager.shared.models.LocalCertificate;
import org.openintegrationengine.tlsmanager.shared.models.TLSPluginConfiguration;
import org.openintegrationengine.tlsmanager.shared.models.TrustedCertificate;
import org.openintegrationengine.tlsmanager.shared.properties.TLSConnectorProperties;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.net.ConnectException;
import java.net.MalformedURLException;
import java.net.NoRouteToHostException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.openintegrationengine.tlsmanager.shared.TLSPluginConstants.PKCS12;

@Slf4j
public final class CertificateService {

    private static final Pattern PEM_CERTIFICATE =
        Pattern.compile("-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", Pattern.DOTALL);

    @Getter
    private KeyStore systemTrustStore;

    @Getter
    private KeyStore externalTrustStore;

    @Getter
    private KeyStore externalKeyStore;

    /** Minimum gap between looks at the backing store for changes made elsewhere. */
    private static final long REFRESH_INTERVAL_MILLIS = 15_000;

    private byte[] loadedTrustStoreBytes;
    private byte[] loadedKeyStoreBytes;
    private long lastRefreshCheck;

    private TrustStoreBackend systemTrustStoreBackend;
    private TrustStoreBackend extraTrustStoreBackend;
    private TrustStoreBackend extraKeyStoreBackend;

    private final ChannelController channelController;
    private final TemplateValueReplacer templateValueReplacer;

    public CertificateService(ChannelController channelController) {
        this(new TemplateValueReplacer(), channelController);
    }

    public CertificateService(TemplateValueReplacer templateValueReplacer, ChannelController channelController) {
        this.templateValueReplacer = templateValueReplacer;
        this.channelController = channelController;
    }

    void init(TLSPluginConfiguration pluginConfiguration) {
        systemTrustStoreBackend = new SystemTrustStoreBackend();

        if (pluginConfiguration.persistenceMode() == PersistenceMode.DATABASE) {
            extraTrustStoreBackend = new DatabaseTrustStoreBackend("extraTrustStore");
            extraKeyStoreBackend = new DatabaseTrustStoreBackend("extraKeyStore");
        } else if (pluginConfiguration.persistenceMode() == PersistenceMode.FILESYSTEM) {
            extraTrustStoreBackend = new FileTrustStoreBackend(
                pluginConfiguration.truststorePath(),
                pluginConfiguration.truststorePassword()
            );

            extraKeyStoreBackend = new FileTrustStoreBackend(
                pluginConfiguration.keystorePath(),
                pluginConfiguration.keystorePassword()
            );
        } else {
            // Should not get here
            throw new RuntimeException("Unsupported persistence mode: " + pluginConfiguration.persistenceMode());
        }

        extraTrustStoreBackend.init();
        extraKeyStoreBackend.init();

        byte[] cacertsBytes = systemTrustStoreBackend.load();
        byte[] extraTrustStoreBytes = extraTrustStoreBackend.load();
        byte[] extraKeyStoreBytes = extraKeyStoreBackend.load();

        try {
            systemTrustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            externalTrustStore = KeyStore.getInstance(PKCS12);
            externalKeyStore = KeyStore.getInstance(PKCS12);
        } catch (KeyStoreException e) {
            log.error("Error initializing CertificateService", e);
            throw new RuntimeException(e);
        }

        loadKeyStore(systemTrustStore, cacertsBytes, systemTrustStoreBackend.loadPassword());
        loadKeyStore(externalTrustStore, extraTrustStoreBytes, extraTrustStoreBackend.loadPassword());
        loadKeyStore(externalKeyStore, extraKeyStoreBytes, extraKeyStoreBackend.loadPassword());
        loadedTrustStoreBytes = extraTrustStoreBytes;
        loadedKeyStoreBytes = extraKeyStoreBytes;
        lastRefreshCheck = System.currentTimeMillis();
    }

    /**
     * Reloads the key pair and trust stores if the backing store has changed since they were
     * read, at most once every {@value #REFRESH_INTERVAL_MILLIS} ms.
     *
     * <p>The stores are read once at start-up, so a change made any other way, such as a
     * restore from a backup or another node in a cluster writing to the shared database,
     * would otherwise not be seen until a restart.
     */
    void refreshIfChanged() {
        refreshIfChanged(false);
    }

    synchronized void refreshIfChanged(boolean force) {
        if (extraKeyStoreBackend == null || extraTrustStoreBackend == null) {
            return;
        }
        long now = System.currentTimeMillis();
        if (!force && now - lastRefreshCheck < REFRESH_INTERVAL_MILLIS) {
            return;
        }
        lastRefreshCheck = now;
        try {
            byte[] keyBytes = extraKeyStoreBackend.load();
            if (!java.util.Arrays.equals(keyBytes, loadedKeyStoreBytes)) {
                loadKeyStore(externalKeyStore, keyBytes, extraKeyStoreBackend.loadPassword());
                loadedKeyStoreBytes = keyBytes;
                log.info("Key pair store changed outside this node; reloaded {} entries",
                    getLocalCertificateAliases().size());
            }
            byte[] trustBytes = extraTrustStoreBackend.load();
            if (!java.util.Arrays.equals(trustBytes, loadedTrustStoreBytes)) {
                loadKeyStore(externalTrustStore, trustBytes, extraTrustStoreBackend.loadPassword());
                loadedTrustStoreBytes = trustBytes;
                log.info("Trusted certificate store changed outside this node; reloaded {} entries",
                    getTrustedCertificateAliases().size());
            }
        } catch (RuntimeException e) {
            // A failed look must not break the caller; the loaded stores stay as they were.
            log.warn("Could not check the certificate stores for changes: {}", e.toString());
        }
    }

    /** Expired or expiring certificates in the key pair and trusted stores, soonest first. */
    List<CertificateExpiry.Finding> getExpiringCertificates(int warnDays) {
        refreshIfChanged();
        java.time.Instant now = java.time.Instant.now();
        List<CertificateExpiry.Finding> findings = new ArrayList<>();
        findings.addAll(CertificateExpiry.scan("key pair", externalKeyStore, now, warnDays));
        findings.addAll(CertificateExpiry.scan("trusted", externalTrustStore, now, warnDays));
        findings.sort(java.util.Comparator.comparing(CertificateExpiry.Finding::notAfter));
        return findings;
    }

    KeyStore getKeyStore(String alias) {
        refreshIfChanged();
        try {
            var keystore = KeyStore.getInstance(PKCS12);
            keystore.load(null, new char[0]);

            if (alias == null) {
                throw new IllegalArgumentException("Alias cannot be null");
            }

            if (externalKeyStore.isKeyEntry(alias)) {
                var certChain = externalKeyStore.getCertificateChain(alias);
                var privateKey = externalKeyStore.getKey(alias, extraKeyStoreBackend.loadPassword());

                keystore.setKeyEntry(
                    alias,
                    privateKey,
                    new char[0],
                    certChain
                );
            } else {
                log.warn("Alias ({}) is not a key entry", alias);
            }

            return keystore;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException e) {
            log.error("Error creating a keystore", e);
            throw new RuntimeException(e);
        }
    }

    private void loadKeyStore(KeyStore keystore, byte[] bytes, char[] password) {
        try (var bais = new ByteArrayInputStream(bytes)) {
            keystore.load(bais, password);
        } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
            log.error("Error loading keystore into memory", e);
            throw new RuntimeException(e);
        }
    }

    public void storeExtraTrustStore(byte[] keystoreBytes, char[] password) {
        try (var bais = new ByteArrayInputStream(keystoreBytes)) {
            externalTrustStore.load(bais, password);
            extraTrustStoreBackend.persist(keystoreBytes);
            loadedTrustStoreBytes = keystoreBytes;
        } catch (CertificateException | IOException | NoSuchAlgorithmException e) {
            log.error("Error overwriting truststore", e);
            throw new RuntimeException(e);
        }
    }

    public void storeExtraKeyStore(byte[] keystoreBytes, char[] password) {
        try (var bais = new ByteArrayInputStream(keystoreBytes)) {
            externalKeyStore.load(bais, password);
            extraKeyStoreBackend.persist(keystoreBytes);
            loadedKeyStoreBytes = keystoreBytes;
        } catch (CertificateException | IOException | NoSuchAlgorithmException e) {
            log.error("Error overwriting keystore", e);
            throw new RuntimeException(e);
        }
    }

    public Set<String> getTrustedCertificateAliases() {
        refreshIfChanged();
        try {
            return new HashSet<>(Collections.list(externalTrustStore.aliases()));
        } catch (KeyStoreException e) {
            log.error("Error reading alias list from loaded truststore", e);
            throw new RuntimeException(e);
        }
    }

    public Set<String> getLocalCertificateAliases() {
        refreshIfChanged();
        try {
            return new HashSet<>(Collections.list(externalKeyStore.aliases()));
        } catch (KeyStoreException e) {
            log.error("Error reading alias list from loaded keystore", e);
            throw new RuntimeException(e);
        }
    }

    public List<TrustedCertificate> getEncodedSystemCertificates() {
        return getEncodedCertificates(systemTrustStore, systemTrustStoreBackend.loadPassword());
    }

    public List<TrustedCertificate> getEncodedLocalCertificates() {
        refreshIfChanged();
        return getEncodedCertificates(externalKeyStore, extraKeyStoreBackend.loadPassword());
    }

    public List<TrustedCertificate> getEncodedTrustedCertificates() {
        refreshIfChanged();
        return getEncodedCertificates(externalTrustStore, extraTrustStoreBackend.loadPassword());
    }

    private List<TrustedCertificate> getEncodedCertificates(KeyStore keyStore, char[] password) {
        List<TrustedCertificate> certificates = new ArrayList<>();

        try {
            Enumeration<String> aliases = keyStore.aliases();

            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();

                if (keyStore.isKeyEntry(alias)) {
                    LocalCertificate certificate = new LocalCertificate(alias);
                    String encodedCertificate = encodeCertificateChain(keyStore.getCertificateChain(alias));
                    String encodedKey = encodeKey(keyStore.getKey(alias, password));
                    certificate.setCertificate(encodedCertificate);
                    certificate.setKey(encodedKey);
                    certificate.setChannelsInUse(getChannelsInUse(alias));
                    certificates.add(certificate);
                } else if (keyStore.isCertificateEntry(alias)) {
                    TrustedCertificate certificate = new TrustedCertificate(alias);
                    String encodedCertificate = encodeCertificateChain(keyStore.getCertificate(alias));
                    certificate.setCertificate(encodedCertificate);
                    certificate.setChannelsInUse(getChannelsInUse(alias));
                    certificates.add(certificate);
                }
            }
            return certificates;
        } catch (KeyStoreException | CertificateEncodingException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        }
    }

    private Set<String> getChannelsInUse(String alias) {
        final Set<String> channelsInUse = new HashSet<>();
        final List<Channel> channels = channelController.getChannels(null);

        BiConsumer<TLSConnectorProperties, String> addIfInUse = (TLSConnectorProperties properties, String channelName) -> {
            if (properties != null) {
                if (alias.equals(properties.getServerCertificateAlias())) {
                    channelsInUse.add(channelName);
                } else if (alias.equals(properties.getClientCertificateAlias())) {
                    channelsInUse.add(channelName);
                } else if (properties.getTrustedServerCertificates() != null
                    && !properties.getTrustedServerCertificates().isEmpty()
                    && properties.getTrustedServerCertificates().contains(alias)) {
                    channelsInUse.add(channelName);
                }
            }
        };

        for (Channel channel : channels) {
            ConnectorProperties connectorProperties = channel.getSourceConnector().getProperties();

            if (connectorProperties != null) {
                Set<ConnectorPluginProperties> sourceProperties = connectorProperties.getPluginProperties();

                if (sourceProperties != null && !sourceProperties.isEmpty()) {
                    TLSConnectorProperties tlsSourceProperties = (TLSConnectorProperties) sourceProperties
                        .stream()
                        .filter(props -> props instanceof TLSConnectorProperties)
                        .findFirst()
                        .orElse(null);

                    addIfInUse.accept(tlsSourceProperties, channel.getName());
                }
            }
            for (Connector destinationConnector : channel.getDestinationConnectors()) {
                ConnectorProperties destinationConnectorProperties = destinationConnector.getProperties();

                if (connectorProperties != null) {
                    Set<ConnectorPluginProperties> destinationProperties = destinationConnectorProperties.getPluginProperties();

                    TLSConnectorProperties tlsDestinationProperties = (TLSConnectorProperties) destinationProperties
                        .stream()
                        .filter(props -> props instanceof TLSConnectorProperties)
                        .findFirst()
                        .orElse(null);

                    addIfInUse.accept(tlsDestinationProperties, channel.getName());
                }
            }
        }
        return channelsInUse;
    }

    static String encodeCertificateChain(Certificate... chain) throws CertificateEncodingException {
        StringBuilder pem = new StringBuilder();

        for (Certificate cert : chain) {
            String base64Cert = Base64.getMimeEncoder(64, "\n".getBytes())
                .encodeToString(cert.getEncoded());
            pem.append("-----BEGIN CERTIFICATE-----\n")
                .append(base64Cert)
                .append("\n-----END CERTIFICATE-----\n\n");
        }
        return pem.toString();
    }

    private String encodeKey(Key key) throws CertificateEncodingException {
        StringBuilder pem = new StringBuilder();

        if (key instanceof PrivateKey) {
            String base64Key = Base64.getMimeEncoder(64, "\n".getBytes())
                .encodeToString(key.getEncoded());
            pem.append("-----BEGIN PRIVATE KEY-----\n")
                .append(base64Key)
                .append("\n-----END PRIVATE KEY-----\n\n");
        }
        return pem.toString();
    }

    public void setTrustedCertificates(List<TrustedCertificate> trustedCertificates) {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            char[] password = extraTrustStoreBackend.loadPassword();
            ks.load(null, password);

            for (TrustedCertificate certificate : trustedCertificates) {
                X509Certificate cert = decodeCertificate(certificate.getCertificate());
                ks.setCertificateEntry(certificate.getAlias(), cert);
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ks.store(out, password);
            byte[] keystoreBytes = out.toByteArray();
            storeExtraTrustStore(keystoreBytes, password);
        } catch (CertificateException | IOException | KeyStoreException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Decodes a trusted certificate entry, which holds exactly one certificate.
     */
    private static X509Certificate decodeCertificate(String certificate) throws CertificateException {
        X509Certificate[] chain = decodeCertificateChain(certificate);
        if (chain.length != 1) {
            throw new CertificateException("A trusted certificate entry must contain exactly one certificate but "
                + chain.length + " were supplied; import each certificate under its own alias.");
        }
        return chain[0];
    }

    /**
     * Decodes every certificate in a PEM string, preserving order, so a full chain
     * (leaf first, then intermediates) round-trips with {@link #encodeCertificateChain}.
     * Each PEM block is decoded separately: stripping all markers and decoding the
     * concatenation fails on the first block's Base64 padding. Bare Base64 without PEM
     * markers is still accepted as a single certificate.
     */
    static X509Certificate[] decodeCertificateChain(String certificate) throws CertificateException {
        if (certificate == null || certificate.isBlank()) {
            throw new CertificateException("No certificate supplied");
        }

        List<String> blocks = new ArrayList<>();
        Matcher matcher = PEM_CERTIFICATE.matcher(certificate);
        while (matcher.find()) {
            blocks.add(matcher.group(1));
        }
        if (blocks.isEmpty()) {
            blocks.add(certificate);
        }

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate[] chain = new X509Certificate[blocks.size()];
        for (int i = 0; i < blocks.size(); i++) {
            byte[] certBytes;
            try {
                certBytes = Base64.getDecoder().decode(blocks.get(i).replaceAll("\\s+", ""));
            } catch (IllegalArgumentException e) {
                throw new CertificateException("Certificate " + (i + 1) + " is not valid Base64", e);
            }
            chain[i] = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
        }
        return chain;
    }

    private PrivateKey decodeKey(String key) throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        String keyContent = key
            .replaceAll("-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", "")
            .replaceAll("-----END [A-Z0-9 ]*PRIVATE KEY-----", "")
            .replaceAll("\\s+", "");
        byte[] keyBytes = Base64.getDecoder().decode(keyContent);
        PrivateKey privateKey;
        try {
            privateKey = KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
        } catch (InvalidKeySpecException e) {
            if (e.getCause() instanceof InvalidKeyException) {
                // Attempt to convert to PKCS#8
                return attemptPkcs8Conversion(key);
            }
            throw e;
        }
        return privateKey;
    }

    private PrivateKey attemptPkcs8Conversion(String key) throws InvalidKeySpecException, IOException {
        try (PEMParser parser = new PEMParser(new StringReader(key))) {
            Object obj = parser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();

            if (obj instanceof PEMKeyPair) {
                return converter.getKeyPair((PEMKeyPair) obj).getPrivate();
            } else if (obj instanceof PrivateKeyInfo) {
                return converter.getPrivateKey((PrivateKeyInfo) obj);
            } else {
                throw new IllegalArgumentException("Unsupported PEM object: " + obj.getClass());
            }
        }
    }

    public void setLocalCertificates(List<LocalCertificate> localCertificates) {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            char[] password = extraKeyStoreBackend.loadPassword();
            ks.load(null, password);

            for (LocalCertificate certificate : localCertificates) {
                X509Certificate[] chain = decodeCertificateChain(certificate.getCertificate());
                PrivateKey privateKey = decodeKey(certificate.getKey());
                ks.setKeyEntry(certificate.getAlias(), privateKey, password, chain);
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ks.store(out, password);
            byte[] keystoreBytes = out.toByteArray();
            storeExtraKeyStore(keystoreBytes, password);
        } catch (CertificateException | InvalidKeySpecException | IOException | KeyStoreException |
                 NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * What a CA operation produced and saved.
     *
     * @param alias            the key pair entry written
     * @param chain            its certificate chain, certificate first
     * @param key              its private key
     * @param cappedToIssuer   true when the end date was cut short to the issuing CA's
     * @param updatedChains    other key pairs whose chain held the replaced CA certificate and now holds the new one
     * @param updatedTrusted   trusted certificates that were the replaced CA certificate and now are the new one
     */
    public record CaResult(String alias, X509Certificate[] chain, PrivateKey key, boolean cappedToIssuer,
                           List<String> updatedChains, List<String> updatedTrusted) {
    }

    /**
     * Creates a CA key pair and saves it under {@code alias}: a self-signed root, or, with
     * {@code issuerAlias}, an intermediate signed by a CA key pair already held.
     */
    public synchronized CaResult createCa(String alias, String subject, String keyType, Integer validityDays,
                                          Integer pathLength, String issuerAlias, boolean replace) {
        try {
            refreshIfChanged();
            String name = aliasOrCommonName(alias, subject);
            requireFreeAlias(name, replace);
            KeyEntry issuer = isBlank(issuerAlias) ? null : keyEntry(issuerAlias);
            CertificateAuthority.Issued issued = CertificateAuthority.createCa(subject,
                CertificateAuthority.KeyType.parse(keyType, null), validityDays, pathLength,
                issuer == null ? null : issuer.key(), issuer == null ? null : issuer.chain(),
                java.time.Instant.now());
            putKeyEntry(name, issued.privateKey(), issued.chain());
            log.info("Created CA \"{}\" ({})", name, issued.certificate().getSubjectX500Principal().getName());
            return new CaResult(name, issued.chain(), issued.privateKey(), issued.cappedToIssuer(), List.of(), List.of());
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Could not create the CA: " + e.getMessage(), e);
        }
    }

    /**
     * Renews the CA key pair {@code alias}: the same key and subject, a new validity period. A
     * self-signed root signs its own renewal; an intermediate is signed by the CA that issued it,
     * found among the key pairs held unless {@code issuerAlias} names it.
     *
     * <p>Every other key pair whose chain held the old CA certificate is given the new one, and so
     * is every trusted certificate that was the old CA certificate, so connectors present and
     * trust the current certificate.
     */
    public synchronized CaResult renewCa(String alias, Integer validityDays, String issuerAlias) {
        try {
            refreshIfChanged();
            KeyEntry current = keyEntry(alias);
            X509Certificate old = current.chain()[0];
            KeyEntry issuer = null;
            if (CertificateAuthority.isCa(old) && !CertificateAuthority.isSelfSigned(old)) {
                issuer = isBlank(issuerAlias) ? findIssuer(alias, old) : keyEntry(issuerAlias);
            }
            CertificateAuthority.Issued issued = CertificateAuthority.renewCa(current.key(), current.chain(),
                validityDays, issuer == null ? null : issuer.key(), issuer == null ? null : issuer.chain(),
                java.time.Instant.now());

            putKeyEntry(alias, issued.privateKey(), issued.chain());
            List<String> chains = replaceInOtherChains(alias, old, issued.certificate());
            List<String> trusted = replaceTrusted(old, issued.certificate());
            log.info("Renewed CA \"{}\" until {}; updated {} chain(s) and {} trusted certificate(s)", alias,
                issued.certificate().getNotAfter().toInstant(), chains.size(), trusted.size());
            return new CaResult(alias, issued.chain(), issued.privateKey(), issued.cappedToIssuer(), chains, trusted);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Could not renew the CA: " + e.getMessage(), e);
        }
    }

    /**
     * Issues a leaf certificate, with a new key pair, from the CA key pair {@code caAlias} (a root or
     * an intermediate) and saves it under {@code alias}, default the subject's CN. Its chain is the
     * CA's chain with the new certificate in front.
     */
    public synchronized CaResult issueLeaf(String caAlias, String alias, String subject, List<String> altNames,
                                           String keyType, Integer validityDays, boolean replace) {
        try {
            refreshIfChanged();
            KeyEntry ca = keyEntry(caAlias);
            String name = aliasOrCommonName(alias, subject);
            requireFreeAlias(name, replace);
            CertificateAuthority.Issued issued = CertificateAuthority.issueLeaf(ca.key(), ca.chain(), subject,
                altNames, CertificateAuthority.KeyType.parse(keyType, null), validityDays, java.time.Instant.now());
            putKeyEntry(name, issued.privateKey(), issued.chain());
            log.info("Issued \"{}\" ({}) from CA \"{}\"", name,
                issued.certificate().getSubjectX500Principal().getName(), caAlias);
            return new CaResult(name, issued.chain(), issued.privateKey(), issued.cappedToIssuer(), List.of(), List.of());
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Could not issue the certificate: " + e.getMessage(), e);
        }
    }

    private record KeyEntry(PrivateKey key, X509Certificate[] chain) {
    }

    private KeyEntry keyEntry(String alias) throws GeneralSecurityException {
        if (isBlank(alias)) {
            throw new IllegalArgumentException("A key pair alias is required.");
        }
        if (!externalKeyStore.isKeyEntry(alias)) {
            throw new IllegalArgumentException("There is no key pair named \"" + alias + "\".");
        }
        Key key = externalKeyStore.getKey(alias, extraKeyStoreBackend.loadPassword());
        Certificate[] chain = externalKeyStore.getCertificateChain(alias);
        if (!(key instanceof PrivateKey privateKey) || chain == null || chain.length == 0) {
            throw new IllegalArgumentException("\"" + alias + "\" has no private key and certificate.");
        }
        X509Certificate[] x509 = new X509Certificate[chain.length];
        for (int i = 0; i < chain.length; i++) {
            x509[i] = (X509Certificate) chain[i];
        }
        return new KeyEntry(privateKey, x509);
    }

    /** The key pair, other than {@code self}, whose certificate issued {@code cert}. */
    private KeyEntry findIssuer(String self, X509Certificate cert) throws GeneralSecurityException {
        for (String candidate : Collections.list(externalKeyStore.aliases())) {
            if (candidate.equalsIgnoreCase(self) || !externalKeyStore.isKeyEntry(candidate)) {
                continue;
            }
            KeyEntry entry = keyEntry(candidate);
            if (CertificateAuthority.isIssuedBy(cert, entry.chain()[0])) {
                return entry;
            }
        }
        throw new IllegalArgumentException("\"" + self + "\" was issued by \""
            + cert.getIssuerX500Principal().getName() + "\", whose key pair is not held here; "
            + "renewing it needs that CA's key pair.");
    }

    private void requireFreeAlias(String alias, boolean replace) throws KeyStoreException {
        if (externalKeyStore.containsAlias(alias) && !replace) {
            throw new IllegalArgumentException("A key pair named \"" + alias + "\" already exists; choose another "
                + "alias or confirm replacing it.");
        }
    }

    /** The alias given, else the subject's CN, made safe for a keystore entry. */
    private static String aliasOrCommonName(String alias, String subject) {
        if (!isBlank(alias)) {
            return alias.trim();
        }
        String cn = CertificateAuthority.commonName(CertificateAuthority.parseSubject(subject));
        if (isBlank(cn)) {
            throw new IllegalArgumentException("Give an alias, or a subject with a CN to name it after.");
        }
        return cn.trim();
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    /** Writes a key pair entry to the key store and its backing store; memory is put back if that fails. */
    private void putKeyEntry(String alias, PrivateKey key, X509Certificate[] chain) throws GeneralSecurityException, IOException {
        char[] password = extraKeyStoreBackend.loadPassword();
        try {
            externalKeyStore.setKeyEntry(alias, key, password, chain);
            persistKeyStore(password);
        } catch (GeneralSecurityException | IOException | RuntimeException e) {
            loadKeyStore(externalKeyStore, loadedKeyStoreBytes, password);
            throw e;
        }
    }

    private void persistKeyStore(char[] password) throws GeneralSecurityException, IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        externalKeyStore.store(out, password);
        byte[] bytes = out.toByteArray();
        extraKeyStoreBackend.persist(bytes);
        loadedKeyStoreBytes = bytes;
    }

    /** Swaps {@code old} for {@code renewed} in the chain of every key pair but {@code except}. */
    private List<String> replaceInOtherChains(String except, X509Certificate old, X509Certificate renewed)
        throws GeneralSecurityException, IOException {
        char[] password = extraKeyStoreBackend.loadPassword();
        List<String> changed = new ArrayList<>();
        for (String candidate : Collections.list(externalKeyStore.aliases())) {
            if (candidate.equalsIgnoreCase(except) || !externalKeyStore.isKeyEntry(candidate)) {
                continue;
            }
            KeyEntry entry = keyEntry(candidate);
            boolean touched = false;
            for (int i = 1; i < entry.chain().length; i++) {
                if (entry.chain()[i].equals(old)) {
                    entry.chain()[i] = renewed;
                    touched = true;
                }
            }
            if (touched) {
                externalKeyStore.setKeyEntry(candidate, entry.key(), password, entry.chain());
                changed.add(candidate);
            }
        }
        if (!changed.isEmpty()) {
            persistKeyStore(password);
        }
        return changed;
    }

    /** Replaces trusted certificates that are {@code old} (same subject and key) with {@code renewed}. */
    private List<String> replaceTrusted(X509Certificate old, X509Certificate renewed)
        throws GeneralSecurityException, IOException {
        List<String> changed = new ArrayList<>();
        for (String candidate : Collections.list(externalTrustStore.aliases())) {
            if (!externalTrustStore.isCertificateEntry(candidate)) {
                continue;
            }
            Certificate trusted = externalTrustStore.getCertificate(candidate);
            if (trusted instanceof X509Certificate x509
                && x509.getSubjectX500Principal().equals(old.getSubjectX500Principal())
                && java.util.Arrays.equals(x509.getPublicKey().getEncoded(), old.getPublicKey().getEncoded())) {
                externalTrustStore.setCertificateEntry(candidate, renewed);
                changed.add(candidate);
            }
        }
        if (!changed.isEmpty()) {
            char[] password = extraTrustStoreBackend.loadPassword();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            externalTrustStore.store(out, password);
            byte[] bytes = out.toByteArray();
            extraTrustStoreBackend.persist(bytes);
            loadedTrustStoreBytes = bytes;
        }
        return changed;
    }

    /** PEM for a chain, as the rest of the API returns it. */
    public static String pem(X509Certificate[] chain) throws CertificateEncodingException {
        return encodeCertificateChain(chain);
    }

    public List<TrustedCertificate> retrieveRemoteCertificates(String urlString) {
        if (urlString == null || urlString.isBlank()) {
            throw remoteCertificateError(Response.Status.BAD_REQUEST, "URL is required.");
        }
        if (!urlString.toLowerCase(Locale.ROOT).startsWith("https://")) {
            throw remoteCertificateError(
                Response.Status.BAD_REQUEST,
                "URL must use HTTPS. Plain HTTP endpoints cannot provide TLS certificates."
            );
        }

        List<TrustedCertificate> result = new ArrayList<>();
        HttpsURLConnection conn = null;

        try {
            SSLContext sc = SSLContext.getInstance("TLS");

            TrustManager[] trustAll = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }

                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                    }

                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                    }
                }
            };

            sc.init(null, trustAll, new SecureRandom());
            URL url = new URL(urlString);
            conn = (HttpsURLConnection) url.openConnection();
            conn.setSSLSocketFactory(sc.getSocketFactory());
            conn.setHostnameVerifier((h, s) -> true);
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            conn.connect();
            Certificate[] certs = conn.getServerCertificates();

            for (Certificate cert : certs) {
                if (cert instanceof X509Certificate x509) {
                    TrustedCertificate certificate = new TrustedCertificate(null);
                    certificate.setCertificate(encodeCertificateChain(x509));
                    result.add(certificate);
                }
            }
        } catch (ClassCastException e) {
            throw remoteCertificateError(
                Response.Status.BAD_REQUEST,
                "URL must use HTTPS. Plain HTTP endpoints cannot provide TLS certificates."
            );
        } catch (IOException | CertificateEncodingException | KeyManagementException | NoSuchAlgorithmException e) {
            throw remoteCertificateError(
                statusForRemoteCertificateFailure(e),
                describeRemoteCertificateFailure(urlString, e)
            );
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
        return result;
    }

    private static WebApplicationException remoteCertificateError(Response.Status status, String message) {
        return new WebApplicationException(
            Response.status(status)
                .entity(message)
                .type(MediaType.TEXT_PLAIN)
                .build()
        );
    }

    private static Response.Status statusForRemoteCertificateFailure(Throwable error) {
        if (hasCause(error, SocketTimeoutException.class)) {
            return Response.Status.GATEWAY_TIMEOUT;
        }
        if (hasCause(error, MalformedURLException.class)) {
            return Response.Status.BAD_REQUEST;
        }
        return Response.Status.BAD_GATEWAY;
    }

    private static String describeRemoteCertificateFailure(String urlString, Throwable error) {
        String host = extractHost(urlString);

        UnknownHostException unknownHost = findCause(error, UnknownHostException.class);
        if (unknownHost != null) {
            String unresolved = unknownHost.getMessage() != null ? unknownHost.getMessage() : host;
            return "Could not resolve host \"" + unresolved + "\". Check that the hostname is correct.";
        }

        if (hasCause(error, SocketTimeoutException.class)) {
            return "Timed out while connecting to \"" + host + "\". The server may be unreachable or too slow to respond.";
        }

        if (hasCause(error, ConnectException.class)) {
            return "Connection refused by \"" + host + "\". The host may be down or not accepting HTTPS connections.";
        }

        if (hasCause(error, NoRouteToHostException.class)) {
            return "No network route to host \"" + host + "\".";
        }

        SSLException sslException = findCause(error, SSLException.class);
        if (sslException != null) {
            String detail = sslException.getMessage();
            return "TLS connection to \"" + host + "\" failed" + (detail != null && !detail.isBlank() ? ": " + detail : ".");
        }

        MalformedURLException malformed = findCause(error, MalformedURLException.class);
        if (malformed != null) {
            return "Invalid URL: " + malformed.getMessage();
        }

        String detail = rootMessage(error);
        return "Failed to retrieve certificates from \"" + host + "\""
            + (detail != null && !detail.isBlank() ? ": " + detail : ".");
    }

    private static String extractHost(String urlString) {
        try {
            String host = new URL(urlString).getHost();
            return host != null && !host.isBlank() ? host : urlString;
        } catch (MalformedURLException e) {
            return urlString;
        }
    }

    private static boolean hasCause(Throwable error, Class<? extends Throwable> type) {
        return findCause(error, type) != null;
    }

    private static <T extends Throwable> T findCause(Throwable error, Class<T> type) {
        Throwable current = error;
        while (current != null) {
            if (type.isInstance(current)) {
                return type.cast(current);
            }
            Throwable next = current.getCause();
            if (next == current) {
                break;
            }
            current = next;
        }
        return null;
    }

    private static String rootMessage(Throwable error) {
        Throwable current = error;
        while (current.getCause() != null && current.getCause() != current) {
            current = current.getCause();
        }
        return current.getMessage() != null ? current.getMessage() : current.toString();
    }

    public ConnectionTestResult testTcpConnection(
        String channelId,
        String channelName,
        TcpDispatcherProperties dispatcherProperties
    ) {
        var oTlsPluginProperties = dispatcherProperties.getPluginProperties()
            .stream()
            .filter(TLSConnectorProperties.class::isInstance)
            .map(TLSConnectorProperties.class::cast)
            .findFirst();

        if (oTlsPluginProperties.isEmpty()) {
            log.debug("No TLS plugin properties found for testTcpConnection. Doing non-TLS test");
            // TODO Actually do the test
        }

        var properties = oTlsPluginProperties.get();

        var socketFactoryService = TLSServicePlugin.getPluginInstance().getSocketFactoryService();
        var socketFactory = socketFactoryService.getConnectorSocketFactory(properties);
        try {

            String host = templateValueReplacer.replaceValues(dispatcherProperties.getRemoteAddress(), channelId, channelName);
            int port = Integer.parseInt(templateValueReplacer.replaceValues(dispatcherProperties.getRemotePort(), channelId, channelName));
            int timeout = Integer.parseInt(templateValueReplacer.replaceValues(dispatcherProperties.getResponseTimeout(), channelId, channelName));

            if (!dispatcherProperties.isOverrideLocalBinding()) {
                return ConnectionUtils.testConnection(
                    socketFactory,
                    host,
                    port,
                    timeout,
                    null,
                    0
                );
            } else {
                String localAddr = templateValueReplacer.replaceValues(dispatcherProperties.getLocalAddress(), channelId, channelName);
                int localPort = Integer.parseInt(templateValueReplacer.replaceValues(dispatcherProperties.getLocalPort(), channelId, channelName));

                return ConnectionUtils.testConnection(
                    socketFactory,
                    host,
                    port,
                    timeout,
                    localAddr,
                    localPort
                );
            }
        } catch (Exception e) {
            throw new MirthApiException(e);
        }
    }

    public ConnectionTestResult testHttpConnection(
        String channelId,
        String channelName,
        HttpDispatcherProperties dispatcherProperties
    ) {
        final int TIMEOUT = 5000;

        var oTlsPluginProperties = dispatcherProperties.getPluginProperties()
            .stream()
            .filter(TLSConnectorProperties.class::isInstance)
            .map(TLSConnectorProperties.class::cast)
            .findFirst();

        if (oTlsPluginProperties.isEmpty()) {
            log.debug("No TLS plugin properties found for testTcpConnection. Doing non-TLS test");
            // TODO Actually do the test
        }

        var properties = oTlsPluginProperties.get();

        var socketFactoryService = TLSServicePlugin.getPluginInstance().getSocketFactoryService();
        var socketFactory = socketFactoryService.getConnectorSocketFactory(properties);

        try {
            var url = new URL(templateValueReplacer.replaceValues(dispatcherProperties.getHost(), channelId, channelName));
            var port = url.getPort();

            int computedPort;
            if (port == -1)
                // If no port was provided, default to port 80 or 443.
                computedPort = "https".equalsIgnoreCase(url.getProtocol()) ? 443 : 80;
            else
                computedPort = port;

            return ConnectionUtils.testConnection(
                socketFactory,
                url.getHost(),
                computedPort,
                TIMEOUT,
                null,
                0
            );
        } catch (Exception e) {
            throw new MirthApiException(e);
        }
    }

    public ConnectionTestResult testWsConnection(
        String channelId,
        String channelName,
        WebServiceDispatcherProperties dispatcherProperties
    ) {
        final int MAX_TIMEOUT = 300_000; // 5 minutes???

        var oTlsPluginProperties = dispatcherProperties.getPluginProperties()
            .stream()
            .filter(TLSConnectorProperties.class::isInstance)
            .map(TLSConnectorProperties.class::cast)
            .findFirst();

        if (oTlsPluginProperties.isEmpty()) {
            log.debug("No TLS plugin properties found for testWsConnection. Doing non-TLS test");
            // TODO Actually do the test
        }

        var properties = oTlsPluginProperties.get();

        var socketFactoryService = TLSServicePlugin.getPluginInstance().getSocketFactoryService();
        var socketFactory = socketFactoryService.getConnectorSocketFactory(properties);

        try {
            String host;
            if (dispatcherProperties.getLocationURI() != null && !dispatcherProperties.getLocationURI().isBlank()) {
                host = dispatcherProperties.getLocationURI();
            } else if (dispatcherProperties.getWsdlUrl() != null && !dispatcherProperties.getWsdlUrl().isBlank()) {
                host = dispatcherProperties.getWsdlUrl();
            } else {
                throw new Exception("Both WSDL URL and Location URI are blank. At least one must be populated in order to test connection.");
            }

            var url = new URL(templateValueReplacer.replaceValues(host, channelId, channelName));
            var port = url.getPort();

            int computedPort;
            if (port == -1)
                // If no port was provided, default to port 80 or 443.
                computedPort = "https".equalsIgnoreCase(url.getProtocol()) ? 443 : 80;
            else
                computedPort = port;

            return ConnectionUtils.testConnection(
                socketFactory,
                url.getHost(),
                computedPort,
                MAX_TIMEOUT,
                null,
                0
            );
        } catch (Exception e) {
            throw new MirthApiException(e);
        }
    }

    /**
     * Perform a byte-level clone of a KeyStore object
     *
     * @param keystore The KeyStore object to be cloned
     * @return Byte-level clone of the provided KeyStore
     */
    private KeyStore clone(KeyStore keystore) {
        // This doesn't have to be secret. It is just here because a keystore password cannot be null
        final var password = "sup3rS3cr1t!".toCharArray();

        try (var outStream = new ByteArrayOutputStream()) {
            var finalTrustStore = KeyStore.getInstance(PKCS12);

            keystore.store(outStream, password);

            try (var inStream = new ByteArrayInputStream(outStream.toByteArray())) {
                finalTrustStore.load(inStream, password);
            }

            return finalTrustStore;
        } catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
