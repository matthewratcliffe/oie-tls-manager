/*
 * SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2025 NovaMap Health Limited <https://novamap.health>
 */

package org.openintegrationengine.tlsmanager.server.servlets;

import com.kaurpalang.mirth.annotationsplugin.annotation.MirthApiProvider;
import com.kaurpalang.mirth.annotationsplugin.type.ApiProviderType;
import com.mirth.connect.client.core.ClientException;
import com.mirth.connect.client.core.api.MirthApiException;
import com.mirth.connect.connectors.http.HttpDispatcherProperties;
import com.mirth.connect.connectors.tcp.TcpDispatcherProperties;
import com.mirth.connect.connectors.ws.DefinitionServiceMap;
import com.mirth.connect.connectors.ws.WebServiceDispatcherProperties;
import com.mirth.connect.server.api.DontCheckAuthorized;
import com.mirth.connect.server.api.MirthServlet;
import lombok.extern.slf4j.Slf4j;
import org.openintegrationengine.tlsmanager.server.CertificateService;
import org.openintegrationengine.tlsmanager.server.TLSServicePlugin;
import org.openintegrationengine.tlsmanager.server.WebServiceService;
import org.openintegrationengine.tlsmanager.shared.TLSPluginConstants;
import org.openintegrationengine.tlsmanager.shared.models.ConnectionTestResult;
import org.openintegrationengine.tlsmanager.shared.models.LocalCertificate;
import org.openintegrationengine.tlsmanager.shared.models.TrustedCertificate;
import org.openintegrationengine.tlsmanager.shared.servlet.TLSServletInterface;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Slf4j
@MirthApiProvider(type = ApiProviderType.SERVER_CLASS)
public class TLSServlet extends MirthServlet implements TLSServletInterface {

    private final CertificateService certificateService;
    private final WebServiceService webServiceService;

    public TLSServlet(@Context HttpServletRequest request, @Context SecurityContext sc) {
        this(
            request,
            sc,
            TLSServicePlugin.getPluginInstance().getCertificateService(),
            TLSServicePlugin.getPluginInstance().getWebServiceService()
        );
    }

    public TLSServlet(
        @Context HttpServletRequest request,
        @Context SecurityContext sc,
        CertificateService certificateService,
        WebServiceService webServiceService
    ) {
        super(request, sc, TLSPluginConstants.PLUGIN_POINTNAME);

        this.certificateService = certificateService;
        this.webServiceService = webServiceService;
    }

    @Override
    public Set<String> getPublicCertificates() {
        return certificateService.getTrustedCertificateAliases();
    }

    @Override
    public Set<String> getClientCertificates() {
        return certificateService.getLocalCertificateAliases();
    }

    @Override
    public byte[] getKeystore() {
        var keystore = certificateService.getExternalTrustStore();

        try (var baos = new ByteArrayOutputStream()) {
            keystore.store(baos, "changeit".toCharArray());
            return baos.toByteArray();
        } catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    @DontCheckAuthorized
    public String setTruststore(InputStream inputStream, String password) {

        if (!isUserAuthorized(false)) {
            isUserAuthorized(true);
            throw new WebApplicationException(Response.Status.FORBIDDEN);
        }

        byte[] trustStoreBytes;
        try {
            trustStoreBytes = inputStream.readAllBytes();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        certificateService.storeExtraTrustStore(trustStoreBytes, password.toCharArray());
        return "timmis";
    }

    @Override
    public List<TrustedCertificate> getSystemCertificates() {
        return certificateService.getEncodedSystemCertificates();
    }

    @Override
    public List<TrustedCertificate> getLocalCertificates() {
        return certificateService.getEncodedLocalCertificates();
    }

    @Override
    public void setLocalCertificates(List<LocalCertificate> localCertificates) {
        certificateService.setLocalCertificates(localCertificates);
    }

    @Override
    public List<TrustedCertificate> getTrustedCertificates() {
        return certificateService.getEncodedTrustedCertificates();
    }

    @Override
    public void setTrustedCertificates(List<TrustedCertificate> trustedCertificates) {
        certificateService.setTrustedCertificates(trustedCertificates);
    }

    @Override
    public List<TrustedCertificate> getRemoteCertificates(String url) {
        return certificateService.retrieveRemoteCertificates(url);
    }

    @Override
    public ConnectionTestResult testTcpConnection(String channelId, String channelName, TcpDispatcherProperties dispatcherProperties) throws ClientException {
        return certificateService.testTcpConnection(channelId, channelName, dispatcherProperties);
    }

    @Override
    public ConnectionTestResult testHttpsConnection(String channelId, String channelName, HttpDispatcherProperties dispatcherProperties) throws ClientException {
        return certificateService.testHttpConnection(channelId, channelName, dispatcherProperties);
    }

    @Override
    public ConnectionTestResult testWsConnection(String channelId, String channelName, WebServiceDispatcherProperties wsDispatcherProperties) throws ClientException {
        return certificateService.testWsConnection(channelId, channelName, wsDispatcherProperties);
    }

    @Override
    public Object cacheWsdlFromUrl(
        String channelId,
        String channelName,
        WebServiceDispatcherProperties properties
    ) {
        try {
            webServiceService.cacheWsdlFromUrl(channelId, channelName, properties);
            return null;
        } catch (Exception e) {
            throw new MirthApiException(e);
        }
    }

    @Override
    public boolean isWsdlCached(
        String channelId,
        String channelName,
        String wsdlUrl,
        String username,
        String password
    ) {
        return false;
    }

    @Override
    public DefinitionServiceMap getDefinition(
        String channelId,
        String channelName,
        String wsdlUrl,
        String username,
        String password
    ) {
        try {
            return webServiceService.getDefinition(channelId, channelName, wsdlUrl, username, password);
        } catch (Exception e) {
            throw new MirthApiException(e);
        }
    }

    @Override
    public Map<String, Object> createCertificateAuthority(Map<String, String> request) {
        return authorityCall("create the CA", () -> certificateService.createCa(
            field(request, "alias"), field(request, "subject"), field(request, "keyType"),
            intField(request, "validityDays"), intField(request, "pathLength"),
            field(request, "issuerAlias"), flag(request, "replace")));
    }

    @Override
    public Map<String, Object> renewCertificateAuthority(Map<String, String> request) {
        return authorityCall("renew the CA", () -> certificateService.renewCa(
            field(request, "alias"), intField(request, "validityDays"), field(request, "issuerAlias")));
    }

    @Override
    public Map<String, Object> issueCertificate(Map<String, String> request) {
        return authorityCall("issue the certificate", () -> certificateService.issueLeaf(
            field(request, "caAlias"), field(request, "alias"), field(request, "subject"),
            names(field(request, "subjectAltNames")), field(request, "keyType"),
            intField(request, "validityDays"), flag(request, "replace")));
    }

    /**
     * Runs a CA operation. A request the caller got wrong (no such CA, an expired CA, a bad
     * subject) is a 400 with the reason as text; the private key is never part of the answer.
     */
    private Map<String, Object> authorityCall(String what, java.util.concurrent.Callable<CertificateService.CaResult> call) {
        try {
            CertificateService.CaResult result = call.call();
            X509Certificate leaf = result.chain()[0];
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("ok", "true");
            out.put("alias", result.alias());
            out.put("subject", leaf.getSubjectX500Principal().getName());
            out.put("issuer", leaf.getIssuerX500Principal().getName());
            out.put("notBefore", leaf.getNotBefore().toInstant().toString());
            out.put("notAfter", leaf.getNotAfter().toInstant().toString());
            out.put("cappedToIssuer", String.valueOf(result.cappedToIssuer()));
            out.put("certificate", CertificateService.pem(result.chain()));
            out.put("updatedChains", String.join(",", result.updatedChains()));
            out.put("updatedTrusted", String.join(",", result.updatedTrusted()));
            return out;
        } catch (IllegalArgumentException e) {
            throw plainError(Response.Status.BAD_REQUEST, e.getMessage());
        } catch (WebApplicationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Could not {}", what, e);
            throw plainError(Response.Status.INTERNAL_SERVER_ERROR, "Could not " + what + ": " + e.getMessage());
        }
    }

    private static WebApplicationException plainError(Response.Status status, String message) {
        return new WebApplicationException(Response.status(status).entity(message)
            .type(javax.ws.rs.core.MediaType.TEXT_PLAIN).build());
    }

    private static String field(Map<String, String> request, String key) {
        String value = request == null ? null : request.get(key);
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static Integer intField(Map<String, String> request, String key) {
        String value = field(request, key);
        if (value == null) {
            return null;
        }
        try {
            return Integer.valueOf(value);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("\"" + key + "\" must be a whole number, not \"" + value + "\".");
        }
    }

    private static boolean flag(Map<String, String> request, String key) {
        return "true".equalsIgnoreCase(field(request, key));
    }

    /** Subject alternative names separated by commas, semicolons or new lines. */
    private static List<String> names(String value) {
        List<String> names = new ArrayList<>();
        if (value != null) {
            for (String name : value.split("[,;\\r\\n]+")) {
                if (!name.isBlank()) {
                    names.add(name.trim());
                }
            }
        }
        return names;
    }}
