/*
 * SPDX-License-Identifier: Apache-2.0 OR MPL-2.0
 * Copyright (c) 2021 Kaur Palang
 * Copyright (c) 2025 NovaMap Health Limited <https://novamap.health>
 * Modifications from commit aee95e6c7ddfcb6762e23c3d27ac227a6b2772d4 onward licensed under MPL-2.0
 */

package org.openintegrationengine.tlsmanager.server;

import com.kaurpalang.mirth.annotationsplugin.annotation.MirthServerClass;
import com.mirth.connect.server.controllers.ConfigurationController;
import com.mirth.connect.server.controllers.ExtensionController;
import com.mirth.connect.server.util.TemplateValueReplacer;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.openintegrationengine.tlsmanager.server.connectorconfig.TLSHttpConfiguration;
import org.openintegrationengine.tlsmanager.server.connectorconfig.TLSTcpConfiguration;
import org.openintegrationengine.tlsmanager.server.connectorconfig.TLSWebServiceConfiguration;
import org.openintegrationengine.tlsmanager.shared.TLSPluginConstants;
import com.mirth.connect.model.ExtensionPermission;
import com.mirth.connect.plugins.ServicePlugin;
import com.mirth.connect.server.controllers.ControllerFactory;
import org.openintegrationengine.tlsmanager.shared.SerializationController;
import org.openintegrationengine.tlsmanager.shared.models.TLSPluginConfiguration;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@MirthServerClass
@Slf4j
public class TLSServicePlugin implements ServicePlugin {

    public static final String PLUGIN_POINT_NAME = "TLS Manager Service Plugin";

    @Getter
    private CertificateService certificateService;

    @Getter
    private SocketFactoryService socketFactoryService;

    @Getter
    private WebServiceService webServiceService;

    private TLSPluginConfiguration tlsPluginConfiguration;

    private ScheduledExecutorService expiryMonitor;

    @Override
    public void init(Properties properties) {
        var configurationController = ControllerFactory.getFactory().createConfigurationController();
        var channelController = ControllerFactory.getFactory().createChannelController();
        var extensionController = ControllerFactory.getFactory().createExtensionController();

        this.certificateService = new CertificateService(channelController);
        this.socketFactoryService = new SocketFactoryService(
            configurationController,
            certificateService
        );

        this.webServiceService = new WebServiceService(
            socketFactoryService,
            new TemplateValueReplacer()
        );

        if (extensionController.isExtensionEnabled("HTTP Sender")
            || extensionController.isExtensionEnabled("HTTP Listener")) {
            configurationController.saveProperty(
                "HTTP",
                "httpConfigurationClass",
                TLSHttpConfiguration.class.getCanonicalName()
            );
        }

        if (extensionController.isExtensionEnabled("TCP Sender")
            || extensionController.isExtensionEnabled("TCP Listener")) {
            configurationController.saveProperty(
                "TCP",
                "tcpConfigurationClass",
                TLSTcpConfiguration.class.getCanonicalName()
            );
        }

        if (extensionController.isExtensionEnabled("Web Service Sender")
            || extensionController.isExtensionEnabled("Web Service Listener")) {
            configurationController.saveProperty(
                "WS",
                "wsConfigurationClass",
                TLSWebServiceConfiguration.class.getCanonicalName()
            );
        }

        SerializationController.registerSerializableClasses();

        tlsPluginConfiguration = TLSPluginConfiguration.fromEnv();

        if (!tlsPluginConfiguration.disableUI()) {
            installWar(configurationController);
        }
    }

    @Override
    public void update(Properties properties) {
        // We don't need to do anything here.
    }

    @Override
    public Properties getDefaultProperties() {
        var defaultProperties = new Properties();
        defaultProperties.setProperty(TLSPluginConstants.PROPERTY_TRUST_BACKEND, "database");

        return defaultProperties;
    }

    @Override
    public ExtensionPermission[] getExtensionPermissions() {
        return new ExtensionPermission[]{};
    }

    @Override
    public Map<String, Object> getObjectsForSwaggerExamples() {
        return new HashMap<>();
    }

    @Override
    public String getPluginPointName() {
        return PLUGIN_POINT_NAME;
    }

    @Override
    public void start() {
        this.certificateService.init(tlsPluginConfiguration);
        startExpiryMonitor();
    }

    @Override
    public void stop() {
        if (expiryMonitor != null) {
            expiryMonitor.shutdownNow();
            expiryMonitor = null;
        }
    }

    /**
     * Logs certificates that have expired or expire within TLS_EXPIRY_WARN_DAYS (default 30)
     * a minute after start and then once a day, as WARN, or ERROR once expired.
     */
    private void startExpiryMonitor() {
        int warnDays = CertificateExpiry.warnDays(System.getenv("TLS_EXPIRY_WARN_DAYS"));
        expiryMonitor = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "tls-manager-expiry-monitor");
            thread.setDaemon(true);
            return thread;
        });
        expiryMonitor.scheduleWithFixedDelay(() -> logExpiringCertificates(warnDays),
            1, 24 * 60, TimeUnit.MINUTES);
    }

    void logExpiringCertificates(int warnDays) {
        try {
            var findings = certificateService.getExpiringCertificates(warnDays);
            if (findings.isEmpty()) {
                log.info("No TLS certificates expire within {} days", warnDays);
                return;
            }
            for (var finding : findings) {
                if (finding.expired()) {
                    log.error(finding.describe());
                } else {
                    log.warn(finding.describe());
                }
            }
        } catch (RuntimeException e) {
            log.warn("Could not check TLS certificate expiry: {}", e.toString());
        }
    }

    public static TLSServicePlugin getPluginInstance() {
        var servicePlugin = ControllerFactory.getFactory()
            .createExtensionController()
            .getServicePlugins()
            .get(PLUGIN_POINT_NAME);

        if (servicePlugin instanceof TLSServicePlugin tlsServicePlugin) {
            return tlsServicePlugin;
        } else {
            // well we shouldn't really get here
            var ex = new RuntimeException(
                "Plugin pointname '%s' does not point to an instance of %s class".formatted(
                    PLUGIN_POINT_NAME,
                    TLSServicePlugin.class.getCanonicalName()
                )
            );

            log.error("Error fetching plugin instance", ex);
            throw ex;
        }
    }

    private void installWar(ConfigurationController configurationController) {
        var webappsPath = Path.of(configurationController.getBaseDir(), "webapps");
        var warPath = Path.of(webappsPath.toString(), "tls-manager.war");

        if (!webappsPath.toFile().exists()) {
            log.debug("Webapps directory does not exist. Creating...");
            if (!webappsPath.toFile().mkdirs()) {
                throw new IllegalStateException("Failed to create webapps directory at " + webappsPath);
            }
        }

        var warFile = warPath.toFile();

        if (warFile.exists()) {
            log.debug("TLS Manager WAR already exists at {}. Deleting...", warPath);
            if (!warFile.delete()) {
                throw new IllegalStateException("Failed to delete TLS Manager WAR at " + warPath);
            }
        }

        var pluginDirectoryPath = Path.of(ExtensionController.getExtensionsPath(), "tls-manager", "tls-manager.war");

        log.debug("Copying TLS Manager WAR from {} to {}", pluginDirectoryPath, warPath);
        try {
            Files.copy(pluginDirectoryPath, warPath);
            log.debug("TLS Manager WAR copied successfully");
        } catch (IOException e) {
            throw new RuntimeException(
                "Failed to copy TLS Manager WAR from %s to %s".formatted(pluginDirectoryPath, warPath),
                e
            );
        }
    }
}
