/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.fedsetup;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.apache.http.client.config.RequestConfig;
import org.jboss.logging.Logger;
import org.keycloak.broker.saml.SAMLIdentityProviderConfig;
import org.keycloak.broker.saml.SAMLIdentityProviderFactory;
import org.keycloak.common.util.Time;
import org.keycloak.fedsetup.representation.DirectInstallationTrust;
import org.keycloak.fedsetup.representation.FedSetupConnection;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.http.simple.SimpleHttpResponse;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * Refreshes the guarded SAML metadata source of an inbound FedSetup Connection.
 *
 * <p>The native SAML broker can refresh metadata during authentication, but that
 * fetch path cannot enforce a FedSetup Direct Installation Trust's source and
 * endpoint bindings.  This refresher therefore resolves the stored metadata
 * URL ahead of time and materializes the validated result in the broker model.</p>
 */
public final class FedSetupSamlMetadataRefresher {

    private static final Logger LOG = Logger.getLogger(FedSetupSamlMetadataRefresher.class);

    private final KeycloakSession session;
    private final RealmModel realm;
    private final RealmFedSetupStore store;

    public FedSetupSamlMetadataRefresher(KeycloakSession session, RealmModel realm, RealmFedSetupStore store) {
        this.session = session;
        this.realm = realm;
        this.store = store;
    }

    /**
     * Refreshes every active, metadata-backed SAML Connection in this realm.
     * A failure is isolated to its Connection; it never replaces the prior,
     * working broker configuration.
     */
    public void refreshAll() {
        for (FedSetupConnection connection : store.getConnections()) {
            if (!"ACTIVE".equals(connection.getStatus()) || !"saml".equals(connection.getProtocol())
                    || blank(connection.getSamlMetadataUrl())) {
                continue;
            }
            try {
                refresh(connection);
            } catch (FedSetupValidationException e) {
                FedSetupAudit.failure(session, realm, "saml_metadata_refresh_failed", connection, "metadata_refresh_rejected");
                LOG.warnf("FedSetup SAML metadata refresh rejected connection %s in realm %s: %s",
                        connection.getId(), realm.getName(), e.getMessage());
            } catch (RuntimeException e) {
                FedSetupAudit.failure(session, realm, "saml_metadata_refresh_failed", connection, "metadata_refresh_failed");
                LOG.warnf(e, "FedSetup SAML metadata refresh failed for connection %s in realm %s",
                        connection.getId(), realm.getName());
            }
        }
    }

    void refresh(FedSetupConnection connection) {
        DirectInstallationTrust trust = store.requireTrust(connection.getTrustId());
        if (!trust.isActive() || (trust.getExpiresAt() > 0 && trust.getExpiresAt() <= Time.currentTime())) {
            throw new FedSetupValidationException("Direct Installation Trust is inactive or expired");
        }
        if (!Objects.equals(connection.getIdpIssuer(), trust.getIdpIssuer())) {
            throw new FedSetupValidationException("Connection IdP issuer no longer matches its Direct Installation Trust");
        }

        String metadataUrl = FedSetupUri.canonicalize(connection.getSamlMetadataUrl());
        if (!FedSetupUri.sameOrigin(metadataUrl, trust.getIdpIssuer())) {
            throw new FedSetupValidationException("SAML metadata URL is not on the Direct Installation Trust issuer origin");
        }
        SAMLMetadata metadata = parseAndValidate(fetchMetadata(metadataUrl), trust, connection);

        IdentityProviderModel provider = realm.getIdentityProviderByAlias(connection.getBrokerAlias());
        if (provider == null || !"saml".equals(provider.getProviderId())) {
            throw new FedSetupValidationException("FedSetup SAML identity broker is missing or has the wrong type");
        }

        Map<String, String> updatedConfig = new LinkedHashMap<>(provider.getConfig());
        applyMetadata(updatedConfig, metadata, connection.hasSamlSingleLogoutService());
        Map<String, String> updatedSso = new LinkedHashMap<>(connection.getSso());
        updatedSso.put("single_sign_on_service", metadata.singleSignOnService());
        updatedSso.put("signing_certificate", metadata.signingCertificates());
        if (metadata.nameIdFormat() != null) {
            updatedSso.put("name_id_format", metadata.nameIdFormat());
        }
        if (connection.hasSamlSingleLogoutService() && metadata.singleLogoutService() != null) {
            updatedSso.put("single_logout_service", metadata.singleLogoutService());
        }

        boolean brokerChanged = !updatedConfig.equals(provider.getConfig());
        boolean connectionChanged = !updatedSso.equals(connection.getSso()) || !metadataUrl.equals(connection.getSamlMetadataUrl());
        if (!brokerChanged && !connectionChanged) {
            return;
        }

        // All parsing and validation is complete before either persistent
        // model is changed.  A failed parse therefore leaves last-known-good
        // metadata in effect.
        if (brokerChanged) {
            provider.setConfig(updatedConfig);
            realm.updateIdentityProvider(provider);
        }
        if (connectionChanged) {
            connection.setSso(updatedSso);
            connection.setSamlMetadataUrl(metadataUrl);
            store.updateConnection(connection, connection.getVersion());
        }
        FedSetupAudit.success(session, realm, org.keycloak.events.admin.OperationType.UPDATE,
                "saml_metadata_refreshed", trust, connection);
        LOG.infof("FedSetup SAML metadata refreshed connection %s in realm %s", connection.getId(), realm.getName());
    }

    /** Parses trusted metadata and returns only the fields FedSetup permits it to control. */
    static SAMLMetadata parseAndValidate(String document, DirectInstallationTrust trust, FedSetupConnection connection) {
        final Map<String, String> parsed;
        try {
            parsed = new SAMLIdentityProviderFactory().parseConfig(null, document);
        } catch (RuntimeException e) {
            throw new FedSetupValidationException("SAML metadata could not be parsed", e);
        }
        if (parsed == null || parsed.isEmpty()) {
            throw new FedSetupValidationException("SAML metadata does not contain an IDPSSODescriptor");
        }
        String entityId = required(parsed, SAMLIdentityProviderConfig.IDP_ENTITY_ID, "entityID");
        if (!Objects.equals(entityId, connection.getSso().get("entity_id"))) {
            throw new FedSetupValidationException("SAML metadata entityID does not match the configured IdP entity ID");
        }
        String sso = issuerBoundEndpoint(parsed, SAMLIdentityProviderConfig.SINGLE_SIGN_ON_SERVICE_URL,
                "SingleSignOnService", trust.getIdpIssuer());
        String slo = optionalIssuerBoundEndpoint(parsed.get(SAMLIdentityProviderConfig.SINGLE_LOGOUT_SERVICE_URL),
                "SingleLogoutService", trust.getIdpIssuer());
        String certificates = validatedCertificates(parsed.get(SAMLIdentityProviderConfig.SIGNING_CERTIFICATE_KEY));
        return new SAMLMetadata(entityId, sso, slo, certificates,
                Boolean.parseBoolean(parsed.get(SAMLIdentityProviderConfig.POST_BINDING_RESPONSE)),
                Boolean.parseBoolean(parsed.get(SAMLIdentityProviderConfig.POST_BINDING_LOGOUT)),
                blank(parsed.get(SAMLIdentityProviderConfig.NAME_ID_POLICY_FORMAT)) ? null
                        : parsed.get(SAMLIdentityProviderConfig.NAME_ID_POLICY_FORMAT));
    }

    private String fetchMetadata(String metadataUrl) {
        FedSetupUri.requirePublicAddress(metadataUrl, "SAML metadata source");
        RequestConfig noRedirects = RequestConfig.copy(RequestConfig.DEFAULT).setRedirectsEnabled(false).build();
        try (SimpleHttpResponse response = SimpleHttp.create(session).withRequestConfig(noRedirects).doGet(metadataUrl).asResponse()) {
            if (response.getStatus() != 200) {
                throw new FedSetupValidationException("SAML metadata endpoint returned HTTP " + response.getStatus());
            }
            return response.asString();
        } catch (IOException | RuntimeException e) {
            if (e instanceof FedSetupValidationException validation) {
                throw validation;
            }
            throw new FedSetupValidationException("Unable to retrieve SAML metadata from the trusted issuer", e);
        }
    }

    static void applyMetadata(Map<String, String> target, SAMLMetadata metadata, boolean refreshSlo) {
        target.put(SAMLIdentityProviderConfig.IDP_ENTITY_ID, metadata.entityId());
        target.put(SAMLIdentityProviderConfig.SINGLE_SIGN_ON_SERVICE_URL, metadata.singleSignOnService());
        target.put(SAMLIdentityProviderConfig.SIGNING_CERTIFICATE_KEY, metadata.signingCertificates());
        target.put(SAMLIdentityProviderConfig.VALIDATE_SIGNATURE, "true");
        target.put(SAMLIdentityProviderConfig.POST_BINDING_RESPONSE, Boolean.toString(metadata.postBindingResponse()));
        if (metadata.nameIdFormat() != null) {
            target.put(SAMLIdentityProviderConfig.NAME_ID_POLICY_FORMAT, metadata.nameIdFormat());
        }
        if (refreshSlo && metadata.singleLogoutService() != null) {
            target.put(SAMLIdentityProviderConfig.SINGLE_LOGOUT_SERVICE_URL, metadata.singleLogoutService());
            target.put(SAMLIdentityProviderConfig.POST_BINDING_LOGOUT, Boolean.toString(metadata.postBindingLogout()));
        }
    }

    private static String issuerBoundEndpoint(Map<String, String> values, String key, String name, String issuer) {
        return optionalIssuerBoundEndpoint(required(values, key, name), name, issuer);
    }

    private static String optionalIssuerBoundEndpoint(String value, String name, String issuer) {
        if (blank(value)) {
            return null;
        }
        String endpoint = FedSetupUri.canonicalize(value);
        if (!FedSetupUri.sameOrigin(endpoint, issuer)) {
            throw new FedSetupValidationException(name + " is not on the Direct Installation Trust issuer origin");
        }
        return endpoint;
    }

    private static String validatedCertificates(String value) {
        if (blank(value)) {
            throw new FedSetupValidationException("SAML metadata has no signing certificate");
        }
        List<String> certificates = new ArrayList<>();
        for (String certificate : value.split(",")) {
            String normalized = certificate.replaceAll("\\s", "");
            if (normalized.isEmpty()) {
                throw new FedSetupValidationException("SAML metadata contains an empty signing certificate");
            }
            try {
                CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(
                        ("-----BEGIN CERTIFICATE-----\n" + normalized + "\n-----END CERTIFICATE-----")
                                .getBytes(StandardCharsets.US_ASCII)));
            } catch (Exception e) {
                throw new FedSetupValidationException("SAML metadata contains an invalid signing certificate", e);
            }
            certificates.add(normalized);
        }
        return String.join(",", certificates);
    }

    private static String required(Map<String, String> values, String key, String name) {
        String value = values.get(key);
        if (blank(value)) {
            throw new FedSetupValidationException("SAML metadata is missing " + name);
        }
        return value;
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }

    record SAMLMetadata(String entityId, String singleSignOnService, String singleLogoutService,
                        String signingCertificates, boolean postBindingResponse, boolean postBindingLogout,
                        String nameIdFormat) {
    }
}
