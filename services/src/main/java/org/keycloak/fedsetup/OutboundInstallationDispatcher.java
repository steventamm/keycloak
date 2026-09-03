/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup;

import java.io.IOException;
import java.net.URI;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import jakarta.ws.rs.core.UriBuilder;

import org.keycloak.common.util.PemUtils;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.fedsetup.representation.DirectInstallationTrust;
import org.keycloak.fedsetup.representation.FedSetupCredentialReference;
import org.keycloak.fedsetup.representation.FedSetupInstallation;
import org.keycloak.fedsetup.representation.InstallationConfigurationRequest;
import org.keycloak.fedsetup.representation.InstallationConfigurationResponse;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.http.simple.SimpleHttpRequest;
import org.keycloak.http.simple.SimpleHttpResponse;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.saml.SamlClient;
import org.keycloak.protocol.saml.SamlProtocol;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.Urls;
import org.keycloak.services.resources.RealmsResource;
import org.keycloak.urls.UrlType;
import org.keycloak.util.JsonSerialization;
import org.keycloak.util.KeyWrapperUtil;

import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;

/**
 * Explicit, retryable IdP-side dispatcher for the Keycloak Direct Installation
 * Trust profile. The record passed to this class is the durable outbox state;
 * it is updated after every attempt and never contains a raw secret.
 */
public final class OutboundInstallationDispatcher {

    private final KeycloakSession session;
    private final RealmModel realm;
    private final RealmFedSetupStore store;

    public OutboundInstallationDispatcher(KeycloakSession session, RealmModel realm, RealmFedSetupStore store) {
        this.session = session;
        this.realm = realm;
        this.store = store;
    }

    public FedSetupInstallation dispatch(FedSetupInstallation installation) {
        DirectInstallationTrust trust = store.requireTrust(installation.getTrustId());
        long previousVersion = installation.getVersion();
        try {
            validateDispatch(installation, trust);
            InstallationConfigurationRequest request = request(installation, trust);
            installation.setDesiredSso(ssoState(request));
            boolean create = installation.getRemoteConnectionId() == null;
            String target = create ? installation.getConfigurationEndpoint()
                    : connectionEndpoint(trust, installation.getConfigurationEndpoint(), installation.getRemoteConnectionId());
            String body = JsonSerialization.valueAsString(request);
            String authorization = authorization(trust, create ? "POST" : "PATCH", target, body, request);
            SimpleHttpRequest http = (create ? SimpleHttp.create(session).doPost(target) : SimpleHttp.create(session).doPatch(target))
                    .header("Authorization", "Bearer " + authorization)
                    .header("Content-Type", MediaType.APPLICATION_JSON)
                    .entity(new StringEntity(body, ContentType.APPLICATION_JSON));
            if (create) http.header(FedSetupConstants.IDEMPOTENCY_HEADER, installation.getIdempotencyKey());
            if (!create) http.header(FedSetupConstants.IF_MATCH_HEADER, required(installation.getRemoteEtag(), "Remote ETag"));
            try (SimpleHttpResponse response = http.asResponse()) {
                int expected = create ? 201 : 200;
                if (response.getStatus() != expected) {
                    throw new FedSetupValidationException("Application returned HTTP " + response.getStatus());
                }
                InstallationConfigurationResponse connection = JsonSerialization.readValue(response.asString(), InstallationConfigurationResponse.class);
                if (connection.getConnectionId() == null || connection.getConnectionId().isBlank()) {
                    throw new FedSetupValidationException("Application response is missing connection id");
                }
                installation.setRemoteConnectionId(connection.getConnectionId());
                installation.setRemoteEtag(required(response.getFirstHeader(FedSetupConstants.ETAG_HEADER), "Application response ETag"));
                if (connection.getScim() != null) {
                    if (!installation.getCapabilities().contains("scim")) {
                        throw new FedSetupValidationException("Application returned SCIM after it was removed from the Installation");
                    }
                    installation.setScimEndpoint(connection.getScim().getProvisioningEndpoint());
                    readScimCredentials(installation, connection, create);
                } else if (installation.getCapabilities().contains("scim")) {
                    throw new FedSetupValidationException("Application response is missing configured SCIM provisioning");
                } else if (!installation.getCapabilities().contains("scim")) {
                    clearScimCredential(installation);
                }
                installation.setAppliedSso(ssoState(request));
                installation.setStatus("ACTIVE");
                installation.setLastError(null);
                installation.setDispatchAttempts(installation.getDispatchAttempts() + 1);
                installation.setNextAttemptAt(0);
                return store.updateInstallation(installation, previousVersion);
            }
        } catch (Exception e) {
            installation.setStatus("RETRY_PENDING");
            installation.setDispatchAttempts(installation.getDispatchAttempts() + 1);
            installation.setNextAttemptAt(Time.currentTime() + retryDelay(installation.getDispatchAttempts()));
            installation.setLastError(safeMessage(e));
            return store.updateInstallation(installation, previousVersion);
        }
    }

    public FedSetupInstallation delete(FedSetupInstallation installation) {
        long previousVersion = installation.getVersion();
        store.suppressPendingScimTasks(installation.getId());
        try {
            DirectInstallationTrust trust = store.requireTrust(installation.getTrustId());
            validateDispatch(installation, trust);
            if (installation.getRemoteConnectionId() == null) {
                clearScimCredential(installation);
                installation.setStatus("DEACTIVATED");
                return store.updateInstallation(installation, previousVersion);
            }
            String target = connectionEndpoint(trust, installation.getConfigurationEndpoint(), installation.getRemoteConnectionId());
            String authorization = authorization(trust, "DELETE", target, "", null);
            SimpleHttpRequest http = SimpleHttp.create(session).doDelete(target).header("Authorization", "Bearer " + authorization);
            try (SimpleHttpResponse response = http.asResponse()) {
                if (response.getStatus() != 204) throw new FedSetupValidationException("Application returned HTTP " + response.getStatus());
            }
            clearScimCredential(installation);
            installation.setStatus("DEACTIVATED");
            installation.setLastError(null);
            installation.setDispatchAttempts(installation.getDispatchAttempts() + 1);
            installation.setNextAttemptAt(0);
            return store.updateInstallation(installation, previousVersion);
        } catch (Exception e) {
            installation.setStatus("DELETE_RETRY_PENDING");
            installation.setDispatchAttempts(installation.getDispatchAttempts() + 1);
            installation.setNextAttemptAt(Time.currentTime() + retryDelay(installation.getDispatchAttempts()));
            installation.setLastError(safeMessage(e));
            return store.updateInstallation(installation, previousVersion);
        }
    }

    /**
     * Detects a material change in the selected local client or realm signing
     * key without sending it.  The scheduled outbox invokes this for active
     * installations, leaving the guarded remote PATCH to an administrator.
     */
    public FedSetupInstallation refreshDesiredSso(FedSetupInstallation installation) {
        if (!"ACTIVE".equals(installation.getStatus()) || installation.getRemoteConnectionId() == null) return installation;
        long previousVersion = installation.getVersion();
        try {
            DirectInstallationTrust trust = store.requireTrust(installation.getTrustId());
            validateDispatch(installation, trust);
            Map<String, String> desired = ssoState(request(installation, trust));
            if (desired.equals(installation.getAppliedSso())) return installation;
            installation.setDesiredSso(desired);
            installation.setStatus("PENDING_REVIEW");
            installation.setLastError("Local SSO metadata changed; administrator review is required before remote update");
            installation.setNextAttemptAt(0);
            return store.updateInstallation(installation, previousVersion);
        } catch (Exception e) {
            // Only persist when the error actually changed. Otherwise a persistently failing
            // ACTIVE installation (e.g. an inactive Trust or a deleted client) would be rewritten,
            // version-bumped, and re-audited on every scheduler tick indefinitely.
            String message = safeMessage(e);
            if (Objects.equals(message, installation.getLastError())) {
                return installation;
            }
            installation.setLastError(message);
            return store.updateInstallation(installation, previousVersion);
        }
    }

    private InstallationConfigurationRequest request(FedSetupInstallation installation, DirectInstallationTrust trust) {
        ClientModel client = realm.getClientByClientId(installation.getClientId());
        if (client == null) throw new FedSetupValidationException("Selected client no longer exists");
        InstallationConfigurationRequest result = new InstallationConfigurationRequest();
        result.setIdpIssuer(issuer());
        result.setIdpDomain(URI.create(issuer()).getHost());
        // Profile authorization is carried by the Installation Authorization
        // JWT, not serialized in the draft configuration body.
        result.setExtensionProfiles(installation.getExtensionProfiles());
        InstallationConfigurationRequest.OidcConfiguration oidc = null;
        InstallationConfigurationRequest.SamlConfiguration saml = null;
        if ("oidc".equals(installation.getProtocol())) {
            oidc = new InstallationConfigurationRequest.OidcConfiguration();
            oidc.setIssuer(issuer());
            String protocolBase = RealmsResource.protocolUrl(session.getContext().getUri(UrlType.FRONTEND))
                    .build(realm.getName(), "openid-connect").toString();
            oidc.setAuthorizationEndpoint(protocolBase + "/auth");
            oidc.setTokenEndpoint(protocolBase + "/token");
            oidc.setClientId(client.getClientId());
            String clientAuthenticationMethod = clientAuthenticationMethod(client);
            oidc.setTokenEndpointAuthMethod(clientAuthenticationMethod);
            if ("client_secret_basic".equals(clientAuthenticationMethod) || "client_secret_post".equals(clientAuthenticationMethod)) {
                if (client.getSecret() == null || client.getSecret().isBlank()) {
                    throw new FedSetupValidationException("Selected OIDC client has no client secret");
                }
                oidc.setClientSecret(client.getSecret());
            }
            // The pre-created Keycloak client remains the source of requested
            // scopes. Sending its default client scopes makes an outbound
            // configuration reflect the reviewed registration and lets the
            // desired/applied state detect a later scope change.
            oidc.setScopes(effectiveOidcScopes(client));
            result.setOidc(oidc);
        } else {
            saml = new InstallationConfigurationRequest.SamlConfiguration();
            String protocolBase = RealmsResource.protocolUrl(session.getContext().getUri(UrlType.FRONTEND))
                    .build(realm.getName(), SamlProtocol.LOGIN_PROTOCOL).toString();
            KeyWrapper signingKey = session.keys().getActiveKey(realm, KeyUse.SIG, Algorithm.RS256);
            if (signingKey == null || signingKey.getCertificate() == null) {
                throw new FedSetupValidationException("Realm has no active SAML signing certificate");
            }
            // The selected SAML client is the pre-existing Application/SP
            // registration.  The IdP entityID is the realm's own immutable
            // issuer, never that client identifier.
            saml.setIdpEntityId(issuer());
            saml.setIdpSsoUrl(protocolBase);
            saml.setIdpMetadataUrl(protocolBase + "/descriptor");
            saml.setIdpCertificate(PemUtils.encodeCertificate(signingKey.getCertificate()));
            String nameIdFormat = new SamlClient(client).getNameIDFormat();
            if (nameIdFormat != null) saml.setNameidFormat(nameIdFormat);
            saml.setAttributeMapping(installation.getSamlAttributeMapping());
            if (trust.isSamlSpInitiatedSloSupported()) saml.setIdpSloUrl(protocolBase);
            result.setSaml(saml);
        }
        if (installation.getCapabilities().contains("scim")) {
            InstallationConfigurationRequest.ScimConfiguration scim = new InstallationConfigurationRequest.ScimConfiguration();
            scim.setFeatures(selectedScimFeatures(installation));
            result.setScim(scim);
        } else if (installation.getRemoteConnectionId() != null && !blank(installation.getScimEndpoint())) {
            result.setRemove(java.util.Set.of("scim"));
        }
        return result;
    }

    private String authorization(DirectInstallationTrust trust, String method, String target, String body,
                                 InstallationConfigurationRequest request) {
        KeyWrapper key = session.keys().getActiveKey(realm, KeyUse.SIG, Algorithm.RS256);
        if (key == null) throw new FedSetupValidationException("Realm has no active RS256 signing key");
        boolean cimd = trust.getInstallationRuntimeCimdUri() != null && !trust.getInstallationRuntimeCimdUri().isBlank();
        JsonWebToken token = new JsonWebToken().issuer(cimd ? cimdUri() : issuer()).id(UUID.randomUUID().toString())
                .issuedNowWithTTL(FedSetupConstants.MAX_AUTHORIZATION_LIFESPAN_SECONDS);
        token.setOtherClaims("application_tenant_id", trust.getApplicationTenantId());
        if (cimd) {
            token.audience(target);
            token.setOtherClaims("idp_issuer", issuer());
            token.setOtherClaims("htm", method);
            token.setOtherClaims("htu", target);
            token.setOtherClaims("request_hash", InstallationAuthorizationValidator.sha256Base64Url(body));
        } else {
            token.setOtherClaims("method", method);
            token.setOtherClaims("uri", target);
            token.setOtherClaims("request_hash", InstallationAuthorizationValidator.sha256(body));
        }
        token.setOtherClaims("capabilities", request == null ? java.util.List.of() : request.requestedCapabilities());
        token.setOtherClaims(cimd ? "federation_extension_profiles" : "extension_profiles",
                request == null ? java.util.List.of() : request.getExtensionProfiles());
        try {
            return new JWSBuilder().type("JWT").kid(key.getKid()).jsonContent(token).sign(KeyWrapperUtil.createSignatureSignerContext(key));
        } catch (Exception e) {
            throw new FedSetupValidationException("Unable to sign Installation Authorization", e);
        }
    }

    private void validateDispatch(FedSetupInstallation installation, DirectInstallationTrust trust) {
        if (!trust.isActive() || trust.getExpiresAt() > 0 && trust.getExpiresAt() <= Time.currentTime()) {
            throw new FedSetupValidationException("Direct Installation Trust is not active");
        }
        if (!installation.getApplicationTenantId().equals(trust.getApplicationTenantId())
                || !issuer().equals(trust.getIdpIssuer())) {
            throw new FedSetupValidationException("Installation does not match the approved Direct Installation Trust");
        }
        if (trust.getInstallationRuntimeCimdUri() != null && !trust.getInstallationRuntimeCimdUri().isBlank()
                && !cimdUri().equals(trust.getInstallationRuntimeCimdUri())) {
            throw new FedSetupValidationException("Installation does not use this realm's approved CIMD installation runtime");
        }
        if (trust.getConfigurationEndpoint() == null
                || !trust.getConfigurationEndpoint().equals(FedSetupUri.canonicalize(installation.getConfigurationEndpoint()))) {
            throw new FedSetupValidationException("Installation does not use the configuration endpoint approved by Direct Installation Trust");
        }
        if (!trust.getCapabilities().containsAll(installation.getCapabilities())
                || !trust.getExtensionProfiles().containsAll(installation.getExtensionProfiles())) {
            throw new FedSetupValidationException("Installation exceeds the approved Direct Installation Trust");
        }
        URI application = URI.create(trust.getCanonicalApplicationBaseUri());
        URI endpoint = URI.create(installation.getConfigurationEndpoint());
        if (!application.getScheme().equals(endpoint.getScheme()) || !application.getHost().equals(endpoint.getHost())
                || effectivePort(application) != effectivePort(endpoint)) {
            throw new FedSetupValidationException("Configuration endpoint does not use the approved Application origin");
        }
        if (installation.getIdempotencyKey() == null || installation.getIdempotencyKey().isBlank()) {
            installation.setIdempotencyKey(UUID.randomUUID().toString());
        }
    }

    private String issuer() {
        return Urls.realmIssuer(session.getContext().getUri(UrlType.FRONTEND).getBaseUri(), realm.getName());
    }

    private String cimdUri() {
        return FedSetupUrls.cimd(session.getContext().getUri(UrlType.FRONTEND), realm);
    }

    private static int effectivePort(URI uri) {
        return uri.getPort() == -1 ? 443 : uri.getPort();
    }

    /**
     * Maps only client-authentication methods representable by the current
     * Express Configuration OIDC object.  In particular, Keycloak's
     * {@code client-secret-jwt} is HMAC-based and must never be relabelled as
     * {@code private_key_jwt}.
     */
    static String clientAuthenticationMethod(ClientModel client) {
        if (client.isPublicClient() || "none".equals(client.getClientAuthenticatorType())) return "none";
        String authenticator = client.getClientAuthenticatorType();
        if (authenticator == null || "client-secret".equals(authenticator)) return "client_secret_basic";
        return switch (authenticator) {
            case "client-secret-post" -> "client_secret_post";
            case "client-jwt" -> "private_key_jwt";
            default -> throw new FedSetupValidationException("Outbound installation requires a pre-created public, client-secret, or private-key-JWT OIDC client");
        };
    }

    @SuppressWarnings("unchecked")
    private void readScimCredentials(FedSetupInstallation installation, InstallationConfigurationResponse response, boolean create) {
        InstallationConfigurationResponse.ScimResponse scim = response.getScim();
        if (scim.getProvisioningEndpoint() == null || scim.getProvisioningEndpoint().isBlank() || !"Bearer".equals(scim.getTokenType())) {
            throw new FedSetupValidationException("Application returned an invalid SCIM provisioning response");
        }
        if (scim.getFeatures() == null || !new LinkedHashSet<>(scim.getFeatures()).equals(selectedScimFeatures(installation))) {
            throw new FedSetupValidationException("Application returned SCIM features different from the approved Installation");
        }
        if (create && (scim.getAccessToken() == null || scim.getAccessToken().isBlank())) {
            throw new FedSetupValidationException("Application SCIM creation response is missing access_token");
        }
        if (!create && scim.getAccessToken() != null) {
            throw new FedSetupValidationException("Application returned access_token on a SCIM update response");
        }
        if (scim.getAccessToken() != null) storeBootstrapScimCredential(installation, scim.getAccessToken());

        if (!installation.getExtensionProfiles().contains(FedSetupConstants.SCIM_CREDENTIAL_PROFILE_URI)) return;
        Object value = response.getExtensions().get(FedSetupConstants.SCIM_CREDENTIAL_PROFILE_URI);
        if (!(value instanceof Map<?, ?> extension) || !(extension.get("token_endpoint") instanceof String tokenEndpoint)
                || !(extension.get("client_id") instanceof String clientId) || tokenEndpoint.isBlank() || clientId.isBlank()) {
            throw new FedSetupValidationException("Application SCIM response does not include the approved Keycloak SCIM credential extension");
        }
        installation.setScimTokenEndpoint(tokenEndpoint);
        installation.setScimServiceClientId(clientId);
    }

    private static LinkedHashSet<String> selectedScimFeatures(FedSetupInstallation installation) {
        if (!installation.getScimFeatures().isEmpty()) return new LinkedHashSet<>(installation.getScimFeatures());
        // Existing preview installations predate explicit feature selection.
        return new LinkedHashSet<>(java.util.List.of("PUSH_NEW_USERS", "PUSH_USER_DEACTIVATION", "REACTIVATE_USERS",
                "PUSH_PROFILE_UPDATES", "PUSH_GROUPS"));
    }

    static LinkedHashSet<String> effectiveOidcScopes(ClientModel client) {
        LinkedHashSet<String> scopes = new LinkedHashSet<>(java.util.List.of("openid", "profile", "email"));
        scopes.addAll(client.getClientScopes(true).keySet());
        return scopes;
    }

    /** A durable comparison view that never persists an OIDC client secret. */
    static Map<String, String> ssoState(InstallationConfigurationRequest request) {
        Map<String, String> result = new java.util.LinkedHashMap<>(request.getSso());
        String secret = result.remove("client_secret");
        if (secret != null && !secret.isBlank()) result.put("client_secret_sha256", InstallationAuthorizationValidator.sha256(secret));
        if (request.getSaml() != null) {
            // This is the durable drift-detection view, not a protocol
            // serialization.  A stable digest avoids changing it merely
            // because a JSON object supplied the same mapping in another
            // member order.
            Map<String, String> mapping = new java.util.TreeMap<>(request.getSaml().getAttributeMapping());
            result.put("saml_attribute_mapping_sha256", InstallationAuthorizationValidator.sha256(JsonSerialization.valueAsString(mapping)));
            String metadataUrl = request.getSaml().getIdpMetadataUrl();
            if (metadataUrl != null && !metadataUrl.isBlank()) result.put("saml_metadata_url", metadataUrl);
        }
        return result;
    }

    private void storeBootstrapScimCredential(FedSetupInstallation installation, String accessToken) {
        if (installation.getScimCredentialReferenceId() != null) {
            throw new FedSetupValidationException("Application attempted to rotate the SCIM access token outside an administrator-approved installation");
        }
        FedSetupCredentialReference credential = new FedSetupCredentialReference();
        credential.setConnectionId(installation.getId());
        credential.setType("scim-bootstrap-bearer");
        credential = store.createCredentialReference(credential);
        credential.setEncryptedSecret(FedSetupSecretCipher.seal(session, realm, credential.getId(), accessToken));
        // The stored representation is immutable in the current preview; save
        // the complete encrypted value before associating it with the outbox.
        store.replaceCredentialReference(credential);
        installation.setScimCredentialReferenceId(credential.getId());
    }

    private void clearScimCredential(FedSetupInstallation installation) {
        store.deleteCredentialReference(installation.getScimCredentialReferenceId());
        installation.setScimCredentialReferenceId(null);
        installation.setScimEndpoint(null);
        installation.setScimTokenEndpoint(null);
        installation.setScimServiceClientId(null);
    }

    private static String trimTrailingSlash(String value) {
        return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }

    private static String connectionEndpoint(DirectInstallationTrust trust, String configurationEndpoint, String connectionId) {
        if (trust.getConnectionEndpointTemplate() == null || trust.getConnectionEndpointTemplate().isBlank()) {
            // Legacy preview trust records predate the discovery template.
            return trimTrailingSlash(configurationEndpoint) + "/" + pathSegment(connectionId);
        }
        try {
            return UriBuilder.fromUri(trust.getConnectionEndpointTemplate()).build(connectionId).toString();
        } catch (Exception e) {
            throw new FedSetupValidationException("Approved connection endpoint template cannot be expanded", e);
        }
    }

    private static String pathSegment(String value) {
        if (value == null || value.isBlank() || value.contains("/") || value.contains("?")) {
            throw new FedSetupValidationException("Remote connection identifier is invalid");
        }
        return value;
    }

    private static String required(String value, String label) {
        if (value == null || value.isBlank()) throw new FedSetupValidationException(label + " is required");
        return value;
    }

    private static int retryDelay(int attempts) {
        return Math.min(3600, 30 * (1 << Math.min(6, Math.max(0, attempts - 1))));
    }

    private static String safeMessage(Exception error) {
        String message = error.getMessage();
        if (message == null || message.isBlank()) return "Outbound installation request failed";
        return message.length() > 512 ? message.substring(0, 512) : message;
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }

    private static final class MediaType {
        private static final String APPLICATION_JSON = "application/json";
    }
}
