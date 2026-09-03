/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

import org.keycloak.broker.jwtauthorizationgrant.JWTAuthorizationGrantConfig;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.common.Profile;
import org.keycloak.fedsetup.representation.DirectInstallationTrust;
import org.keycloak.fedsetup.representation.FedSetupConfigurationProfile;
import org.keycloak.fedsetup.representation.FedSetupConnection;
import org.keycloak.fedsetup.representation.FedSetupIdJagConfiguration;
import org.keycloak.fedsetup.representation.FedSetupIdJagResourceBinding;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.AudienceProtocolMapper;
import org.keycloak.services.Urls;
import org.keycloak.urls.UrlType;

/**
 * Materializes the bounded, receiver-only ID-JAG support documented in DD-34.
 * All authorization of resource URI, scopes, issuer, and CIMD is performed
 * against realm-local administrator state before native Keycloak grant
 * processing is enabled.
 */
public final class FedSetupIdJagConnectionService {

    public static final String CONNECTION_ATTRIBUTE = "fedsetup.id-jag.connection-id";
    public static final String CIMD_URI_ATTRIBUTE = "fedsetup.id-jag.cimd-uri";
    private static final String MAPPER_PREFIX = "FedSetup ID-JAG audience: ";
    private static final String IDP_ALIAS_PREFIX = "fedsetup-idjag-";

    private FedSetupIdJagConnectionService() {
    }

    /**
     * Validates and canonicalizes a complete id_jag capability object.  A
     * present object replaces the complete prior state; this method retains an
     * existing response-only resource-connection identifier only for the same
     * local resource URI.
     */
    public static FedSetupIdJagConfiguration validate(KeycloakSession session, RealmModel realm,
            FedSetupConfigurationProfile profile, DirectInstallationTrust trust, FedSetupConnection connection,
            FedSetupIdJagConfiguration requested, FedSetupIdJagConfiguration previous) {
        if (!Profile.isFeatureEnabled(Profile.Feature.IDENTITY_ASSERTION_JWT)) {
            throw new FedSetupValidationException("The Identity Assertion JWT preview feature is not enabled");
        }
        if (trust == null || !trust.getCapabilities().contains("id_jag")) {
            throw new FedSetupValidationException("Direct Installation Trust does not authorize id_jag");
        }
        if (requested == null || blank(requested.getClientId()) || blank(requested.getRequesterType())
                || requested.getResourceConnections().isEmpty()) {
            throw new FedSetupValidationException("id_jag requires client_id, requester_type, and at least one resource connection");
        }
        if (!Set.of("app_instance", "workload_principal").contains(requested.getRequesterType())) {
            throw new FedSetupValidationException("id_jag.requester_type must be app_instance or workload_principal");
        }
        if ("app_instance".equals(requested.getRequesterType()) && !isSsoConnection(connection)) {
            throw new FedSetupValidationException("id_jag.requester_type app_instance requires an OIDC or SAML SSO Connection");
        }
        if (blank(requested.getCimdUri())) {
            throw new FedSetupValidationException("id_jag without cimd_uri requires an approved Provider Delegation Profile");
        }
        String canonicalCimd = FedSetupUri.canonicalize(requested.getCimdUri());
        if (!canonicalCimd.equals(FedSetupUri.canonicalize(requested.getClientId()))) {
            throw new FedSetupValidationException("id_jag.cimd_uri must equal id_jag.client_id");
        }
        requested.setClientId(canonicalCimd);
        requested.setCimdUri(canonicalCimd);
        // Verify the document and its public keys before committing a local
        // confidential client that will use it for client authentication.
        FedSetupCimdResolver.validate(session, canonicalCimd);

        Map<String, FedSetupIdJagResourceBinding> bindings = bindings(profile);
        String realmIssuer = FedSetupUri.canonicalize(Urls.realmIssuer(
                session.getContext().getUri(UrlType.FRONTEND).getBaseUri(), realm.getName()));
        Map<String, String> previousIds = previousResourceConnectionIds(previous);
        Set<String> resources = new LinkedHashSet<>();
        List<FedSetupIdJagConfiguration.ResourceConnection> normalized = new ArrayList<>();
        for (FedSetupIdJagConfiguration.ResourceConnection candidate : requested.getResourceConnections()) {
            if (candidate == null || blank(candidate.getResourceIssuer()) || blank(candidate.getResource()) || candidate.getScopes().isEmpty()) {
                throw new FedSetupValidationException("Each ID-JAG resource connection requires resource_issuer, resource, and scopes");
            }
            if (!candidate.getConditions().isEmpty()) {
                throw new FedSetupValidationException("ID-JAG resource connection conditions require an approved Provider Delegation Profile");
            }
            String issuer = FedSetupUri.canonicalize(candidate.getResourceIssuer());
            String resource = FedSetupUri.canonicalize(candidate.getResource());
            if (!realmIssuer.equals(issuer)) {
                throw new FedSetupValidationException("ID-JAG resource_issuer must be this Keycloak realm issuer");
            }
            if (!resources.add(resource)) {
                throw new FedSetupValidationException("An ID-JAG resource may occur in only one resource connection");
            }
            FedSetupIdJagResourceBinding binding = bindings.get(resource);
            if (binding == null) {
                throw new FedSetupValidationException("ID-JAG resource or scope is not approved by the Application Tenant administrator");
            }
            requireApprovedScopes(binding, candidate.getScopes());
            ClientModel resourceClient = realm.getClientByClientId(binding.getClientId());
            if (resourceClient == null || !resourceClient.isEnabled() || !"openid-connect".equals(resourceClient.getProtocol())) {
                throw new FedSetupValidationException("The approved ID-JAG resource client is no longer available");
            }
            for (String scope : candidate.getScopes()) {
                if (KeycloakModelUtils.getClientScopeByName(realm, scope) == null) {
                    throw new FedSetupValidationException("An approved ID-JAG scope is no longer available in this realm");
                }
            }
            FedSetupIdJagConfiguration.ResourceConnection value = new FedSetupIdJagConfiguration.ResourceConnection();
            value.setResourceIssuer(issuer);
            value.setResource(resource);
            value.setScopes(candidate.getScopes());
            value.setResourceConnectionId(previousIds.getOrDefault(resource, "rc_" + UUID.randomUUID().toString().replace("-", "")));
            normalized.add(value);
        }
        requested.setResourceConnections(normalized);
        return requested;
    }

    static void requireApprovedScopes(FedSetupIdJagResourceBinding binding, Set<String> requestedScopes) {
        if (binding == null || requestedScopes == null || !binding.getScopes().containsAll(requestedScopes)) {
            throw new FedSetupValidationException("ID-JAG resource or scope is not approved by the Application Tenant administrator");
        }
    }

    /** Creates or refreshes the managed requesting client and non-login issuer verifier. */
    public static void materialize(KeycloakSession session, RealmModel realm, FedSetupConnection connection,
            DirectInstallationTrust trust, FedSetupConnection previous) {
        FedSetupIdJagConfiguration desired = connection.getIdJag();
        if (desired == null) {
            if (previous != null) deactivate(realm, previous);
            return;
        }
        if (previous != null && previous.getIdJag() != null
                && !Objects.equals(previous.getIdJag().getClientId(), desired.getClientId())) {
            deactivateRequestingClient(realm, previous.getIdJag().getClientId());
        }

        ClientModel client = realm.getClientByClientId(desired.getClientId());
        if (client != null && !Objects.equals(connection.getId(), client.getAttribute(CONNECTION_ATTRIBUTE))) {
            throw new FedSetupValidationException("id_jag.client_id is already used by another local client or FedSetup Connection");
        }
        if (client == null) {
            client = realm.addClient(UUID.randomUUID().toString(), desired.getClientId());
        }
        configureRequestingClient(realm, client, connection, desired);

        // Use the full Connection identifier rather than a truncated prefix: the Connection ID
        // is already unique, and truncating it would introduce an avoidable alias collision risk.
        String alias = previous != null && previous.getIdJagIdentityProviderAlias() != null
                ? previous.getIdJagIdentityProviderAlias() : IDP_ALIAS_PREFIX + connection.getId().replace("-", "");
        materializeIssuerVerifier(session, realm, alias, trust);
        connection.setIdJagIdentityProviderAlias(alias);
        client.setAttribute(OIDCConfigAttributes.JWT_AUTHORIZATION_GRANT_IDP, alias);
    }

    /** Disables, rather than deletes, managed credentials and issuer metadata for audit retention. */
    public static void deactivate(RealmModel realm, FedSetupConnection connection) {
        if (connection == null) return;
        if (connection.getIdJag() != null) deactivateRequestingClient(realm, connection.getIdJag().getClientId());
        if (!blank(connection.getIdJagIdentityProviderAlias())) {
            IdentityProviderModel provider = realm.getIdentityProviderByAlias(connection.getIdJagIdentityProviderAlias());
            if (provider != null) {
                provider.setEnabled(false);
                realm.updateIdentityProvider(provider);
            }
        }
    }

    private static void configureRequestingClient(RealmModel realm, ClientModel client, FedSetupConnection connection,
            FedSetupIdJagConfiguration desired) {
        client.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        client.setEnabled("ACTIVE".equals(connection.getStatus()));
        client.setPublicClient(false);
        client.setBearerOnly(false);
        client.setStandardFlowEnabled(false);
        client.setImplicitFlowEnabled(false);
        client.setDirectAccessGrantsEnabled(false);
        client.setServiceAccountsEnabled(false);
        client.setClientAuthenticatorType(FedSetupIdJagCimdClientAuthenticator.PROVIDER_ID);
        client.setAttribute(CONNECTION_ATTRIBUTE, connection.getId());
        client.setAttribute(CIMD_URI_ATTRIBUTE, desired.getCimdUri());
        client.setAttribute(OIDCConfigAttributes.JWT_AUTHORIZATION_GRANT_ENABLED, Boolean.TRUE.toString());

        // The requesting client receives only optional scopes chosen in the
        // Application profile; realm defaults must not widen the connection.
        new ArrayList<>(client.getClientScopes(true).values()).forEach(client::removeClientScope);
        new ArrayList<>(client.getClientScopes(false).values()).forEach(client::removeClientScope);
        for (String scope : requestedScopes(desired)) {
            ClientScopeModel model = KeycloakModelUtils.getClientScopeByName(realm, scope);
            if (model == null) throw new FedSetupValidationException("Approved ID-JAG scope no longer exists in this realm");
            client.addClientScope(model, false);
        }

        client.getProtocolMappersStream().filter(mapper -> mapper.getName() != null && mapper.getName().startsWith(MAPPER_PREFIX))
                .toList().forEach(client::removeProtocolMapper);
        Set<String> audiences = new LinkedHashSet<>();
        for (FedSetupIdJagConfiguration.ResourceConnection resourceConnection : desired.getResourceConnections()) {
            FedSetupIdJagResourceBinding binding = bindingFor(realm, connection, resourceConnection.getResource());
            if (audiences.add(binding.getClientId())) {
                ProtocolMapperModel mapper = AudienceProtocolMapper.createClaimMapper(MAPPER_PREFIX + binding.getClientId(),
                        binding.getClientId(), null, true, false, true);
                client.addProtocolMapper(mapper);
            }
        }
    }

    private static void materializeIssuerVerifier(KeycloakSession session, RealmModel realm, String alias, DirectInstallationTrust trust) {
        IdentityProviderModel provider = realm.getIdentityProviderByAlias(alias);
        if (provider != null && !"oidc".equals(provider.getProviderId())) {
            throw new FedSetupValidationException("The managed ID-JAG identity-provider alias is already in use");
        }
        if (provider == null) {
            provider = new IdentityProviderModel();
            provider.setAlias(alias);
            provider.setProviderId("oidc");
        }
        String jwksUri = trust.getRuntimeJwksUri();
        if (trust.getInstallationRuntimeCimdUri() != null && !trust.getInstallationRuntimeCimdUri().isBlank()) {
            jwksUri = FedSetupOidcMetadataResolver.resolve(session, trust.getIdpIssuer()).jwksUri();
        }
        if (blank(jwksUri)) {
            throw new FedSetupValidationException("Direct Installation Trust has no approved OIDC JWKS source for ID-JAG");
        }
        Map<String, String> config = new LinkedHashMap<>();
        config.put(IdentityProviderModel.ISSUER, trust.getIdpIssuer());
        config.put(OIDCIdentityProviderConfig.JWKS_URL, jwksUri);
        config.put(OIDCIdentityProviderConfig.USE_JWKS_URL, Boolean.TRUE.toString());
        config.put(OIDCIdentityProviderConfig.VALIDATE_SIGNATURE, Boolean.TRUE.toString());
        config.put(JWTAuthorizationGrantConfig.JWT_AUTHORIZATION_GRANT_ENABLED, Boolean.TRUE.toString());
        config.put(JWTAuthorizationGrantConfig.JWT_AUTHORIZATION_GRANT_ASSERTION_REUSE_ALLOWED, Boolean.FALSE.toString());
        config.put(JWTAuthorizationGrantConfig.JWT_AUTHORIZATION_GRANT_MAX_ALLOWED_ASSERTION_EXPIRATION, "300");
        config.put(JWTAuthorizationGrantConfig.JWT_AUTHORIZATION_GRANT_ASSERTION_SIGNATURE_ALG,
                FedSetupConstants.INSTALLATION_SIGNING_ALGORITHM);
        config.put(JWTAuthorizationGrantConfig.JWT_AUTHORIZATION_GRANT_LIMIT_ACCESS_TOKEN_EXP, Boolean.TRUE.toString());
        provider.setConfig(config);
        provider.setDisplayName("FedSetup ID-JAG " + trust.getIdpIssuer());
        provider.setEnabled(true);
        provider.setHideOnLogin(true);
        provider.setLinkOnly(true);
        if (realm.getIdentityProviderByAlias(alias) == null) realm.addIdentityProvider(provider);
        else realm.updateIdentityProvider(provider);
    }

    private static Map<String, FedSetupIdJagResourceBinding> bindings(FedSetupConfigurationProfile profile) {
        if (profile == null || !profile.getCapabilities().contains("id_jag")) {
            throw new FedSetupValidationException("The Application integration profile does not approve id_jag");
        }
        Map<String, FedSetupIdJagResourceBinding> result = new LinkedHashMap<>();
        for (FedSetupIdJagResourceBinding binding : profile.getIdJagResourceBindings()) {
            if (binding != null && binding.getResource() != null) result.put(binding.getResource(), binding);
        }
        return result;
    }

    private static FedSetupIdJagResourceBinding bindingFor(RealmModel realm, FedSetupConnection connection, String resource) {
        FedSetupConfigurationProfile profile = new RealmFedSetupStore(realm).getApplicationProfile();
        FedSetupIdJagResourceBinding binding = bindings(profile).get(resource);
        if (binding == null) throw new FedSetupValidationException("Approved ID-JAG resource binding no longer exists");
        return binding;
    }

    private static Map<String, String> previousResourceConnectionIds(FedSetupIdJagConfiguration previous) {
        Map<String, String> result = new LinkedHashMap<>();
        if (previous != null) {
            for (FedSetupIdJagConfiguration.ResourceConnection connection : previous.getResourceConnections()) {
                if (connection != null && connection.getResource() != null && connection.getResourceConnectionId() != null) {
                    result.put(connection.getResource(), connection.getResourceConnectionId());
                }
            }
        }
        return result;
    }

    private static Set<String> requestedScopes(FedSetupIdJagConfiguration configuration) {
        Set<String> result = new LinkedHashSet<>();
        for (FedSetupIdJagConfiguration.ResourceConnection connection : configuration.getResourceConnections()) {
            result.addAll(connection.getScopes());
        }
        return result;
    }

    private static boolean isSsoConnection(FedSetupConnection connection) {
        return connection != null && Set.of("oidc", "saml").contains(connection.getProtocol());
    }

    private static void deactivateRequestingClient(RealmModel realm, String clientId) {
        if (blank(clientId)) return;
        ClientModel client = realm.getClientByClientId(clientId);
        if (client != null && client.getAttribute(CONNECTION_ATTRIBUTE) != null) client.setEnabled(false);
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }
}
