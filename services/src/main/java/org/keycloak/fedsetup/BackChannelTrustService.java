/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup;

import java.util.Objects;
import java.util.Set;

import org.keycloak.common.util.Time;
import org.keycloak.fedsetup.representation.DirectInstallationTrust;
import org.keycloak.fedsetup.representation.FedSetupConfigurationProfile;
import org.keycloak.fedsetup.representation.FedSetupTrustPreAuthorization;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.Urls;

/** Implements Section 5.1's pre-authorized CIMD-backed Trust Establishment Request. */
public final class BackChannelTrustService {

    private static final String REPLAY_PREFIX = "fedsetup.trust-establishment.";

    private BackChannelTrustService() {
    }

    public static DirectInstallationTrust establish(KeycloakSession session, RealmModel realm, RealmFedSetupStore store,
                                                    String authorization, String idempotencyKey, String endpoint) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            throw new FedSetupValidationException("A Bearer Trust Establishment Request is required");
        }
        if (idempotencyKey == null || idempotencyKey.isBlank()) {
            throw new FedSetupValidationException("Idempotency-Key is required for Trust Establishment Request");
        }
        String compact = authorization.substring("Bearer ".length());
        String requestHash = InstallationAuthorizationValidator.sha256(compact);
        JsonWebToken unverified = unverified(compact);
        String cimdUri = requiredIssuer(unverified);
        String idpIssuer = InstallationAuthorizationValidator.stringClaim(unverified, "idp_issuer", "Trust Establishment Request");
        String applicationTenantId = InstallationAuthorizationValidator.stringClaim(unverified, "application_tenant_id",
                "Trust Establishment Request");
        String canonicalIdpIssuer = FedSetupUri.canonicalize(idpIssuer);
        String existingId = store.getIdempotencyResult("trust:" + idempotencyKey, applicationTenantId, canonicalIdpIssuer, requestHash);
        if (existingId != null) return store.requireTrust(existingId);
        FedSetupTrustPreAuthorization preAuthorization = store.findTrustPreAuthorization(applicationTenantId,
                canonicalIdpIssuer, FedSetupUri.canonicalize(cimdUri));
        if (preAuthorization == null || preAuthorization.getExpiresAt() <= Time.currentTime()) {
            throw new FedSetupValidationException("No active Direct Installation Trust pre-authorization matches this request");
        }

        JsonWebToken token = InstallationAuthorizationValidator.verifyCimdJwt(session, compact, preAuthorization.getCimdUri(),
                preAuthorization.getCimdUri(), endpoint);
        idpIssuer = FedSetupUri.canonicalize(InstallationAuthorizationValidator.stringClaim(token, "idp_issuer",
                "Trust Establishment Request"));
        applicationTenantId = InstallationAuthorizationValidator.stringClaim(token, "application_tenant_id",
                "Trust Establishment Request");
        if (!Objects.equals(preAuthorization.getIdpIssuer(), idpIssuer)
                || !Objects.equals(preAuthorization.getApplicationTenantId(), applicationTenantId)) {
            throw new FedSetupValidationException("Trust Establishment Request does not match the pre-authorization");
        }
        InstallationAuthorizationValidator.requireLifetime(token, "Trust Establishment Request");
        if (!"POST".equals(InstallationAuthorizationValidator.stringClaim(token, "htm", "Trust Establishment Request"))
                || !Objects.equals(endpoint, InstallationAuthorizationValidator.stringClaim(token, "htu", "Trust Establishment Request"))
                || !Objects.equals(InstallationAuthorizationValidator.sha256Base64Url(""),
                        InstallationAuthorizationValidator.stringClaim(token, "request_hash", "Trust Establishment Request"))) {
            throw new FedSetupValidationException("Trust Establishment Request is not bound to this endpoint");
        }
        Set<String> capabilities = InstallationAuthorizationValidator.stringSetOrEmpty(token, "authorized_capabilities",
                "Trust Establishment Request");
        Set<String> providerProfiles = InstallationAuthorizationValidator.stringSetOrEmpty(token, "provider_delegation_profiles",
                "Trust Establishment Request");
        Set<String> federationProfiles = InstallationAuthorizationValidator.stringSetOrEmpty(token, "federation_extension_profiles",
                "Trust Establishment Request");
        if (!preAuthorization.getCapabilities().containsAll(capabilities)
                || !preAuthorization.getProviderDelegationProfiles().containsAll(providerProfiles)
                || !preAuthorization.getFederationExtensionProfiles().containsAll(federationProfiles)) {
            throw new FedSetupValidationException("Trust Establishment Request exceeds the pre-authorization");
        }

        long now = Time.currentTime();
        if (!session.singleUseObjects().putIfAbsent(REPLAY_PREFIX + realm.getId() + "." + token.getId(),
                Math.max(1, token.getExp() - now))) {
            throw new FedSetupValidationException("Trust Establishment Request has already been used");
        }

        FedSetupConfigurationProfile profile = store.getApplicationProfile();
        if (profile == null || !applicationTenantId.equals(profile.getApplicationTenantId())) {
            throw new FedSetupValidationException("Application integration profile does not match Trust Establishment Request");
        }
        DirectInstallationTrust trust = new DirectInstallationTrust();
        trust.setApplicationTenantId(applicationTenantId);
        trust.setCanonicalApplicationBaseUri(profile.getCanonicalBaseUri());
        trust.setAuthorizationServer(Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));
        trust.setConfigurationEndpoint(FedSetupUrls.resourceBase(session.getContext().getUri(), realm) + "/connections");
        trust.setConfigurationResource(FedSetupUrls.resourceBase(session.getContext().getUri(), realm));
        trust.setConnectionEndpointTemplate(FedSetupUrls.resourceBase(session.getContext().getUri(), realm) + "/connections/{connection_id}");
        trust.setIdpIssuer(idpIssuer);
        trust.setTrustProfileUri(FedSetupConstants.BACK_CHANNEL_TRUST_PROFILE_URI);
        trust.setInstallationRuntimeCimdUri(preAuthorization.getCimdUri());
        trust.setCapabilities(capabilities);
        trust.setProviderDelegationProfiles(providerProfiles);
        trust.setExtensionProfiles(federationProfiles);
        DirectInstallationTrust created = store.createTrust(trust);
        FedSetupConfigurationClientService.authorize(session, realm, created);
        preAuthorization.setConsumed(true);
        store.updateTrustPreAuthorization(preAuthorization, preAuthorization.getVersion());
        store.putIdempotencyResult("trust:" + idempotencyKey, applicationTenantId, idpIssuer, created.getId(), requestHash);
        return created;
    }

    private static JsonWebToken unverified(String compact) {
        try {
            return new JWSInput(compact).readJsonContent(JsonWebToken.class);
        } catch (Exception e) {
            throw new FedSetupValidationException("Invalid Trust Establishment Request", e);
        }
    }

    private static String requiredIssuer(JsonWebToken token) {
        if (token.getIssuer() == null || token.getIssuer().isBlank()) {
            throw new FedSetupValidationException("Trust Establishment Request is missing iss");
        }
        return token.getIssuer();
    }

}
