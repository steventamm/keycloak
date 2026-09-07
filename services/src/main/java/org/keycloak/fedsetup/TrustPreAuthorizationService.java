/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup;

import java.util.ArrayList;
import java.util.Objects;
import java.util.UUID;

import org.keycloak.TokenVerifier;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.fedsetup.representation.FedSetupConfigurationProfile;
import org.keycloak.fedsetup.representation.FedSetupTrustPreAuthorization;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.util.KeyWrapperUtil;

/** Issues and verifies Application-signed, ticket-safe trust pre-authorizations. */
public final class TrustPreAuthorizationService {

    private TrustPreAuthorizationService() {
    }

    public static String issue(KeycloakSession session, RealmModel realm, FedSetupConfigurationProfile profile,
                               String endpoint, FedSetupTrustPreAuthorization entry) {
        KeyWrapper key = session.keys().getActiveKey(realm, KeyUse.SIG, Algorithm.RS256);
        if (key == null) throw new FedSetupValidationException("Realm has no active RS256 signing key");
        entry.setJti(UUID.randomUUID().toString());
        JsonWebToken token = new JsonWebToken().issuer(profile.getCanonicalBaseUri()).audience(endpoint).id(entry.getJti());
        token.issuedNowWithTTL((int) Math.max(1, entry.getExpiresAt() - Time.currentTime()));
        token.setOtherClaims("application_tenant_id", entry.getApplicationTenantId());
        token.setOtherClaims("idp_issuer", entry.getIdpIssuer());
        token.setOtherClaims("cimd_uri", entry.getCimdUri());
        token.setOtherClaims("authorized_capabilities", new ArrayList<>(entry.getCapabilities()));
        token.setOtherClaims("provider_delegation_profiles", new ArrayList<>(entry.getProviderDelegationProfiles()));
        token.setOtherClaims("federation_extension_profiles", new ArrayList<>(entry.getFederationExtensionProfiles()));
        try {
            return new JWSBuilder().type(FedSetupConstants.TRUST_PRE_AUTHORIZATION_TYPE).kid(key.getKid()).jsonContent(token)
                    .sign(KeyWrapperUtil.createSignatureSignerContext(key));
        } catch (Exception e) {
            throw new FedSetupValidationException("Unable to sign Trust Pre-Authorization", e);
        }
    }

    public static void verify(KeycloakSession session, RealmModel realm, FedSetupConfigurationProfile profile, String endpoint,
                              FedSetupTrustPreAuthorization entry, String compact, String applicationTenantId, String idpIssuer,
                              String cimdUri, java.util.Set<String> capabilities, java.util.Set<String> providerProfiles,
                              java.util.Set<String> federationProfiles) {
        try {
            JWSInput input = new JWSInput(compact);
            if (!FedSetupConstants.TRUST_PRE_AUTHORIZATION_TYPE.equals(input.getHeader().getType())
                    || !FedSetupConstants.INSTALLATION_SIGNING_ALGORITHM.equals(input.getHeader().getAlgorithm().name())
                    || input.getHeader().getKeyId() == null) {
                throw new FedSetupValidationException("Trust Pre-Authorization key, type, or algorithm is not trusted");
            }
            KeyWrapper key = session.keys().getKey(realm, input.getHeader().getKeyId(), KeyUse.SIG, Algorithm.RS256);
            if (key == null) throw new FedSetupValidationException("Trust Pre-Authorization signing key is not retained");
            TokenVerifier<JsonWebToken> verifier = TokenVerifier.create(compact, JsonWebToken.class).publicKey((java.security.PublicKey) key.getPublicKey())
                    .withChecks(TokenVerifier.IS_ACTIVE, token -> Objects.equals(profile.getCanonicalBaseUri(), token.getIssuer())
                            && token.hasAudience(endpoint));
            verifier.verify();
            JsonWebToken token = verifier.getToken();
            if (!Objects.equals(entry.getJti(), token.getId()) || !entry.isActive() || entry.getExpiresAt() <= Time.currentTime()
                    || !Objects.equals(applicationTenantId, claim(token, "application_tenant_id"))
                    || !Objects.equals(idpIssuer, claim(token, "idp_issuer")) || !Objects.equals(cimdUri, claim(token, "cimd_uri"))
                    || !entry.getCapabilities().equals(InstallationAuthorizationValidator.stringSetOrEmpty(token, "authorized_capabilities", "Trust Pre-Authorization"))
                    || !entry.getProviderDelegationProfiles().equals(InstallationAuthorizationValidator.stringSetOrEmpty(token, "provider_delegation_profiles", "Trust Pre-Authorization"))
                    || !entry.getFederationExtensionProfiles().equals(InstallationAuthorizationValidator.stringSetOrEmpty(token, "federation_extension_profiles", "Trust Pre-Authorization"))
                    || !entry.getCapabilities().containsAll(capabilities) || !entry.getProviderDelegationProfiles().containsAll(providerProfiles)
                    || !entry.getFederationExtensionProfiles().containsAll(federationProfiles)) {
                throw new FedSetupValidationException("Trust Establishment Request does not match the active Trust Pre-Authorization");
            }
        } catch (FedSetupValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new FedSetupValidationException("Invalid Trust Pre-Authorization", e);
        }
    }

    private static String claim(JsonWebToken token, String name) {
        return InstallationAuthorizationValidator.stringClaim(token, name, "Trust Pre-Authorization");
    }
}
