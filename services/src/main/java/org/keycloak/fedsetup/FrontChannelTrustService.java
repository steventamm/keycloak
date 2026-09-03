/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup;

import java.util.Objects;

import org.keycloak.common.util.Time;
import org.keycloak.fedsetup.representation.DirectInstallationTrust;
import org.keycloak.fedsetup.representation.FedSetupConfigurationProfile;
import org.keycloak.fedsetup.representation.FedSetupFrontChannelTransaction;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.JsonWebToken;

/** Establishes a trust from the one-time code defined by the front-channel profile. */
public final class FrontChannelTrustService {

    private static final String ASSERTION_REPLAY_PREFIX = "fedsetup.front-channel-client-assertion.";

    private FrontChannelTrustService() {
    }

    public static DirectInstallationTrust redeem(KeycloakSession session, RealmModel realm, RealmFedSetupStore store,
                                                 String code, String clientAssertion, String tokenEndpoint) {
        if (code == null || code.isBlank()) throw new FedSetupValidationException("Authorization code is required");
        if (clientAssertion == null || clientAssertion.isBlank()) throw new FedSetupValidationException("client_assertion is required");
        FedSetupFrontChannelTransaction transaction = store.findFrontChannelTransactionByCodeHash(
                InstallationAuthorizationValidator.sha256Base64Url(code));
        if (transaction == null || transaction.isConsumed() || !transaction.isConsented()
                || transaction.getExpiresAt() <= Time.currentTime()) {
            throw new FedSetupValidationException("Authorization code is invalid, expired, or already used");
        }

        JsonWebToken assertion = InstallationAuthorizationValidator.verifyCimdJwt(session, clientAssertion,
                transaction.getCimdUri(), transaction.getCimdUri(), tokenEndpoint);
        if (!Objects.equals(transaction.getCimdUri(), assertion.getSubject())) {
            throw new FedSetupValidationException("client_assertion subject does not match the CIMD client identifier");
        }
        requireLifetime(assertion);
        long now = Time.currentTime();
        if (!session.singleUseObjects().putIfAbsent(ASSERTION_REPLAY_PREFIX + realm.getId() + "." + assertion.getId(),
                Math.max(1, assertion.getExp() - now))) {
            throw new FedSetupValidationException("client_assertion has already been used");
        }

        FedSetupConfigurationProfile profile = store.getApplicationProfile();
        if (profile == null || !Objects.equals(profile.getApplicationTenantId(), transaction.getApplicationTenantId())) {
            throw new FedSetupValidationException("Application integration profile does not match the authorization code");
        }
        if (store.findTrust(transaction.getApplicationTenantId(), transaction.getIdpIssuer()) != null) {
            throw new FedSetupValidationException("A Direct Installation Trust already exists for this Application Tenant and IdP issuer");
        }

        DirectInstallationTrust trust = new DirectInstallationTrust();
        trust.setApplicationTenantId(transaction.getApplicationTenantId());
        trust.setCanonicalApplicationBaseUri(profile.getCanonicalBaseUri());
        trust.setConfigurationEndpoint(FedSetupUrls.resourceBase(session.getContext().getUri(), realm) + "/connections");
        trust.setConnectionEndpointTemplate(FedSetupUrls.resourceBase(session.getContext().getUri(), realm) + "/connections/{connection_id}");
        trust.setIdpIssuer(transaction.getIdpIssuer());
        trust.setTrustProfileUri(FedSetupConstants.FRONT_CHANNEL_TRUST_PROFILE_URI);
        trust.setInstallationRuntimeCimdUri(transaction.getCimdUri());
        trust.setCapabilities(transaction.getCapabilities());
        trust.setProviderDelegationProfiles(transaction.getProviderDelegationProfiles());
        trust.setExtensionProfiles(transaction.getFederationExtensionProfiles());
        DirectInstallationTrust created = store.createTrust(trust);
        transaction.setConsumed(true);
        store.updateFrontChannelTransaction(transaction, transaction.getVersion());
        return created;
    }

    private static void requireLifetime(JsonWebToken token) {
        if (token.getId() == null || token.getId().isBlank() || token.getIat() == null || token.getExp() == null) {
            throw new FedSetupValidationException("client_assertion is missing jti, iat, or exp");
        }
        long now = Time.currentTime();
        if (token.getExp() <= now || token.getIat() > now + 10
                || token.getExp() - token.getIat() > FedSetupConstants.MAX_AUTHORIZATION_LIFESPAN_SECONDS) {
            throw new FedSetupValidationException("client_assertion lifetime is invalid");
        }
    }
}
