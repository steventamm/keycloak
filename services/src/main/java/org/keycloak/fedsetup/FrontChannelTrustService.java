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
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.Urls;

/** Establishes a trust from the one-time code defined by the front-channel profile. */
public final class FrontChannelTrustService {

    private static final String ASSERTION_REPLAY_PREFIX = "fedsetup.front-channel-client-assertion.";

    private FrontChannelTrustService() {
    }

    public static DirectInstallationTrust redeem(KeycloakSession session, RealmModel realm, RealmFedSetupStore store,
                                                 String authorization, String confirmationEndpoint) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            throw new FedSetupValidationException("A Bearer Trust Establishment Authorization is required");
        }
        String proof = authorization.substring("Bearer ".length());
        JsonWebToken unverified;
        try {
            unverified = new JWSInput(proof).readJsonContent(JsonWebToken.class);
        } catch (Exception e) {
            throw new FedSetupValidationException("Invalid Front-channel confirmation proof", e);
        }
        String code = InstallationAuthorizationValidator.stringClaim(unverified, "confirmation_code", "Confirmation proof");
        FedSetupFrontChannelTransaction transaction = store.findFrontChannelTransactionByCodeHash(
                InstallationAuthorizationValidator.sha256Base64Url(code));
        if (transaction == null || transaction.isConsumed() || !transaction.isConsented()
                || transaction.getExpiresAt() <= Time.currentTime()) {
            throw new FedSetupValidationException("Authorization code is invalid, expired, or already used");
        }

        JsonWebToken assertion = InstallationAuthorizationValidator.verifyCimdJwt(session, proof,
                transaction.getCimdUri(), transaction.getCimdUri(), confirmationEndpoint);
        if (!Objects.equals(transaction.getCimdUri(), assertion.getSubject())) {
            throw new FedSetupValidationException("Confirmation proof subject does not match the CIMD client identifier");
        }
        if (!Objects.equals(transaction.getIdpIssuer(), InstallationAuthorizationValidator.stringClaim(assertion, "idp_issuer", "Confirmation proof"))
                || !Objects.equals(transaction.getApplicationTenantId(), InstallationAuthorizationValidator.stringClaim(assertion,
                        "application_tenant_id", "Confirmation proof"))
                || !"POST".equals(InstallationAuthorizationValidator.stringClaim(assertion, "htm", "Confirmation proof"))
                || !Objects.equals(confirmationEndpoint, InstallationAuthorizationValidator.stringClaim(assertion, "htu", "Confirmation proof"))
                || !Objects.equals(InstallationAuthorizationValidator.sha256Base64Url(""),
                        InstallationAuthorizationValidator.stringClaim(assertion, "request_hash", "Confirmation proof"))
                || !Objects.equals(transaction.getCapabilities(), InstallationAuthorizationValidator.stringSetOrEmpty(assertion,
                        "authorized_capabilities", "Confirmation proof"))
                || !Objects.equals(transaction.getProviderDelegationProfiles(), InstallationAuthorizationValidator.stringSetOrEmpty(assertion,
                        "provider_delegation_profiles", "Confirmation proof"))
                || !Objects.equals(transaction.getFederationExtensionProfiles(), InstallationAuthorizationValidator.stringSetOrEmpty(assertion,
                        "federation_extension_profiles", "Confirmation proof"))) {
            throw new FedSetupValidationException("Confirmation proof does not match the approved transaction");
        }
        InstallationAuthorizationValidator.requireLifetime(assertion, "Confirmation proof");
        long now = Time.currentTime();
        if (!session.singleUseObjects().putIfAbsent(ASSERTION_REPLAY_PREFIX + realm.getId() + "." + assertion.getId(),
                Math.max(1, assertion.getExp() - now))) {
            throw new FedSetupValidationException("Confirmation proof has already been used");
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
        trust.setAuthorizationServer(Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));
        trust.setConfigurationEndpoint(FedSetupUrls.resourceBase(session.getContext().getUri(), realm) + "/connections");
        trust.setConfigurationResource(FedSetupUrls.resourceBase(session.getContext().getUri(), realm));
        trust.setConnectionEndpointTemplate(FedSetupUrls.resourceBase(session.getContext().getUri(), realm) + "/connections/{connection_id}");
        trust.setIdpIssuer(transaction.getIdpIssuer());
        trust.setTrustProfileUri(FedSetupConstants.FRONT_CHANNEL_TRUST_PROFILE_URI);
        trust.setInstallationRuntimeCimdUri(transaction.getCimdUri());
        trust.setCapabilities(transaction.getCapabilities());
        trust.setProviderDelegationProfiles(transaction.getProviderDelegationProfiles());
        trust.setExtensionProfiles(transaction.getFederationExtensionProfiles());
        DirectInstallationTrust created = store.createTrust(trust);
        FedSetupConfigurationClientService.authorize(session, realm, created);
        transaction.setConsumed(true);
        store.updateFrontChannelTransaction(transaction, transaction.getVersion());
        return created;
    }

}
