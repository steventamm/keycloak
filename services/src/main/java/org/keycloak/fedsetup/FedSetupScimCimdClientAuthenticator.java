/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup;

import java.util.Objects;

import jakarta.ws.rs.core.Response;

import org.keycloak.Config;
import org.keycloak.OAuthErrorException;
import org.keycloak.TokenVerifier;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.ClientAuthenticationFlowContext;
import org.keycloak.authentication.authenticators.client.AbstractClientAuthenticator;
import org.keycloak.authentication.authenticators.client.AbstractJWTClientValidator;
import org.keycloak.authentication.authenticators.client.ClientAssertionState;
import org.keycloak.authentication.authenticators.client.ClientAuthUtil;
import org.keycloak.authentication.authenticators.client.JWTClientValidator;
import org.keycloak.common.Profile;
import org.keycloak.events.Details;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.EnvironmentDependentProviderFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.JsonWebToken;

/**
 * Connection-scoped SCIM client authentication with a dynamically resolved
 * CIMD key.  It preserves the standard private_key_jwt claim validation while
 * replacing the static client certificate lookup with the key source bound by
 * Direct Installation Trust.
 */
public final class FedSetupScimCimdClientAuthenticator extends AbstractClientAuthenticator implements EnvironmentDependentProviderFactory {

    public static final String PROVIDER_ID = "fedsetup-cimd-client-jwt";

    @Override
    public void authenticateClient(ClientAuthenticationFlowContext context) {
        context.attempted();
        try {
            ClientAssertionState state = context.getState(ClientAssertionState.class, ClientAssertionState.supplier());
            JsonWebToken token = state.getToken();
            if (token != null && !Objects.equals(token.getIssuer(), token.getSubject())) return;
            if (token != null && state.getClient() == null) state.setClient(context.getRealm().getClientByClientId(token.getSubject()));
            JWTClientValidator validator = new JWTClientValidator(context, this::verifySignature, getId());
            if (validator.validate()) context.success();
        } catch (Exception e) {
            Response challenge = ClientAuthUtil.errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), OAuthErrorException.INVALID_CLIENT,
                    "FedSetup SCIM client assertion validation failed: " + e.getMessage());
            context.failure(AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS, challenge);
        }
    }

    private boolean verifySignature(AbstractJWTClientValidator validator) {
        try {
            ClientAuthenticationFlowContext context = validator.getContext();
            ClientModel client = validator.getClient();
            if (client == null) return false;
            String connectionId = client.getAttribute(FedSetupScimConnectionService.CONNECTION_ATTRIBUTE);
            FedSetupConnectionState state = trustForConnection(context.getRealm(), connectionId);
            if (state == null) return false;
            JWSInput jws = context.getState(ClientAssertionState.class, ClientAssertionState.supplier()).getJws();
            if (jws == null || jws.getHeader().getKeyId() == null || jws.getHeader().getAlgorithm() == null
                    || !FedSetupConstants.INSTALLATION_SIGNING_ALGORITHM.equals(jws.getHeader().getAlgorithm().name())) return false;
            FedSetupCimdResolver.ResolvedCimd key = FedSetupCimdResolver.resolve(context.getSession(), state.cimdUri(),
                    jws.getHeader().getKeyId(), jws.getHeader().getAlgorithm().name());
            TokenVerifier<JsonWebToken> verifier = TokenVerifier.create(
                    context.getState(ClientAssertionState.class, ClientAssertionState.supplier()).getClientAssertion(), JsonWebToken.class);
            verifier.publicKey(key.publicKey()).withChecks(TokenVerifier.IS_ACTIVE);
            verifier.verify();
            context.getEvent().detail(Details.CLIENT_JWT_KID, key.jwk().getKeyId());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private FedSetupConnectionState trustForConnection(RealmModel realm, String connectionId) {
        if (connectionId == null || connectionId.isBlank()) return null;
        RealmFedSetupStore store = new RealmFedSetupStore(realm);
        var connection = store.getConnection(connectionId);
        if (connection == null || !"ACTIVE".equals(connection.getStatus()) || !connection.getCapabilities().contains("scim")) return null;
        var trust = store.getTrust(connection.getTrustId());
        if (trust == null || !trust.isActive() || trust.getInstallationRuntimeCimdUri() == null || trust.getInstallationRuntimeCimdUri().isBlank()) return null;
        return new FedSetupConnectionState(trust.getInstallationRuntimeCimdUri());
    }

    @Override public String getId() { return PROVIDER_ID; }
    @Override public boolean isSupported(Config.Scope config) { return Profile.isFeatureEnabled(Profile.Feature.FED_SETUP_CONFIGURATION); }
    @Override public String getDisplayType() { return "FedSetup CIMD signed JWT"; }
    @Override public String getHelpText() { return "Connection-scoped SCIM client assertion verified with the Direct Installation Trust CIMD key source"; }
    @Override public boolean isConfigurable() { return false; }
    @Override public AuthenticationExecutionModel.Requirement[] getRequirementChoices() { return REQUIREMENT_CHOICES; }
    @Override public java.util.List<ProviderConfigProperty> getConfigProperties() { return java.util.List.of(); }
    @Override public java.util.List<ProviderConfigProperty> getConfigPropertiesPerClient() { return java.util.List.of(); }
    @Override public java.util.Map<String, Object> getAdapterConfiguration(KeycloakSession session, ClientModel client) { return java.util.Map.of(); }
    @Override public java.util.Set<String> getProtocolAuthenticatorMethods(String loginProtocol) { return java.util.Set.of(); }

    private record FedSetupConnectionState(String cimdUri) {
    }
}
