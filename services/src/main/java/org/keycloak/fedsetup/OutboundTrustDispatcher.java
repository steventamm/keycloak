/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import jakarta.ws.rs.core.UriBuilder;

import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.fedsetup.representation.DirectInstallationTrust;
import org.keycloak.fedsetup.representation.FedSetupFrontChannelTransaction;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.http.simple.SimpleHttpRequest;
import org.keycloak.http.simple.SimpleHttpResponse;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.Urls;
import org.keycloak.urls.UrlType;
import org.keycloak.util.JsonSerialization;
import org.keycloak.util.KeyWrapperUtil;

/** IdP-side senders for the IETF Direct Installation Trust profiles. */
public final class OutboundTrustDispatcher {

    private OutboundTrustDispatcher() {
    }

    public static DirectInstallationTrust establishBackChannel(KeycloakSession session, RealmModel realm, RealmFedSetupStore store,
                                                               DirectInstallationTrust trust) {
        validateLocalTrust(session, realm, trust, FedSetupConstants.BACK_CHANNEL_TRUST_PROFILE_URI);
        String endpoint = required(trust.getInstallationTrustEndpoint(), "installation_trust_endpoint");
        String token = trustJwt(session, realm, trust, endpoint);
        // SimpleHttp requires an entity for POST.  A zero-length entity preserves the profile's no-body requirement.
        SimpleHttpRequest request = SimpleHttp.create(session).doPost(endpoint)
                .header("Authorization", "Bearer " + token)
                .header(FedSetupConstants.IDEMPOTENCY_HEADER, UUID.randomUUID().toString())
                .entity(new StringEntity("", ContentType.DEFAULT_TEXT));
        try (SimpleHttpResponse response = request.asResponse()) {
            if (response.getStatus() != 201) throw new FedSetupValidationException("Application trust endpoint returned HTTP " + response.getStatus());
            applyConfirmation(trust, confirmation(response.asString(), trust));
            return store.updateTrust(trust, trust.getVersion());
        } catch (Exception e) {
            if (e instanceof FedSetupValidationException validation) throw validation;
            throw new FedSetupValidationException("Unable to establish back-channel Direct Installation Trust", e);
        }
    }

    /** Creates browser state and returns the external Application authorization endpoint URI. */
    public static String startFrontChannel(KeycloakSession session, RealmModel realm, RealmFedSetupStore store, DirectInstallationTrust trust) {
        validateLocalTrust(session, realm, trust, FedSetupConstants.FRONT_CHANNEL_TRUST_PROFILE_URI);
        String authorizationEndpoint = required(trust.getInstallationAuthorizationEndpoint(), "installation_authorization_endpoint");
        String tokenEndpoint = required(trust.getInstallationTokenEndpoint(), "installation_token_endpoint");
        FedSetupFrontChannelTransaction transaction = new FedSetupFrontChannelTransaction();
        transaction.setTrustId(trust.getId());
        transaction.setApplicationTenantId(trust.getApplicationTenantId());
        transaction.setIdpIssuer(trust.getIdpIssuer());
        transaction.setCimdUri(cimdUri(session, realm));
        transaction.setRedirectUri(FedSetupUrls.frontCallback(session.getContext().getUri(UrlType.FRONTEND), realm));
        transaction.setTokenEndpoint(tokenEndpoint);
        transaction.setState(randomValue());
        transaction.setCapabilities(trust.getCapabilities());
        transaction.setProviderDelegationProfiles(trust.getProviderDelegationProfiles());
        transaction.setFederationExtensionProfiles(trust.getExtensionProfiles());
        transaction.setExpiresAt(Time.currentTime() + FedSetupConstants.MAX_AUTHORIZATION_LIFESPAN_SECONDS);
        transaction = store.createFrontChannelTransaction(transaction);
        return UriBuilder.fromUri(authorizationEndpoint)
                .queryParam("response_type", "code")
                .queryParam("client_id", transaction.getCimdUri())
                .queryParam("idp_issuer", transaction.getIdpIssuer())
                .queryParam("redirect_uri", transaction.getRedirectUri())
                .queryParam("application_tenant_id", transaction.getApplicationTenantId())
                .queryParam("capabilities", String.join(",", transaction.getCapabilities()))
                .queryParam("provider_delegation_profiles", String.join(",", transaction.getProviderDelegationProfiles()))
                .queryParam("federation_extension_profiles", String.join(",", transaction.getFederationExtensionProfiles()))
                .queryParam("scope", "fedsetup-trust")
                .queryParam("state", transaction.getState()).build().toString();
    }

    /** Redeems the code returned to the IdP realm's registered CIMD callback. */
    public static DirectInstallationTrust redeemFrontChannelCode(KeycloakSession session, RealmModel realm, RealmFedSetupStore store,
                                                                  FedSetupFrontChannelTransaction transaction, String code) {
        if (transaction.getTrustId() == null || transaction.getTokenEndpoint() == null || transaction.isConsumed()
                || transaction.getExpiresAt() <= Time.currentTime()) {
            throw new FedSetupValidationException("Front-channel callback transaction is expired or invalid");
        }
        DirectInstallationTrust trust = store.requireTrust(transaction.getTrustId());
        validateLocalTrust(session, realm, trust, FedSetupConstants.FRONT_CHANNEL_TRUST_PROFILE_URI);
        String assertion = clientAssertion(session, realm, transaction.getCimdUri(), transaction.getTokenEndpoint());
        SimpleHttpRequest request = SimpleHttp.create(session).doPost(transaction.getTokenEndpoint())
                .param("grant_type", "authorization_code")
                .param("code", code)
                .param("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .param("client_assertion", assertion).acceptJson();
        try (SimpleHttpResponse response = request.asResponse()) {
            if (response.getStatus() != 200) throw new FedSetupValidationException("Application token endpoint returned HTTP " + response.getStatus());
            applyConfirmation(trust, confirmation(response.asString(), trust));
            transaction.setConsumed(true);
            store.updateFrontChannelTransaction(transaction, transaction.getVersion());
            return store.updateTrust(trust, trust.getVersion());
        } catch (Exception e) {
            if (e instanceof FedSetupValidationException validation) throw validation;
            throw new FedSetupValidationException("Unable to redeem front-channel Direct Installation Trust code", e);
        }
    }

    private static String trustJwt(KeycloakSession session, RealmModel realm, DirectInstallationTrust trust, String audience) {
        KeyWrapper key = session.keys().getActiveKey(realm, KeyUse.SIG, Algorithm.RS256);
        if (key == null) throw new FedSetupValidationException("Realm has no active RS256 signing key");
        String cimd = cimdUri(session, realm);
        JsonWebToken token = new JsonWebToken().issuer(cimd).id(UUID.randomUUID().toString())
                .issuedNowWithTTL(FedSetupConstants.MAX_AUTHORIZATION_LIFESPAN_SECONDS).audience(audience);
        token.setOtherClaims("idp_issuer", issuer(session, realm));
        token.setOtherClaims("application_tenant_id", trust.getApplicationTenantId());
        token.setOtherClaims("capabilities", new ArrayList<>(trust.getCapabilities()));
        token.setOtherClaims("provider_delegation_profiles", new ArrayList<>(trust.getProviderDelegationProfiles()));
        token.setOtherClaims("federation_extension_profiles", new ArrayList<>(trust.getExtensionProfiles()));
        try {
            return new JWSBuilder().type("JWT").kid(key.getKid()).jsonContent(token).sign(KeyWrapperUtil.createSignatureSignerContext(key));
        } catch (Exception e) {
            throw new FedSetupValidationException("Unable to sign Direct Installation Trust request", e);
        }
    }

    private static String clientAssertion(KeycloakSession session, RealmModel realm, String cimd, String audience) {
        KeyWrapper key = session.keys().getActiveKey(realm, KeyUse.SIG, Algorithm.RS256);
        if (key == null) throw new FedSetupValidationException("Realm has no active RS256 signing key");
        JsonWebToken token = new JsonWebToken().issuer(cimd).subject(cimd).audience(audience).id(UUID.randomUUID().toString())
                .issuedNowWithTTL(FedSetupConstants.MAX_AUTHORIZATION_LIFESPAN_SECONDS);
        try {
            return new JWSBuilder().type("JWT").kid(key.getKid()).jsonContent(token).sign(KeyWrapperUtil.createSignatureSignerContext(key));
        } catch (Exception e) {
            throw new FedSetupValidationException("Unable to sign the front-channel client assertion", e);
        }
    }

    private static void validateLocalTrust(KeycloakSession session, RealmModel realm, DirectInstallationTrust trust, String profile) {
        if (trust == null || !trust.isActive() || !profile.equals(trust.getTrustProfileUri())
                || !issuer(session, realm).equals(trust.getIdpIssuer()) || !cimdUri(session, realm).equals(trust.getInstallationRuntimeCimdUri())) {
            throw new FedSetupValidationException("Direct Installation Trust is not approved for this realm's installation runtime and profile");
        }
    }

    private static Confirmation confirmation(String raw, DirectInstallationTrust trust) {
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> confirmation = JsonSerialization.readValue(raw, Map.class);
            if (!trust.getApplicationTenantId().equals(confirmation.get("application_tenant_id"))
                    || !trust.getIdpIssuer().equals(confirmation.get("idp_issuer"))) {
                throw new FedSetupValidationException("Application trust confirmation does not match the requested tenant and issuer");
            }
            Set<String> capabilities = strings(confirmation.get("capabilities"), "capabilities");
            Set<String> providerProfiles = strings(confirmation.get("provider_delegation_profiles"), "provider_delegation_profiles");
            Set<String> federationProfiles = strings(confirmation.get("federation_extension_profiles"), "federation_extension_profiles");
            if (!trust.getCapabilities().containsAll(capabilities)
                    || !trust.getProviderDelegationProfiles().containsAll(providerProfiles)
                    || !trust.getExtensionProfiles().containsAll(federationProfiles)) {
                throw new FedSetupValidationException("Application trust confirmation grants terms not requested by the IdP administrator");
            }
            return new Confirmation(capabilities, providerProfiles, federationProfiles);
        } catch (FedSetupValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new FedSetupValidationException("Application returned an invalid trust confirmation", e);
        }
    }

    private static void applyConfirmation(DirectInstallationTrust trust, Confirmation confirmation) {
        trust.setCapabilities(confirmation.capabilities());
        trust.setProviderDelegationProfiles(confirmation.providerDelegationProfiles());
        trust.setExtensionProfiles(confirmation.federationExtensionProfiles());
    }

    private static Set<String> strings(Object value, String name) {
        if (!(value instanceof Collection<?> values)) throw new FedSetupValidationException("Application trust confirmation is missing " + name);
        Set<String> result = new LinkedHashSet<>();
        for (Object item : values) {
            if (!(item instanceof String string) || string.isBlank()) throw new FedSetupValidationException("Application trust confirmation has invalid " + name);
            result.add(string);
        }
        return result;
    }

    private static String cimdUri(KeycloakSession session, RealmModel realm) {
        return FedSetupUrls.cimd(session.getContext().getUri(UrlType.FRONTEND), realm);
    }

    private static String issuer(KeycloakSession session, RealmModel realm) {
        return Urls.realmIssuer(session.getContext().getUri(UrlType.FRONTEND).getBaseUri(), realm.getName());
    }

    private static String required(String value, String name) {
        if (value == null || value.isBlank()) throw new FedSetupValidationException(name + " is required");
        return value;
    }

    private static String randomValue() {
        byte[] value = new byte[32];
        new java.security.SecureRandom().nextBytes(value);
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private record Confirmation(Set<String> capabilities, Set<String> providerDelegationProfiles,
                                Set<String> federationExtensionProfiles) {
    }
}
