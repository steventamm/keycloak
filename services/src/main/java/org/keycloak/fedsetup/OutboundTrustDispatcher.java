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
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

import jakarta.ws.rs.core.UriBuilder;

import org.keycloak.TokenVerifier;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.fedsetup.representation.DirectInstallationTrust;
import org.keycloak.fedsetup.representation.FedSetupFrontChannelTransaction;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.http.simple.SimpleHttpRequest;
import org.keycloak.http.simple.SimpleHttpResponse;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.Urls;
import org.keycloak.urls.UrlType;
import org.keycloak.util.JsonSerialization;
import org.keycloak.util.KeyWrapperUtil;

import org.apache.http.client.config.RequestConfig;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;

/** IdP-side senders for the IETF Direct Installation Trust profiles. */
public final class OutboundTrustDispatcher {

    private OutboundTrustDispatcher() {
    }

    public static DirectInstallationTrust establishBackChannel(KeycloakSession session, RealmModel realm, RealmFedSetupStore store,
                                                               DirectInstallationTrust trust) {
        validateLocalTrust(session, realm, trust, FedSetupConstants.BACK_CHANNEL_TRUST_PROFILE_URI);
        if (trust.isBackChannelEstablished()) return trust;
        String endpoint = required(trust.getInstallationTrustEndpoint(), "installation_trust_endpoint");
        if (trust.getTrustIdempotencyKey() == null) {
            trust.setTrustIdempotencyKey(UUID.randomUUID().toString());
        }
        String token = trustJwt(session, realm, trust, endpoint);
        // SimpleHttp requires an entity for POST.  A zero-length entity preserves the profile's no-body requirement.
        SimpleHttpRequest request = SimpleHttp.create(session).doPost(endpoint)
                .header("Authorization", "Bearer " + token)
                .header(FedSetupConstants.IDEMPOTENCY_HEADER, trust.getTrustIdempotencyKey())
                .entity(new StringEntity("", ContentType.DEFAULT_TEXT));
        try (SimpleHttpResponse response = request.asResponse()) {
            if (response.getStatus() == 202) {
                PendingResponse pending = pending(response.asString());
                trust.setDeferredPendingId(pending.pendingId());
                return store.updateTrust(trust, trust.getVersion());
            }
            if (response.getStatus() != 201) throw new FedSetupValidationException("Application trust endpoint returned HTTP " + response.getStatus());
            applyConfirmation(trust, confirmation(response.asString(), trust));
            trust.setDeferredPendingId(null);
            trust.setBackChannelEstablished(true);
            return store.updateTrust(trust, trust.getVersion());
        } catch (Exception e) {
            if (e instanceof FedSetupValidationException validation) throw validation;
            throw new FedSetupValidationException("Unable to establish back-channel Direct Installation Trust", e);
        }
    }

    /** Creates browser state and returns the external Application authorization endpoint URI. */
    public static String startFrontChannel(KeycloakSession session, RealmModel realm, RealmFedSetupStore store, DirectInstallationTrust trust) {
        validateLocalTrust(session, realm, trust, FedSetupConstants.FRONT_CHANNEL_TRUST_PROFILE_URI);
        String authorizationEndpoint = required(trust.getInstallationConsentEndpoint(), "installation_consent_endpoint");
        String tokenEndpoint = required(trust.getInstallationConfirmationEndpoint(), "installation_confirmation_endpoint");
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
                .queryParam("authorized_capabilities", String.join(" ", transaction.getCapabilities()))
                .queryParam("provider_delegation_profiles", String.join(" ", transaction.getProviderDelegationProfiles()))
                .queryParam("federation_extension_profiles", String.join(" ", transaction.getFederationExtensionProfiles()))
                .queryParam("scope", "fedsetup:trust")
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
        String proof = confirmationProof(session, realm, trust, code, transaction.getTokenEndpoint());
        SimpleHttpRequest request = SimpleHttp.create(session).doPost(transaction.getTokenEndpoint())
                .header("Authorization", "Bearer " + proof).acceptJson()
                // SimpleHttp requires an entity for POST. A zero-length entity
                // preserves the confirmation endpoint's no-body contract.
                .entity(new StringEntity("", ContentType.DEFAULT_TEXT));
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
        JsonWebToken token = new JsonWebToken().issuer(cimd).subject(cimd).id(UUID.randomUUID().toString())
                .issuedNowWithTTL(FedSetupConstants.MAX_AUTHORIZATION_LIFESPAN_SECONDS).audience(audience);
        token.setOtherClaims("idp_issuer", issuer(session, realm));
        token.setOtherClaims("application_tenant_id", trust.getApplicationTenantId());
        token.setOtherClaims("htm", "POST");
        token.setOtherClaims("htu", audience);
        token.setOtherClaims("request_hash", InstallationAuthorizationValidator.sha256Base64Url(""));
        token.setOtherClaims("authorized_capabilities", new ArrayList<>(trust.getCapabilities()));
        token.setOtherClaims("provider_delegation_profiles", new ArrayList<>(trust.getProviderDelegationProfiles()));
        token.setOtherClaims("federation_extension_profiles", new ArrayList<>(trust.getExtensionProfiles()));
        if (trust.getTrustPreAuthorization() != null && !trust.getTrustPreAuthorization().isBlank()) {
            token.setOtherClaims("trust_pre_authorization", trust.getTrustPreAuthorization());
        } else if (trust.getDeferredPendingId() != null && !trust.getDeferredPendingId().isBlank()) {
            token.setOtherClaims("pending_id", trust.getDeferredPendingId());
        } else if (trust.getInstallationTrustJwksUri() != null && !trust.getInstallationTrustJwksUri().isBlank()) {
            token.setOtherClaims("approval_notification_endpoint", FedSetupUrls.trustNotification(
                    session.getContext().getUri(UrlType.FRONTEND), realm, trust.getId()));
        }
        try {
            return new JWSBuilder().type("JWT").kid(key.getKid()).jsonContent(token).sign(KeyWrapperUtil.createSignatureSignerContext(key));
        } catch (Exception e) {
            throw new FedSetupValidationException("Unable to sign Direct Installation Trust request", e);
        }
    }

    private static String confirmationProof(KeycloakSession session, RealmModel realm, DirectInstallationTrust trust, String code, String audience) {
        KeyWrapper key = session.keys().getActiveKey(realm, KeyUse.SIG, Algorithm.RS256);
        if (key == null) throw new FedSetupValidationException("Realm has no active RS256 signing key");
        String cimd = cimdUri(session, realm);
        JsonWebToken token = new JsonWebToken().issuer(cimd).subject(cimd).audience(audience).id(UUID.randomUUID().toString())
                .issuedNowWithTTL(FedSetupConstants.MAX_AUTHORIZATION_LIFESPAN_SECONDS);
        token.setOtherClaims("idp_issuer", trust.getIdpIssuer());
        token.setOtherClaims("application_tenant_id", trust.getApplicationTenantId());
        token.setOtherClaims("htm", "POST");
        token.setOtherClaims("htu", audience);
        token.setOtherClaims("request_hash", InstallationAuthorizationValidator.sha256Base64Url(""));
        token.setOtherClaims("confirmation_code", code);
        token.setOtherClaims("authorized_capabilities", new ArrayList<>(trust.getCapabilities()));
        token.setOtherClaims("provider_delegation_profiles", new ArrayList<>(trust.getProviderDelegationProfiles()));
        token.setOtherClaims("federation_extension_profiles", new ArrayList<>(trust.getExtensionProfiles()));
        try {
            return new JWSBuilder().type("JWT").kid(key.getKid()).jsonContent(token).sign(KeyWrapperUtil.createSignatureSignerContext(key));
        } catch (Exception e) {
            throw new FedSetupValidationException("Unable to sign the front-channel confirmation proof", e);
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
            Set<String> capabilities = strings(confirmation.get("authorized_capabilities"), "authorized_capabilities");
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

    /** Validates an advisory notification and returns the stored deferred proposal to resume. */
    public static DirectInstallationTrust receiveApprovalNotification(KeycloakSession session, RealmModel realm, RealmFedSetupStore store,
                                                                      String trustId, String compact, String endpoint) {
        DirectInstallationTrust trust = store.requireTrust(trustId);
        if (trust.getDeferredPendingId() == null || trust.getInstallationTrustJwksUri() == null) {
            throw new FedSetupValidationException("No deferred Trust proposal is awaiting notification");
        }
        verifyApprovalNotification(session, trust, compact, endpoint);
        return establishBackChannel(session, realm, store, trust);
    }

    private static void verifyApprovalNotification(KeycloakSession session, DirectInstallationTrust trust, String compact, String endpoint) {
        try {
            JWSInput input = new JWSInput(compact);
            if (!FedSetupConstants.INSTALLATION_SIGNING_ALGORITHM.equals(input.getHeader().getAlgorithm().name())
                    || input.getHeader().getKeyId() == null) {
                throw new FedSetupValidationException("Trust Approval Notification key or algorithm is not trusted");
            }
            java.security.PublicKey key = applicationSigningKey(session, trust.getInstallationTrustJwksUri(), input.getHeader().getKeyId());
            TokenVerifier<JsonWebToken> verifier = TokenVerifier.create(compact, JsonWebToken.class).publicKey(key)
                    .withChecks(TokenVerifier.IS_ACTIVE, token -> Objects.equals(trust.getCanonicalApplicationBaseUri(), token.getIssuer())
                            && token.hasAudience(endpoint));
            verifier.verify();
            JsonWebToken token = verifier.getToken();
            if (!Objects.equals("trust-proposal-updated", token.getOtherClaims().get("event"))
                    || !Objects.equals(trust.getDeferredPendingId(), stringClaim(token, "pending_id"))
                    || !Objects.equals(trust.getApplicationTenantId(), stringClaim(token, "application_tenant_id"))
                    || !Objects.equals(trust.getIdpIssuer(), stringClaim(token, "idp_issuer"))
                    || !Objects.equals(trust.getInstallationRuntimeCimdUri(), stringClaim(token, "cimd_uri"))) {
                throw new FedSetupValidationException("Trust Approval Notification does not match the deferred proposal");
            }
        } catch (FedSetupValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new FedSetupValidationException("Invalid Trust Approval Notification", e);
        }
    }

    private static java.security.PublicKey applicationSigningKey(KeycloakSession session, String jwksUri, String kid) {
        String uri = FedSetupUri.canonicalize(jwksUri);
        FedSetupUri.requirePublicAddress(uri, "Application Trust signing-key source");
        RequestConfig noRedirects = RequestConfig.copy(RequestConfig.DEFAULT).setRedirectsEnabled(false).build();
        try (SimpleHttpResponse response = SimpleHttp.create(session).withRequestConfig(noRedirects).doGet(uri).acceptJson().asResponse()) {
            if (response.getStatus() != 200) throw new FedSetupValidationException("Application Trust signing-key endpoint returned HTTP " + response.getStatus());
            JSONWebKeySet keySet = JsonSerialization.readValue(response.asString(), JSONWebKeySet.class);
            if (keySet == null || keySet.getKeys() == null) throw new FedSetupValidationException("Application Trust signing-key endpoint is empty");
            for (JWK key : keySet.getKeys()) {
                if (Objects.equals(kid, key.getKeyId()) && FedSetupConstants.INSTALLATION_SIGNING_ALGORITHM.equals(key.getAlgorithm())) {
                    return JWKParser.create(key).toPublicKey();
                }
            }
            throw new FedSetupValidationException("Application Trust signing key is not present");
        } catch (FedSetupValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new FedSetupValidationException("Unable to retrieve Application Trust signing keys", e);
        }
    }

    private static PendingResponse pending(String raw) {
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> response = JsonSerialization.readValue(raw, Map.class);
            Object id = response.get("pending_id");
            if (!(id instanceof String pendingId) || pendingId.isBlank()) {
                throw new FedSetupValidationException("Application returned an invalid deferred Trust response");
            }
            return new PendingResponse(pendingId);
        } catch (FedSetupValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new FedSetupValidationException("Application returned an invalid deferred Trust response", e);
        }
    }

    private static String stringClaim(JsonWebToken token, String name) {
        Object value = token.getOtherClaims().get(name);
        if (!(value instanceof String string) || string.isBlank()) throw new FedSetupValidationException("Trust Approval Notification is missing " + name);
        return string;
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

    private record PendingResponse(String pendingId) {
    }
}
