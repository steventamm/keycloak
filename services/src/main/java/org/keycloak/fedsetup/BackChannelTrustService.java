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
import org.keycloak.fedsetup.representation.FedSetupPendingTrustAuthorization;
import org.keycloak.fedsetup.representation.FedSetupTrustPreAuthorization;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.Urls;

/** Implements the Back-Channel Direct Installation Trust profile. */
public final class BackChannelTrustService {

    private static final String REPLAY_PREFIX = "fedsetup.trust-establishment.";

    private BackChannelTrustService() {
    }

    public static Result establish(KeycloakSession session, RealmModel realm, RealmFedSetupStore store,
                                   String authorization, String idempotencyKey, String endpoint) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            throw new FedSetupValidationException("A Bearer Trust Establishment Request is required");
        }
        if (idempotencyKey == null || idempotencyKey.isBlank()) {
            throw new FedSetupValidationException("Idempotency-Key is required for Trust Establishment Request");
        }
        String compact = authorization.substring("Bearer ".length());
        JsonWebToken unverified = unverified(compact);
        String cimdUri = FedSetupUri.canonicalize(requiredIssuer(unverified));
        String idpIssuer = FedSetupUri.canonicalize(InstallationAuthorizationValidator.stringClaim(unverified, "idp_issuer",
                "Trust Establishment Request"));
        String applicationTenantId = InstallationAuthorizationValidator.stringClaim(unverified, "application_tenant_id",
                "Trust Establishment Request");
        String preAuthorization = optionalString(unverified, "trust_pre_authorization");
        String pendingId = optionalString(unverified, "pending_id");
        String notificationEndpoint = optionalString(unverified, "approval_notification_endpoint");
        if (preAuthorization != null && pendingId != null || notificationEndpoint != null && (preAuthorization != null || pendingId != null)) {
            throw new FedSetupValidationException("Trust Establishment Request has mutually exclusive deferred-approval claims");
        }
        if (preAuthorization != null) {
            FedSetupTrustPreAuthorization entry = store.findTrustPreAuthorization(applicationTenantId, idpIssuer, cimdUri);
            if (entry == null) throw new FedSetupValidationException("No active Direct Installation Trust authorization matches this request");
            return establishPreAuthorized(session, realm, store, compact, endpoint, entry, applicationTenantId, idpIssuer);
        }
        return establishDeferred(session, realm, store, compact, idempotencyKey, endpoint, applicationTenantId, idpIssuer, cimdUri,
                pendingId, notificationEndpoint);
    }

    private static Result establishPreAuthorized(KeycloakSession session, RealmModel realm, RealmFedSetupStore store, String compact,
                                                  String endpoint, FedSetupTrustPreAuthorization entry, String applicationTenantId,
                                                  String idpIssuer) {
        JsonWebToken token = validateRuntimeJwt(session, realm, compact, entry.getCimdUri(), endpoint, applicationTenantId, idpIssuer);
        Set<String> capabilities = terms(token, "authorized_capabilities");
        Set<String> providerProfiles = terms(token, "provider_delegation_profiles");
        Set<String> federationProfiles = terms(token, "federation_extension_profiles");
        FedSetupConfigurationProfile profile = requireProfile(store, applicationTenantId);
        TrustPreAuthorizationService.verify(session, realm, profile, endpoint, entry,
                optionalString(token, "trust_pre_authorization"), applicationTenantId, idpIssuer, entry.getCimdUri(), capabilities,
                providerProfiles, federationProfiles);
        consumeRuntimeJti(session, realm, token);
        return Result.established(existingOrCreateTrust(session, realm, store, applicationTenantId, idpIssuer, entry.getCimdUri(),
                capabilities, providerProfiles, federationProfiles));
    }

    private static Result establishDeferred(KeycloakSession session, RealmModel realm, RealmFedSetupStore store, String compact,
                                            String idempotencyKey, String endpoint, String applicationTenantId, String idpIssuer,
                                            String cimdUri, String pendingId, String notificationEndpoint) {
        FedSetupConfigurationProfile profile = requireProfile(store, applicationTenantId);
        if (notificationEndpoint != null) {
            notificationEndpoint = FedSetupUri.canonicalize(notificationEndpoint);
            FedSetupUri.requirePublicAddress(notificationEndpoint, "Approval notification endpoint");
        }
        FedSetupIdpRuntimeBinding.requireBound(session, store, idpIssuer, cimdUri);
        JsonWebToken token = validateRuntimeJwt(session, realm, compact, cimdUri, endpoint, applicationTenantId, idpIssuer);
        Set<String> capabilities = terms(token, "authorized_capabilities");
        Set<String> providerProfiles = terms(token, "provider_delegation_profiles");
        Set<String> federationProfiles = terms(token, "federation_extension_profiles");
        requireRequestedScope(profile, capabilities, federationProfiles);
        if (!providerProfiles.isEmpty()) throw new FedSetupValidationException("Provider delegation profiles are not supported");
        consumeRuntimeJti(session, realm, token);

        FedSetupPendingTrustAuthorization pending = store.findPendingTrustAuthorization(idempotencyKey, applicationTenantId, idpIssuer);
        if (pending != null) {
            if (!sameBinding(pending, cimdUri, capabilities, providerProfiles, federationProfiles)) {
                throw new FedSetupValidationException("Idempotency-Key conflicts with a different Trust binding or requested scope");
            }
            if (pendingId != null && !pendingId.equals(pending.getPendingId())) {
                throw new FedSetupValidationException("pending_id does not match the Idempotency-Key operation");
            }
            expireIfNecessary(store, pending);
            if ("APPROVED".equals(pending.getStatus())) return Result.established(store.requireTrust(pending.getTrustId()));
            if (!"PENDING".equals(pending.getStatus())) {
                throw new FedSetupValidationException("No active Direct Installation Trust authorization matches this request");
            }
            if (pendingId != null && pending.getNextPollAt() > Time.currentTime()) {
                throw new FedSetupRateLimitException(pending.getNextPollAt() - Time.currentTime());
            }
            if (pendingId != null) {
                pending.setNextPollAt(Time.currentTime() + FedSetupConstants.PENDING_TRUST_POLL_INTERVAL_SECONDS);
                pending = store.updatePendingTrustAuthorization(pending, pending.getVersion());
            }
            return Result.pending(pending);
        }
        if (pendingId != null) throw new FedSetupValidationException("pending_id does not identify a pending Trust authorization");
        if (notificationEndpoint != null && !hasApplicationSigningKeys(session, realm)) {
            throw new FedSetupValidationException("Application does not publish approval notification signing keys");
        }
        FedSetupPendingTrustAuthorization created = new FedSetupPendingTrustAuthorization();
        created.setApplicationTenantId(applicationTenantId);
        created.setIdpIssuer(idpIssuer);
        created.setCimdUri(cimdUri);
        created.setRuntimeKeyId(keyId(compact));
        created.setOriginalIdempotencyKey(idempotencyKey);
        created.setCapabilities(capabilities);
        created.setProviderDelegationProfiles(providerProfiles);
        created.setFederationExtensionProfiles(federationProfiles);
        created.setApprovalNotificationEndpoint(notificationEndpoint);
        created.setStatus("PENDING");
        created.setExpiresAt(Time.currentTime() + FedSetupConstants.DEFAULT_PENDING_TRUST_LIFESPAN_SECONDS);
        created.setNextPollAt(Time.currentTime() + FedSetupConstants.PENDING_TRUST_POLL_INTERVAL_SECONDS);
        return Result.pending(store.createPendingTrustAuthorization(created));
    }

    public static DirectInstallationTrust approve(KeycloakSession session, RealmModel realm, RealmFedSetupStore store,
                                                   FedSetupPendingTrustAuthorization pending) {
        expireIfNecessary(store, pending);
        if (!"PENDING".equals(pending.getStatus())) {
            throw new FedSetupValidationException("Pending Direct Installation Trust authorization is not active");
        }
        DirectInstallationTrust trust = existingOrCreateTrust(session, realm, store, pending.getApplicationTenantId(), pending.getIdpIssuer(),
                pending.getCimdUri(), pending.getCapabilities(), pending.getProviderDelegationProfiles(), pending.getFederationExtensionProfiles());
        pending.setTrustId(trust.getId());
        pending.setStatus("APPROVED");
        store.updatePendingTrustAuthorization(pending, pending.getVersion());
        return trust;
    }

    private static void expireIfNecessary(RealmFedSetupStore store, FedSetupPendingTrustAuthorization pending) {
        if ("PENDING".equals(pending.getStatus()) && pending.getExpiresAt() <= Time.currentTime()) {
            pending.setStatus("EXPIRED");
            pending.setApprovalNotificationEndpoint(null);
            store.updatePendingTrustAuthorization(pending, pending.getVersion());
        }
    }

    private static DirectInstallationTrust existingOrCreateTrust(KeycloakSession session, RealmModel realm, RealmFedSetupStore store,
                                                                  String applicationTenantId, String idpIssuer, String cimdUri,
                                                                  Set<String> capabilities, Set<String> providerProfiles,
                                                                  Set<String> federationProfiles) {
        DirectInstallationTrust existing = store.findTrust(applicationTenantId, idpIssuer);
        if (existing != null) {
            if (Objects.equals(existing.getInstallationRuntimeCimdUri(), cimdUri) && existing.getCapabilities().equals(capabilities)
                    && existing.getProviderDelegationProfiles().equals(providerProfiles) && existing.getExtensionProfiles().equals(federationProfiles)) {
                return existing;
            }
            throw new FedSetupValidationException("A Direct Installation Trust already exists for this Application Tenant and IdP issuer");
        }
        return createTrust(session, realm, store, applicationTenantId, idpIssuer, cimdUri, capabilities, providerProfiles, federationProfiles);
    }

    private static DirectInstallationTrust createTrust(KeycloakSession session, RealmModel realm, RealmFedSetupStore store,
                                                        String applicationTenantId, String idpIssuer, String cimdUri,
                                                        Set<String> capabilities, Set<String> providerProfiles, Set<String> federationProfiles) {
        FedSetupConfigurationProfile profile = requireProfile(store, applicationTenantId);
        requireRequestedScope(profile, capabilities, federationProfiles);
        if (!providerProfiles.isEmpty()) throw new FedSetupValidationException("Provider delegation profiles are not supported");
        DirectInstallationTrust trust = new DirectInstallationTrust();
        trust.setApplicationTenantId(applicationTenantId);
        trust.setCanonicalApplicationBaseUri(profile.getCanonicalBaseUri());
        trust.setAuthorizationServer(Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));
        trust.setConfigurationEndpoint(FedSetupUrls.resourceBase(session.getContext().getUri(), realm) + "/connections");
        trust.setConfigurationResource(FedSetupUrls.resourceBase(session.getContext().getUri(), realm));
        trust.setConnectionEndpointTemplate(FedSetupUrls.resourceBase(session.getContext().getUri(), realm) + "/connections/{connection_id}");
        trust.setIdpIssuer(idpIssuer);
        trust.setTrustProfileUri(FedSetupConstants.BACK_CHANNEL_TRUST_PROFILE_URI);
        trust.setInstallationRuntimeCimdUri(cimdUri);
        trust.setCapabilities(capabilities);
        trust.setProviderDelegationProfiles(providerProfiles);
        trust.setExtensionProfiles(federationProfiles);
        DirectInstallationTrust created = store.createTrust(trust);
        FedSetupConfigurationClientService.authorize(session, realm, created);
        return created;
    }

    private static JsonWebToken validateRuntimeJwt(KeycloakSession session, RealmModel realm, String compact, String cimdUri, String endpoint,
                                                    String applicationTenantId, String idpIssuer) {
        JsonWebToken token = InstallationAuthorizationValidator.verifyCimdJwt(session, compact, cimdUri, cimdUri, endpoint);
        InstallationAuthorizationValidator.requireLifetime(token, "Trust Establishment Request");
        if (!Objects.equals(cimdUri, token.getSubject())
                || !Objects.equals(applicationTenantId, InstallationAuthorizationValidator.stringClaim(token, "application_tenant_id", "Trust Establishment Request"))
                || !Objects.equals(idpIssuer, FedSetupUri.canonicalize(InstallationAuthorizationValidator.stringClaim(token, "idp_issuer", "Trust Establishment Request")))
                || !"POST".equals(InstallationAuthorizationValidator.stringClaim(token, "htm", "Trust Establishment Request"))
                || !Objects.equals(endpoint, InstallationAuthorizationValidator.stringClaim(token, "htu", "Trust Establishment Request"))
                || !Objects.equals(InstallationAuthorizationValidator.sha256Base64Url(""),
                        InstallationAuthorizationValidator.stringClaim(token, "request_hash", "Trust Establishment Request"))) {
            throw new FedSetupValidationException("Trust Establishment Request is not bound to this endpoint");
        }
        return token;
    }

    private static void requireRequestedScope(FedSetupConfigurationProfile profile, Set<String> capabilities, Set<String> federationProfiles) {
        if (!profile.getCapabilities().containsAll(capabilities) || !profile.getExtensionProfiles().containsAll(federationProfiles)) {
            throw new FedSetupValidationException("Trust Establishment Request exceeds the Application integration profile");
        }
    }

    private static FedSetupConfigurationProfile requireProfile(RealmFedSetupStore store, String applicationTenantId) {
        FedSetupConfigurationProfile profile = store.getApplicationProfile();
        if (profile == null || !applicationTenantId.equals(profile.getApplicationTenantId())) {
            throw new FedSetupValidationException("No active Direct Installation Trust authorization matches this request");
        }
        return profile;
    }

    private static void consumeRuntimeJti(KeycloakSession session, RealmModel realm, JsonWebToken token) {
        long remainingLifetime = token.getExp() - Time.currentTime();
        if (remainingLifetime <= 0 || !session.singleUseObjects().putIfAbsent(REPLAY_PREFIX + realm.getId() + "." + token.getId(), remainingLifetime)) {
            throw new FedSetupValidationException("Trust Establishment Request has already been used");
        }
    }

    private static boolean sameBinding(FedSetupPendingTrustAuthorization pending, String cimdUri, Set<String> capabilities,
                                       Set<String> providerProfiles, Set<String> federationProfiles) {
        return Objects.equals(pending.getCimdUri(), cimdUri) && Objects.equals(pending.getCapabilities(), capabilities)
                && Objects.equals(pending.getProviderDelegationProfiles(), providerProfiles)
                && Objects.equals(pending.getFederationExtensionProfiles(), federationProfiles);
    }

    private static Set<String> terms(JsonWebToken token, String claim) {
        return InstallationAuthorizationValidator.stringSetOrEmpty(token, claim, "Trust Establishment Request");
    }

    private static boolean hasApplicationSigningKeys(KeycloakSession session, RealmModel realm) {
        return session.keys().getActiveKey(realm, org.keycloak.crypto.KeyUse.SIG, org.keycloak.crypto.Algorithm.RS256) != null;
    }

    private static String keyId(String compact) {
        try {
            return new JWSInput(compact).getHeader().getKeyId();
        } catch (Exception e) {
            throw new FedSetupValidationException("Invalid Trust Establishment Request", e);
        }
    }

    private static String optionalString(JsonWebToken token, String name) {
        Object value = token.getOtherClaims().get(name);
        if (value == null) return null;
        if (!(value instanceof String string) || string.isBlank()) {
            throw new FedSetupValidationException("Trust Establishment Request has invalid " + name);
        }
        return string;
    }

    public record Result(DirectInstallationTrust trust, FedSetupPendingTrustAuthorization pending) {
        static Result established(DirectInstallationTrust trust) { return new Result(trust, null); }
        static Result pending(FedSetupPendingTrustAuthorization pending) { return new Result(null, pending); }
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
