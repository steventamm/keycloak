/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup;

import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

import org.keycloak.TokenVerifier;
import org.keycloak.common.Profile;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.fedsetup.representation.DirectInstallationTrust;
import org.keycloak.fedsetup.representation.DirectInstallationTrustApprovalRequest;
import org.keycloak.fedsetup.representation.DirectInstallationTrustConsentResult;
import org.keycloak.fedsetup.representation.DirectInstallationTrustInvitation;
import org.keycloak.fedsetup.representation.DirectInstallationTrustInvitationRequest;
import org.keycloak.fedsetup.representation.FedSetupConfigurationProfile;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.utils.JWKSServerUtils;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.Urls;
import org.keycloak.services.resources.RealmsResource;
import org.keycloak.urls.UrlType;
import org.keycloak.util.JsonSerialization;
import org.keycloak.util.KeyWrapperUtil;

/**
 * The administrator-mediated bootstrap for the Keycloak Direct Installation
 * Trust profile.  No method in this class performs a remote call: the signed
 * invitation and approval are deliberately handed between the two tenant
 * administrators.
 */
public final class DirectInstallationTrustConsentService {

    private static final Set<String> SUPPORTED_CAPABILITIES = Set.of("oidc", "saml", "scim", "id_jag");
    private static final String PENDING = "PENDING";
    private static final String CONSUMED = "CONSUMED";

    private final KeycloakSession session;
    private final RealmModel realm;
    private final RealmFedSetupStore store;

    public DirectInstallationTrustConsentService(KeycloakSession session, RealmModel realm, RealmFedSetupStore store) {
        this.session = session;
        this.realm = realm;
        this.store = store;
    }

    /** Creates an Application-side invitation and returns the one-time signed artifact. */
    public DirectInstallationTrustConsentResult invite(DirectInstallationTrustInvitationRequest request) {
        FedSetupConfigurationProfile profile = store.getApplicationProfile();
        if (profile == null) {
            throw new FedSetupValidationException("Application integration profile is required before creating an invitation");
        }
        if (request == null || blank(request.getIdpIssuer()) || blank(request.getSigningKeyJwk())) {
            throw new FedSetupValidationException("idpIssuer and signingKeyJwk are required");
        }

        long now = Time.currentTime();
        long expiresAt = request.getExpiresAt() == 0 ? now + FedSetupConstants.MAX_AUTHORIZATION_LIFESPAN_SECONDS : request.getExpiresAt();
        if (expiresAt <= now || expiresAt - now > FedSetupConstants.MAX_AUTHORIZATION_LIFESPAN_SECONDS) {
            throw new FedSetupValidationException("Invitation expiry must be in the next five minutes");
        }
        validateApprovedTerms(profile, request.getCapabilities(), request.getExtensionProfiles());

        DirectInstallationTrustInvitation invitation = new DirectInstallationTrustInvitation();
        invitation.setId(UUID.randomUUID().toString());
        invitation.setApplicationTenantId(profile.getApplicationTenantId());
        invitation.setCanonicalApplicationBaseUri(profile.getCanonicalBaseUri());
        invitation.setConfigurationEndpoint(configurationEndpoint());
        invitation.setIdpIssuer(FedSetupUri.canonicalize(request.getIdpIssuer()));
        invitation.setSigningKeyJwk(normalizedRsaJwk(request.getSigningKeyJwk()));
        if (!blank(request.getRuntimeJwksUri())) invitation.setRuntimeJwksUri(FedSetupUri.canonicalize(request.getRuntimeJwksUri()));
        if (!blank(request.getRuntimeSigningCertificate())) invitation.setRuntimeSigningCertificate(request.getRuntimeSigningCertificate());
        invitation.setCapabilities(request.getCapabilities());
        invitation.setExtensionProfiles(request.getExtensionProfiles());
        invitation.setExpiresAt(expiresAt);
        invitation.setStatus(PENDING);

        KeyWrapper applicationSigningKey = activeSigningKey();
        String signedInvitation = sign(applicationSigningKey, invitationToken(invitation, applicationSigningKey));
        invitation.setSignedInvitationHash(InstallationAuthorizationValidator.sha256(signedInvitation));
        store.createInvitation(invitation);

        DirectInstallationTrustConsentResult result = new DirectInstallationTrustConsentResult();
        result.setInvitation(signedInvitation);
        return result;
    }

    /**
     * IdP-side administrator approval.  The incoming Application signature is
     * verified, but the protected admin endpoint and the key/issuer comparison
     * are what turn it into IdP administrator consent.
     */
    public DirectInstallationTrustConsentResult approve(DirectInstallationTrustApprovalRequest request) {
        if (request == null || blank(request.getInvitation())) {
            throw new FedSetupValidationException("A signed Direct Installation Trust invitation is required");
        }
        InvitationClaims invitation = verifyInvitation(request.getInvitation());
        KeyWrapper activeKey = activeSigningKey();
        if (!issuer().equals(invitation.idpIssuer()) || !samePublicKey(invitation.signingKeyJwk(), activeKey)) {
            throw new FedSetupValidationException("Invitation was not issued for this IdP realm and active signing key");
        }
        validateClaims(invitation);
        if (invitation.capabilities().contains("id_jag")) {
            throw new FedSetupValidationException("This Keycloak preview receives ID-JAG assertions but does not issue them");
        }

        DirectInstallationTrust trust = trust(invitation);
        DirectInstallationTrust existing = store.findTrust(trust.getApplicationTenantId(), trust.getIdpIssuer());
        if (existing == null) {
            existing = store.createTrust(trust);
        } else if (!sameTrust(existing, trust)) {
            throw new FedSetupValidationException("A different Direct Installation Trust already exists for this Application Tenant");
        }

        JsonWebToken approval = new JsonWebToken().issuer(issuer()).id(UUID.randomUUID().toString())
                .issuedNowWithTTL(FedSetupConstants.MAX_AUTHORIZATION_LIFESPAN_SECONDS);
        approval.setOtherClaims("invitation_id", invitation.id());
        approval.setOtherClaims("invitation_hash", InstallationAuthorizationValidator.sha256(request.getInvitation()));
        approval.setOtherClaims("application_issuer", invitation.applicationIssuer());
        approval.setOtherClaims("application_tenant_id", invitation.applicationTenantId());
        approval.setOtherClaims("canonical_application_base_uri", invitation.canonicalApplicationBaseUri());
        approval.setOtherClaims("configuration_endpoint", invitation.configurationEndpoint());
        approval.setOtherClaims("idp_issuer", invitation.idpIssuer());
        approval.setOtherClaims("signing_key_jwk", invitation.signingKeyJwk());
        approval.setOtherClaims("runtime_jwks_uri", invitation.runtimeJwksUri());
        approval.setOtherClaims("runtime_signing_certificate", invitation.runtimeSigningCertificate());
        approval.setOtherClaims("capabilities", new ArrayList<>(invitation.capabilities()));
        approval.setOtherClaims("extension_profiles", new ArrayList<>(invitation.extensionProfiles()));

        DirectInstallationTrustConsentResult result = new DirectInstallationTrustConsentResult();
        result.setApproval(sign(activeKey, approval));
        result.setTrust(existing);
        return result;
    }

    /** Consumes the IdP approval and creates the matching Application-side trust exactly once. */
    public DirectInstallationTrust consume(DirectInstallationTrustApprovalRequest request) {
        if (request == null || blank(request.getInvitation()) || blank(request.getApproval())) {
            throw new FedSetupValidationException("The original invitation and the IdP approval are required");
        }
        InvitationClaims invitation = verifyInvitation(request.getInvitation());
        DirectInstallationTrustInvitation stored = store.requireInvitation(invitation.id());
        if (!PENDING.equals(stored.getStatus()) || stored.getExpiresAt() <= Time.currentTime()
                || !MessageDigest.isEqual(stored.getSignedInvitationHash().getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                InstallationAuthorizationValidator.sha256(request.getInvitation()).getBytes(java.nio.charset.StandardCharsets.US_ASCII))) {
            throw new FedSetupValidationException("Direct Installation Trust invitation is expired or has already been consumed");
        }
        if (!sameInvitation(stored, invitation)) {
            throw new FedSetupValidationException("Invitation does not match the stored Application approval");
        }
        FedSetupConfigurationProfile profile = store.getApplicationProfile();
        if (profile == null || !Objects.equals(profile.getApplicationTenantId(), stored.getApplicationTenantId())
                || !Objects.equals(profile.getCanonicalBaseUri(), stored.getCanonicalApplicationBaseUri())) {
            throw new FedSetupValidationException("The Application integration profile no longer matches this invitation");
        }
        validateApprovedTerms(profile, stored.getCapabilities(), stored.getExtensionProfiles());

        JsonWebToken approval = verify(request.getApproval(), stored.getSigningKeyJwk(), stored.getIdpIssuer());
        ApprovalClaims approved = approvalClaims(approval);
        if (!sameApproval(stored, invitation, approved, request.getInvitation())) {
            throw new FedSetupValidationException("IdP approval is not bound to this Direct Installation Trust invitation");
        }
        if (store.findTrust(stored.getApplicationTenantId(), stored.getIdpIssuer()) != null) {
            throw new FedSetupValidationException("A Direct Installation Trust already exists for this Application Tenant and IdP issuer");
        }

        DirectInstallationTrust trust = new DirectInstallationTrust();
        trust.setApplicationTenantId(stored.getApplicationTenantId());
        trust.setCanonicalApplicationBaseUri(stored.getCanonicalApplicationBaseUri());
        trust.setConfigurationEndpoint(stored.getConfigurationEndpoint());
        trust.setIdpIssuer(stored.getIdpIssuer());
        trust.setSigningKeyJwk(stored.getSigningKeyJwk());
        trust.setRuntimeJwksUri(stored.getRuntimeJwksUri());
        trust.setRuntimeSigningCertificate(stored.getRuntimeSigningCertificate());
        trust.setCapabilities(stored.getCapabilities());
        trust.setExtensionProfiles(stored.getExtensionProfiles());
        DirectInstallationTrust created = store.createTrust(trust);
        stored.setStatus(CONSUMED);
        store.updateInvitation(stored, stored.getVersion());
        return created;
    }

    private JsonWebToken invitationToken(DirectInstallationTrustInvitation invitation, KeyWrapper applicationSigningKey) {
        JsonWebToken token = new JsonWebToken().issuer(issuer()).id(invitation.getId())
                .issuedNowWithTTL(Math.toIntExact(invitation.getExpiresAt() - Time.currentTime()));
        token.setOtherClaims("application_issuer", issuer());
        token.setOtherClaims("application_signing_key_jwk", publicJwk(applicationSigningKey));
        token.setOtherClaims("application_tenant_id", invitation.getApplicationTenantId());
        token.setOtherClaims("canonical_application_base_uri", invitation.getCanonicalApplicationBaseUri());
        token.setOtherClaims("configuration_endpoint", invitation.getConfigurationEndpoint());
        token.setOtherClaims("idp_issuer", invitation.getIdpIssuer());
        token.setOtherClaims("signing_key_jwk", invitation.getSigningKeyJwk());
        token.setOtherClaims("runtime_jwks_uri", invitation.getRuntimeJwksUri());
        token.setOtherClaims("runtime_signing_certificate", invitation.getRuntimeSigningCertificate());
        token.setOtherClaims("capabilities", new ArrayList<>(invitation.getCapabilities()));
        token.setOtherClaims("extension_profiles", new ArrayList<>(invitation.getExtensionProfiles()));
        return token;
    }

    private InvitationClaims verifyInvitation(String compact) {
        JsonWebToken unverified;
        try {
            unverified = new JWSInput(compact).readJsonContent(JsonWebToken.class);
        } catch (Exception e) {
            throw new FedSetupValidationException("Invalid Direct Installation Trust invitation", e);
        }
        String applicationKey = claim(unverified, "application_signing_key_jwk", true);
        JsonWebToken verified = verify(compact, applicationKey, unverified.getIssuer());
        InvitationClaims claims = new InvitationClaims(verified.getId(), verified.getIssuer(),
                claim(verified, "application_tenant_id", true), claim(verified, "canonical_application_base_uri", true),
                claim(verified, "configuration_endpoint", true), claim(verified, "idp_issuer", true),
                claim(verified, "signing_key_jwk", true), claim(verified, "runtime_jwks_uri", false),
                claim(verified, "runtime_signing_certificate", false), claimSet(verified, "capabilities"),
                claimSet(verified, "extension_profiles"));
        if (blank(claims.id()) || claims.idpIssuer() == null || claims.applicationIssuer() == null) {
            throw new FedSetupValidationException("Direct Installation Trust invitation is missing an identifier or issuer");
        }
        return normalize(claims);
    }

    private JsonWebToken verify(String compact, String publicJwk, String expectedIssuer) {
        try {
            JWK jwk = JWKParser.create().parse(publicJwk).getJwk();
            TokenVerifier<JsonWebToken> verifier = TokenVerifier.create(compact, JsonWebToken.class);
            String algorithm = verifier.getHeader().getAlgorithm().name();
            if (!"RS256".equals(algorithm) || !Objects.equals(algorithm, jwk.getAlgorithm())
                    || !Objects.equals(verifier.getHeader().getKeyId(), jwk.getKeyId())) {
                throw new FedSetupValidationException("Direct Installation Trust token key or algorithm is not approved");
            }
            verifier.publicKey(JWKParser.create(jwk).toPublicKey()).withChecks(TokenVerifier.IS_ACTIVE,
                    token -> Objects.equals(expectedIssuer, token.getIssuer()));
            verifier.verify();
            JsonWebToken token = verifier.getToken();
            if (token.getId() == null || token.getId().isBlank() || token.getIat() == null || token.getExp() == null) {
                throw new FedSetupValidationException("Direct Installation Trust token is missing jti, iat, or exp");
            }
            long now = Time.currentTime();
            if (token.getExp() <= now || token.getIat() > now + 10
                    || token.getExp() - token.getIat() > FedSetupConstants.MAX_AUTHORIZATION_LIFESPAN_SECONDS) {
                throw new FedSetupValidationException("Direct Installation Trust token lifetime is invalid");
            }
            return token;
        } catch (FedSetupValidationException e) {
            throw e;
        } catch (VerificationException | RuntimeException e) {
            throw new FedSetupValidationException("Invalid Direct Installation Trust token", e);
        }
    }

    private InvitationClaims normalize(InvitationClaims claims) {
        return new InvitationClaims(claims.id(), FedSetupUri.canonicalize(claims.applicationIssuer()), claims.applicationTenantId(),
                FedSetupUri.canonicalize(claims.canonicalApplicationBaseUri()), FedSetupUri.canonicalize(claims.configurationEndpoint()),
                FedSetupUri.canonicalize(claims.idpIssuer()), normalizedRsaJwk(claims.signingKeyJwk()),
                claims.runtimeJwksUri() == null ? null : FedSetupUri.canonicalize(claims.runtimeJwksUri()),
                claims.runtimeSigningCertificate(), claims.capabilities(), claims.extensionProfiles());
    }

    private void validateClaims(InvitationClaims invitation) {
        if (invitation.capabilities().isEmpty() || invitation.extensionProfiles().isEmpty()
                || !SUPPORTED_CAPABILITIES.containsAll(invitation.capabilities())
                || !invitation.extensionProfiles().contains(FedSetupConstants.FEATURE_PROFILE_URI)) {
            throw new FedSetupValidationException("Invitation requests unsupported capabilities or does not approve the Keycloak trust profile");
        }
        if (invitation.capabilities().contains("id_jag") && !Profile.isFeatureEnabled(Profile.Feature.IDENTITY_ASSERTION_JWT)) {
            throw new FedSetupValidationException("The Identity Assertion JWT preview feature must be enabled before approving id_jag");
        }
        if (invitation.runtimeJwksUri() == null && blank(invitation.runtimeSigningCertificate())) {
            throw new FedSetupValidationException("Invitation must approve an OIDC JWKS URI or SAML signing certificate");
        }
    }

    private void validateApprovedTerms(FedSetupConfigurationProfile profile, Set<String> capabilities, Set<String> profiles) {
        if (capabilities == null || profiles == null || capabilities.isEmpty() || profiles.isEmpty()
                || !profile.getCapabilities().containsAll(capabilities) || !profile.getExtensionProfiles().containsAll(profiles)
                || !SUPPORTED_CAPABILITIES.containsAll(capabilities) || !profiles.contains(FedSetupConstants.FEATURE_PROFILE_URI)) {
            throw new FedSetupValidationException("Invitation capabilities and extension profiles must be explicitly supported by the Application profile");
        }
        if (capabilities.contains("id_jag") && !Profile.isFeatureEnabled(Profile.Feature.IDENTITY_ASSERTION_JWT)) {
            throw new FedSetupValidationException("The Identity Assertion JWT preview feature must be enabled before approving id_jag");
        }
    }

    private DirectInstallationTrust trust(InvitationClaims invitation) {
        DirectInstallationTrust trust = new DirectInstallationTrust();
        trust.setApplicationTenantId(invitation.applicationTenantId());
        trust.setCanonicalApplicationBaseUri(invitation.canonicalApplicationBaseUri());
        trust.setConfigurationEndpoint(invitation.configurationEndpoint());
        trust.setIdpIssuer(invitation.idpIssuer());
        trust.setSigningKeyJwk(invitation.signingKeyJwk());
        trust.setRuntimeJwksUri(invitation.runtimeJwksUri());
        trust.setRuntimeSigningCertificate(invitation.runtimeSigningCertificate());
        trust.setCapabilities(invitation.capabilities());
        trust.setExtensionProfiles(invitation.extensionProfiles());
        return trust;
    }

    private ApprovalClaims approvalClaims(JsonWebToken approval) {
        return new ApprovalClaims(claim(approval, "invitation_id", true), claim(approval, "invitation_hash", true),
                claim(approval, "application_issuer", true), claim(approval, "application_tenant_id", true),
                claim(approval, "canonical_application_base_uri", true), claim(approval, "configuration_endpoint", true),
                claim(approval, "idp_issuer", true), claim(approval, "signing_key_jwk", true),
                claim(approval, "runtime_jwks_uri", false), claim(approval, "runtime_signing_certificate", false),
                claimSet(approval, "capabilities"), claimSet(approval, "extension_profiles"));
    }

    private boolean sameInvitation(DirectInstallationTrustInvitation stored, InvitationClaims invitation) {
        return Objects.equals(stored.getApplicationTenantId(), invitation.applicationTenantId())
                && Objects.equals(stored.getCanonicalApplicationBaseUri(), invitation.canonicalApplicationBaseUri())
                && Objects.equals(stored.getConfigurationEndpoint(), invitation.configurationEndpoint())
                && Objects.equals(stored.getIdpIssuer(), invitation.idpIssuer())
                && Objects.equals(stored.getSigningKeyJwk(), invitation.signingKeyJwk())
                && Objects.equals(stored.getRuntimeJwksUri(), invitation.runtimeJwksUri())
                && Objects.equals(stored.getRuntimeSigningCertificate(), invitation.runtimeSigningCertificate())
                && Objects.equals(stored.getCapabilities(), invitation.capabilities())
                && Objects.equals(stored.getExtensionProfiles(), invitation.extensionProfiles());
    }

    private boolean sameApproval(DirectInstallationTrustInvitation stored, InvitationClaims invitation, ApprovalClaims approval,
                                 String signedInvitation) {
        return Objects.equals(invitation.id(), approval.invitationId())
                && Objects.equals(InstallationAuthorizationValidator.sha256(signedInvitation), approval.invitationHash())
                && Objects.equals(issuer(), approval.applicationIssuer())
                && Objects.equals(stored.getApplicationTenantId(), approval.applicationTenantId())
                && Objects.equals(stored.getCanonicalApplicationBaseUri(), canonical(approval.canonicalApplicationBaseUri()))
                && Objects.equals(stored.getConfigurationEndpoint(), canonical(approval.configurationEndpoint()))
                && Objects.equals(stored.getIdpIssuer(), canonical(approval.idpIssuer()))
                && Objects.equals(stored.getSigningKeyJwk(), normalizedRsaJwk(approval.signingKeyJwk()))
                && Objects.equals(stored.getRuntimeJwksUri(), optionalCanonical(approval.runtimeJwksUri()))
                && Objects.equals(stored.getRuntimeSigningCertificate(), approval.runtimeSigningCertificate())
                && Objects.equals(stored.getCapabilities(), approval.capabilities())
                && Objects.equals(stored.getExtensionProfiles(), approval.extensionProfiles());
    }

    private boolean sameTrust(DirectInstallationTrust existing, DirectInstallationTrust requested) {
        return Objects.equals(existing.getCanonicalApplicationBaseUri(), requested.getCanonicalApplicationBaseUri())
                && Objects.equals(existing.getConfigurationEndpoint(), requested.getConfigurationEndpoint())
                && Objects.equals(existing.getSigningKeyJwk(), requested.getSigningKeyJwk())
                && Objects.equals(existing.getRuntimeJwksUri(), requested.getRuntimeJwksUri())
                && Objects.equals(existing.getRuntimeSigningCertificate(), requested.getRuntimeSigningCertificate())
                && Objects.equals(existing.getCapabilities(), requested.getCapabilities())
                && Objects.equals(existing.getExtensionProfiles(), requested.getExtensionProfiles())
                && existing.isActive();
    }

    private String configurationEndpoint() {
        return RealmsResource.realmBaseUrl(session.getContext().getUri(UrlType.FRONTEND)).path(FedSetupConstants.REALM_RESOURCE_ID)
                .build(realm.getName()).toString() + "/connections";
    }

    private String issuer() {
        return Urls.realmIssuer(session.getContext().getUri(UrlType.FRONTEND).getBaseUri(), realm.getName());
    }

    private KeyWrapper activeSigningKey() {
        KeyWrapper key = session.keys().getActiveKey(realm, KeyUse.SIG, Algorithm.RS256);
        if (key == null || key.getPublicKey() == null) {
            throw new FedSetupValidationException("Realm has no active RS256 signing key");
        }
        return key;
    }

    private String publicJwk(KeyWrapper key) {
        JWK jwk = JWKSServerUtils.toJwk(key);
        if (jwk == null) throw new FedSetupValidationException("Unable to represent the realm signing key as a JWK");
        return JsonSerialization.valueAsString(jwk);
    }

    private String sign(KeyWrapper key, JsonWebToken token) {
        try {
            return new JWSBuilder().type("JWT").kid(key.getKid()).jsonContent(token).sign(KeyWrapperUtil.createSignatureSignerContext(key));
        } catch (Exception e) {
            throw new FedSetupValidationException("Unable to sign Direct Installation Trust token", e);
        }
    }

    private boolean samePublicKey(String configuredJwk, KeyWrapper key) {
        try {
            PublicKey configured = JWKParser.create(JWKParser.create().parse(configuredJwk).getJwk()).toPublicKey();
            return MessageDigest.isEqual(configured.getEncoded(), key.getPublicKey().getEncoded());
        } catch (RuntimeException e) {
            throw new FedSetupValidationException("Invalid approved IdP signing JWK", e);
        }
    }

    private String normalizedRsaJwk(String rawJwk) {
        try {
            JWK jwk = JWKParser.create().parse(rawJwk).getJwk();
            if (blank(jwk.getKeyId()) || !"RS256".equals(jwk.getAlgorithm())) {
                throw new FedSetupValidationException("Direct Installation Trust requires an RS256 JWK with a kid");
            }
            JWKParser.create(jwk).toPublicKey();
            return JsonSerialization.valueAsString(jwk);
        } catch (FedSetupValidationException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new FedSetupValidationException("Invalid Direct Installation Trust signing JWK", e);
        }
    }

    private static String claim(JsonWebToken token, String name, boolean required) {
        Object value = token.getOtherClaims().get(name);
        if (value instanceof String string && !string.isBlank()) return string;
        if (required) throw new FedSetupValidationException("Direct Installation Trust token is missing " + name);
        return null;
    }

    private static Set<String> claimSet(JsonWebToken token, String name) {
        Object value = token.getOtherClaims().get(name);
        if (!(value instanceof Collection<?> values)) {
            throw new FedSetupValidationException("Direct Installation Trust token is missing " + name);
        }
        Set<String> result = new LinkedHashSet<>();
        for (Object item : values) {
            if (!(item instanceof String string) || string.isBlank()) {
                throw new FedSetupValidationException("Direct Installation Trust token has an invalid " + name);
            }
            result.add(string);
        }
        return result;
    }

    private static String canonical(String value) { return FedSetupUri.canonicalize(value); }
    private static String optionalCanonical(String value) { return value == null ? null : FedSetupUri.canonicalize(value); }
    private static boolean blank(String value) { return value == null || value.isBlank(); }

    private record InvitationClaims(String id, String applicationIssuer, String applicationTenantId,
                                    String canonicalApplicationBaseUri, String configurationEndpoint, String idpIssuer,
                                    String signingKeyJwk, String runtimeJwksUri, String runtimeSigningCertificate,
                                    Set<String> capabilities, Set<String> extensionProfiles) { }

    private record ApprovalClaims(String invitationId, String invitationHash, String applicationIssuer, String applicationTenantId,
                                  String canonicalApplicationBaseUri, String configurationEndpoint, String idpIssuer,
                                  String signingKeyJwk, String runtimeJwksUri, String runtimeSigningCertificate,
                                  Set<String> capabilities, Set<String> extensionProfiles) { }
}
