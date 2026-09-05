/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.Time;
import org.keycloak.fedsetup.representation.DirectInstallationTrust;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.JsonWebToken;

/** Validates the signed, one-time request authorization defined by the Keycloak DIT profile. */
public final class InstallationAuthorizationValidator {

    private static final String REPLAY_PREFIX = "fedsetup.installation-authorization.";

    private InstallationAuthorizationValidator() {
    }

    public static ValidatedAuthorization validate(KeycloakSession session, DirectInstallationTrust trust, String authorization,
                                                  String method, String uri, String requestBody, String applicationTenantId,
                                                  Set<String> requestedCapabilities, Set<String> requestedProfiles) {
        return validate(session, trust, authorization, method, uri, requestBody, applicationTenantId, requestedCapabilities,
                requestedProfiles, true);
    }

    /**
     * Validates a request without consuming its {@code jti}.  POST uses this
     * form only to locate a previously successful idempotent result: the
     * caller must invoke {@link #consume(KeycloakSession, ValidatedAuthorization)}
     * before it creates a new Connection.
     */
    public static ValidatedAuthorization validateForIdempotency(KeycloakSession session, DirectInstallationTrust trust, String authorization,
                                                                String method, String uri, String requestBody, String applicationTenantId,
                                                                Set<String> requestedCapabilities, Set<String> requestedProfiles) {
        return validate(session, trust, authorization, method, uri, requestBody, applicationTenantId, requestedCapabilities,
                requestedProfiles, false);
    }

    private static ValidatedAuthorization validate(KeycloakSession session, DirectInstallationTrust trust, String authorization,
                                                   String method, String uri, String requestBody, String applicationTenantId,
                                                   Set<String> requestedCapabilities, Set<String> requestedProfiles, boolean consumeReplay) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            throw new FedSetupValidationException("A Bearer Installation Authorization is required");
        }
        if (!trust.isActive() || trust.getExpiresAt() > 0 && trust.getExpiresAt() <= Time.currentTime()) {
            throw new FedSetupValidationException("Direct Installation Trust is not active");
        }
        if (!Objects.equals(trust.getApplicationTenantId(), applicationTenantId)) {
            throw new FedSetupValidationException("Application Tenant does not match Direct Installation Trust");
        }

        boolean cimd = trust.getInstallationRuntimeCimdUri() != null && !trust.getInstallationRuntimeCimdUri().isBlank();
        JsonWebToken token = verify(session, authorization.substring("Bearer ".length()), trust, cimd ? uri : null);
        String bodyHash = cimd ? sha256Base64Url(requestBody) : sha256(requestBody);
        String tokenTenant = stringClaim(token, "application_tenant_id", "Installation Authorization");
        String tokenMethod = stringClaim(token, cimd ? "htm" : "method", "Installation Authorization");
        String tokenUri = stringClaim(token, cimd ? "htu" : "uri", "Installation Authorization");
        String tokenHash = stringClaim(token, "request_hash", "Installation Authorization");
        Set<String> tokenCapabilities = stringSetClaimOrEmpty(token, "capabilities");
        Set<String> tokenProfiles = stringSetClaimOrEmpty(token, cimd ? "federation_extension_profiles" : "extension_profiles");
        String tokenIdpIssuer = cimd ? stringClaim(token, "idp_issuer", "Installation Authorization") : token.getIssuer();

        if (!Objects.equals(trust.getIdpIssuer(), tokenIdpIssuer) || !Objects.equals(applicationTenantId, tokenTenant)
                || !Objects.equals(method, tokenMethod) || !Objects.equals(uri, tokenUri)
                || !MessageDigest.isEqual(bodyHash.getBytes(StandardCharsets.US_ASCII), tokenHash.getBytes(StandardCharsets.US_ASCII))) {
            throw new FedSetupValidationException("Installation Authorization is not bound to this request");
        }
        if (!trust.getCapabilities().containsAll(tokenCapabilities) || !tokenCapabilities.containsAll(requestedCapabilities)
                || !trust.getExtensionProfiles().containsAll(tokenProfiles) || !tokenProfiles.containsAll(requestedProfiles)) {
            throw new FedSetupValidationException("Installation Authorization grants insufficient capabilities or extension profiles");
        }
        requireLifetime(token, "Installation Authorization");
        ValidatedAuthorization validated = new ValidatedAuthorization(token.getId(), bodyHash, tokenCapabilities, tokenProfiles, token.getExp());
        if (consumeReplay) {
            consume(session, validated);
        }
        return validated;
    }

    /** Consumes a validated Installation Authorization exactly once. */
    public static void consume(KeycloakSession session, ValidatedAuthorization authorization) {
        long remainingLifetime = authorization.expiresAt() - Time.currentTime();
        if (remainingLifetime <= 0 || !session.singleUseObjects().putIfAbsent(
                REPLAY_PREFIX + session.getContext().getRealm().getId() + "." + authorization.id(), Math.max(1, remainingLifetime))) {
            throw new FedSetupValidationException("Installation Authorization has already been used");
        }
    }

    public static String sha256(String requestBody) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(requestBody.getBytes(StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                result.append(String.format("%02x", b));
            }
            return result.toString();
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    public static String sha256Base64Url(String requestBody) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(requestBody.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    static JsonWebToken verifyCimdJwt(KeycloakSession session, String jwt, String cimdUri, String expectedIssuer, String audience) {
        try {
            TokenVerifier<JsonWebToken> verifier = TokenVerifier.create(jwt, JsonWebToken.class);
            String algorithm = verifier.getHeader().getAlgorithm().name();
            if (!FedSetupConstants.INSTALLATION_SIGNING_ALGORITHM.equals(algorithm) || verifier.getHeader().getKeyId() == null) {
                throw new FedSetupValidationException("Installation Authorization key or algorithm is not trusted");
            }
            FedSetupCimdResolver.ResolvedCimd resolved = FedSetupCimdResolver.resolve(session, cimdUri, verifier.getHeader().getKeyId(), algorithm);
            verifier.publicKey(resolved.publicKey()).withChecks(TokenVerifier.IS_ACTIVE,
                    token -> Objects.equals(expectedIssuer, token.getIssuer()) && (audience == null || token.hasAudience(audience)));
            verifier.verify();
            return verifier.getToken();
        } catch (FedSetupValidationException e) {
            // A malformed or unavailable approved CIMD/JWKS source is a
            // credential-verification failure, not a Configuration Request
            // syntax error. Keep its operational detail as the cause while
            // exposing the Section 8.2 invalid_credential category.
            throw new FedSetupValidationException("Invalid Installation Authorization", e);
        } catch (VerificationException | RuntimeException e) {
            throw new FedSetupValidationException("Invalid Installation Authorization", e);
        }
    }

    private static JsonWebToken verify(KeycloakSession session, String jwt, DirectInstallationTrust trust, String audience) {
        if (trust.getInstallationRuntimeCimdUri() != null && !trust.getInstallationRuntimeCimdUri().isBlank()) {
            return verifyCimdJwt(session, jwt, trust.getInstallationRuntimeCimdUri(), trust.getInstallationRuntimeCimdUri(), audience);
        }
        try {
            JWK pinnedKey = JWKParser.create().parse(trust.getSigningKeyJwk()).getJwk();
            TokenVerifier<JsonWebToken> verifier = TokenVerifier.create(jwt, JsonWebToken.class);
            String algorithm = verifier.getHeader().getAlgorithm().name();
            if ("none".equalsIgnoreCase(algorithm) || !Objects.equals(algorithm, pinnedKey.getAlgorithm())
                    || !Objects.equals(verifier.getHeader().getKeyId(), pinnedKey.getKeyId())) {
                throw new FedSetupValidationException("Installation Authorization key or algorithm is not trusted");
            }
            verifier.publicKey(JWKParser.create(pinnedKey).toPublicKey())
                    .withChecks(TokenVerifier.IS_ACTIVE, token -> Objects.equals(trust.getIdpIssuer(), token.getIssuer()));
            verifier.verify();
            return verifier.getToken();
        } catch (FedSetupValidationException e) {
            throw e;
        } catch (VerificationException | RuntimeException e) {
            throw new FedSetupValidationException("Invalid Installation Authorization", e);
        }
    }

    static String stringClaim(JsonWebToken token, String name, String credentialName) {
        Object value = token.getOtherClaims().get(name);
        if (!(value instanceof String string) || string.isBlank()) {
            throw new FedSetupValidationException(credentialName + " is missing " + name);
        }
        return string;
    }

    static void requireLifetime(JsonWebToken token, String credentialName) {
        if (token.getId() == null || token.getId().isBlank() || token.getIat() == null || token.getExp() == null) {
            throw new FedSetupValidationException(credentialName + " is missing jti, iat, or exp");
        }
        long now = Time.currentTime();
        if (token.getExp() <= now || token.getIat() > now + 10
                || token.getExp() - token.getIat() > FedSetupConstants.MAX_AUTHORIZATION_LIFESPAN_SECONDS) {
            throw new FedSetupValidationException(credentialName + " lifetime is invalid");
        }
    }

    private static Set<String> stringSetClaim(JsonWebToken token, String name) {
        Object value = token.getOtherClaims().get(name);
        if (!(value instanceof Collection<?> values)) {
            throw new FedSetupValidationException("Installation Authorization is missing " + name);
        }
        Set<String> result = new LinkedHashSet<>();
        for (Object item : values) {
            if (!(item instanceof String string) || string.isBlank()) {
                throw new FedSetupValidationException("Installation Authorization has an invalid " + name);
            }
            result.add(string);
        }
        return result;
    }

    private static Set<String> stringSetClaimOrEmpty(JsonWebToken token, String name) {
        return token.getOtherClaims().containsKey(name) ? stringSetClaim(token, name) : Set.of();
    }

    /** Parses an optional string-array claim while retaining the caller's protocol-specific error label. */
    static Set<String> stringSetOrEmpty(JsonWebToken token, String name, String credentialName) {
        Object value = token.getOtherClaims().get(name);
        if (value == null) return Set.of();
        if (!(value instanceof Collection<?> values)) {
            throw new FedSetupValidationException(credentialName + " has invalid " + name);
        }
        Set<String> result = new LinkedHashSet<>();
        for (Object item : values) {
            if (!(item instanceof String string) || string.isBlank()) {
                throw new FedSetupValidationException(credentialName + " has invalid " + name);
            }
            result.add(string);
        }
        return result;
    }

    public record ValidatedAuthorization(String id, String requestHash, Set<String> capabilities, Set<String> extensionProfiles,
                                         long expiresAt) {
    }
}
