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
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.JsonWebToken;

/** Shared JWT-claim and request-hash validation helpers for Direct Installation Trust profiles. */
public final class InstallationAuthorizationValidator {

    private InstallationAuthorizationValidator() {
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

}
