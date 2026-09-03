/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup;

import java.util.Collection;
import java.util.Objects;
import java.util.UUID;

import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.urls.UrlType;
import org.keycloak.util.KeyWrapperUtil;

/** Creates the Platform-Control Proof used by Platform Certification submission. */
public final class FedSetupPlatformControlProof {

    private FedSetupPlatformControlProof() {
    }

    /**
     * Signs a short-lived, nonce-bound proof that this realm controls its
     * FedSetup CIMD URI. The receiving Catalog still owns nonce issuance,
     * nonce consumption, operator binding, CIMD resolution, and signature
     * verification.
     */
    public static String sign(KeycloakSession session, RealmModel realm, String platformCertificationEndpoint, String nonce) {
        KeyWrapper key = session.keys().getActiveKey(realm, KeyUse.SIG, Algorithm.RS256);
        if (key == null || key.getPrivateKey() == null || key.getPublicKey() == null) {
            throw new FedSetupValidationException("Realm has no active RS256 signing key");
        }
        long now = Time.currentTime();
        return sign(key, FedSetupUrls.cimd(session.getContext().getUri(UrlType.FRONTEND), realm),
                platformCertificationEndpoint, nonce, UUID.randomUUID().toString(), now,
                now + FedSetupConstants.MAX_AUTHORIZATION_LIFESPAN_SECONDS);
    }

    static String sign(KeyWrapper key, String platformUri, String platformCertificationEndpoint,
                       String nonce, String jti, long issuedAt, long expiresAt) {
        if (key == null || !FedSetupConstants.INSTALLATION_SIGNING_ALGORITHM.equals(key.getAlgorithm())) {
            throw new FedSetupValidationException("Platform-Control Proof requires an asymmetric RS256 signing key");
        }
        if (blank(nonce) || blank(jti)) {
            throw new FedSetupValidationException("Platform-Control Proof requires nonce and jti");
        }
        if (expiresAt <= issuedAt || expiresAt - issuedAt > FedSetupConstants.MAX_AUTHORIZATION_LIFESPAN_SECONDS) {
            throw new FedSetupValidationException("Platform-Control Proof lifetime is invalid");
        }

        String canonicalPlatformUri = FedSetupUri.canonicalize(platformUri);
        String canonicalEndpoint = FedSetupUri.canonicalize(platformCertificationEndpoint);
        JsonWebToken token = new JsonWebToken().issuer(canonicalPlatformUri).audience(canonicalEndpoint)
                .id(jti).iat(issuedAt).exp(expiresAt);
        token.setOtherClaims("nonce", nonce);
        try {
            return new JWSBuilder().type("JWT").kid(key.getKid()).jsonContent(token)
                    .sign(KeyWrapperUtil.createSignatureSignerContext(key));
        } catch (Exception e) {
            throw new FedSetupValidationException("Unable to sign Platform-Control Proof", e);
        }
    }

    static JsonWebToken verify(String compact, String platformUri, String platformCertificationEndpoint, String nonce,
                               JWK jwk, Collection<String> allowedAlgorithms) {
        if (jwk == null || blank(jwk.getKeyId())) {
            throw new FedSetupValidationException("Platform-Control Proof verification requires a CIMD JWK with kid");
        }
        String canonicalPlatformUri = FedSetupUri.canonicalize(platformUri);
        String canonicalEndpoint = FedSetupUri.canonicalize(platformCertificationEndpoint);
        try {
            TokenVerifier<JsonWebToken> verifier = TokenVerifier.create(compact, JsonWebToken.class);
            String algorithm = verifier.getHeader().getAlgorithm().name();
            if (!permittedAlgorithm(algorithm, allowedAlgorithms)
                    || !Objects.equals(verifier.getHeader().getKeyId(), jwk.getKeyId())) {
                throw new FedSetupValidationException("Platform-Control Proof key or algorithm is not trusted");
            }
            verifier.publicKey(JWKParser.create(jwk).toPublicKey()).withChecks(TokenVerifier.IS_ACTIVE,
                    token -> Objects.equals(canonicalPlatformUri, token.getIssuer())
                            && token.hasAudience(canonicalEndpoint)
                            && Objects.equals(nonce, token.getOtherClaims().get("nonce"))
                            && !blank(token.getId())
                            && validLifetime(token));
            verifier.verify();
            return verifier.getToken();
        } catch (FedSetupValidationException e) {
            throw e;
        } catch (VerificationException | RuntimeException e) {
            throw new FedSetupValidationException("Invalid Platform-Control Proof", e);
        }
    }

    private static boolean permittedAlgorithm(String algorithm, Collection<String> allowedAlgorithms) {
        return algorithm != null && allowedAlgorithms != null && allowedAlgorithms.contains(algorithm)
                && !"none".equalsIgnoreCase(algorithm) && !algorithm.startsWith("HS");
    }

    private static boolean validLifetime(JsonWebToken token) {
        return token.getIat() != null && token.getExp() != null && token.getExp() > token.getIat()
                && token.getExp() - token.getIat() <= FedSetupConstants.MAX_AUTHORIZATION_LIFESPAN_SECONDS;
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }
}
