/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup;

import java.io.IOException;
import java.security.PublicKey;
import java.util.Objects;

import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.http.simple.SimpleHttpResponse;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.oidc.OIDCClientRepresentation;
import org.keycloak.util.JsonSerialization;

import org.apache.http.client.config.RequestConfig;

/** Resolves a pre-approved CIMD identity and one of its public signing keys. */
public final class FedSetupCimdResolver {

    private FedSetupCimdResolver() {
    }

    public static ResolvedCimd resolve(KeycloakSession session, String rawCimdUri, String kid, String algorithm) {
        if (!FedSetupConstants.INSTALLATION_SIGNING_ALGORITHM.equals(algorithm)) {
            throw new FedSetupValidationException("CIMD signing algorithm is not permitted by the Keycloak Direct Installation Trust profile");
        }
        String cimdUri = FedSetupUri.canonicalize(rawCimdUri);
        FedSetupUri.requirePublicAddress(cimdUri, "CIMD source");
        OIDCClientRepresentation metadata = fetch(session, cimdUri, OIDCClientRepresentation.class);
        if (metadata == null || !Objects.equals(cimdUri, metadata.getClientId())) {
            throw new FedSetupValidationException("CIMD client_id does not match the approved CIMD URI");
        }
        JSONWebKeySet keySet = metadata.getJwks();
        if (keySet == null) {
            if (metadata.getJwksUri() == null || metadata.getJwksUri().isBlank()) {
                throw new FedSetupValidationException("CIMD has no signing key set");
            }
            String jwksUri = FedSetupUri.canonicalize(metadata.getJwksUri());
            FedSetupUri.requirePublicAddress(jwksUri, "CIMD signing-key source");
            keySet = fetch(session, jwksUri, JSONWebKeySet.class);
        }
        if (keySet == null || keySet.getKeys() == null) {
            throw new FedSetupValidationException("CIMD signing key set is empty");
        }
        for (JWK key : keySet.getKeys()) {
            if (Objects.equals(kid, key.getKeyId()) && Objects.equals(algorithm, key.getAlgorithm())) {
                try {
                    return new ResolvedCimd(cimdUri, metadata, key, JWKParser.create(key).toPublicKey());
                } catch (RuntimeException e) {
                    throw new FedSetupValidationException("CIMD signing key is invalid", e);
                }
            }
        }
        throw new FedSetupValidationException("CIMD has no key matching the JWT kid and algorithm");
    }

    public static OIDCClientRepresentation metadata(KeycloakSession session, String rawCimdUri) {
        String cimdUri = FedSetupUri.canonicalize(rawCimdUri);
        FedSetupUri.requirePublicAddress(cimdUri, "CIMD source");
        OIDCClientRepresentation metadata = fetch(session, cimdUri, OIDCClientRepresentation.class);
        if (metadata == null || !Objects.equals(cimdUri, metadata.getClientId())) {
            throw new FedSetupValidationException("CIMD client_id does not match the approved CIMD URI");
        }
        return metadata;
    }

    /**
     * Verifies that a CIMD is an HTTPS client identity document with usable
     * RS256 public key material before a FedSetup connection starts relying on
     * it.  Selection of a particular {@code kid} still happens for each JWT
     * in {@link #resolve(KeycloakSession, String, String, String)}.
     */
    public static OIDCClientRepresentation validate(KeycloakSession session, String rawCimdUri) {
        OIDCClientRepresentation metadata = metadata(session, rawCimdUri);
        JSONWebKeySet keySet = metadata.getJwks();
        if (keySet == null) {
            if (metadata.getJwksUri() == null || metadata.getJwksUri().isBlank()) {
                throw new FedSetupValidationException("CIMD has no signing key set");
            }
            String jwksUri = FedSetupUri.canonicalize(metadata.getJwksUri());
            FedSetupUri.requirePublicAddress(jwksUri, "CIMD signing-key source");
            keySet = fetch(session, jwksUri, JSONWebKeySet.class);
        }
        if (keySet == null || keySet.getKeys() == null || keySet.getKeys().length == 0) {
            throw new FedSetupValidationException("CIMD signing key set is empty");
        }
        boolean usable = false;
        for (JWK key : keySet.getKeys()) {
            if (FedSetupConstants.INSTALLATION_SIGNING_ALGORITHM.equals(key.getAlgorithm())) {
                try {
                    JWKParser.create(key).toPublicKey();
                    usable = true;
                } catch (RuntimeException ignored) {
                    // The next matching key may be valid; do not accept an
                    // all-invalid key set merely because it names RS256.
                }
            }
        }
        if (!usable) {
            throw new FedSetupValidationException("CIMD has no usable RS256 signing key");
        }
        return metadata;
    }

    private static <T> T fetch(KeycloakSession session, String uri, Class<T> type) {
        RequestConfig noRedirects = RequestConfig.copy(RequestConfig.DEFAULT).setRedirectsEnabled(false).build();
        try (SimpleHttpResponse response = SimpleHttp.create(session).withRequestConfig(noRedirects).doGet(uri).acceptJson().asResponse()) {
            if (response.getStatus() != 200) {
                throw new FedSetupValidationException("CIMD endpoint returned HTTP " + response.getStatus());
            }
            return JsonSerialization.readValue(response.asString(), type);
        } catch (IOException | RuntimeException e) {
            if (e instanceof FedSetupValidationException validation) throw validation;
            throw new FedSetupValidationException("Unable to retrieve the approved CIMD source", e);
        }
    }

    public record ResolvedCimd(String uri, OIDCClientRepresentation metadata, JWK jwk, PublicKey publicKey) {
    }
}
