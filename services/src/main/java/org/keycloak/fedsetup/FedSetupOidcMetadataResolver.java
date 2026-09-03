/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup;

import java.io.IOException;
import java.net.URI;
import java.util.Objects;

import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.http.simple.SimpleHttpResponse;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;
import org.keycloak.util.JsonSerialization;

import org.apache.http.client.config.RequestConfig;

/** Resolves OIDC runtime metadata only from the issuer bound in a Direct Installation Trust. */
public final class FedSetupOidcMetadataResolver {

    private FedSetupOidcMetadataResolver() {
    }

    public static RuntimeMetadata resolve(KeycloakSession session, String boundIssuer) {
        String issuer = FedSetupUri.canonicalize(boundIssuer);
        String discovery = discoveryUri(issuer);
        FedSetupUri.requirePublicAddress(discovery, "OIDC issuer discovery");
        RequestConfig noRedirects = RequestConfig.copy(RequestConfig.DEFAULT).setRedirectsEnabled(false).build();
        try (SimpleHttpResponse response = SimpleHttp.create(session).withRequestConfig(noRedirects).doGet(discovery).acceptJson().asResponse()) {
            if (response.getStatus() != 200) throw new FedSetupValidationException("OIDC discovery endpoint returned HTTP " + response.getStatus());
            OIDCConfigurationRepresentation metadata = JsonSerialization.readValue(response.asString(), OIDCConfigurationRepresentation.class);
            if (metadata == null || !Objects.equals(issuer, FedSetupUri.canonicalize(metadata.getIssuer()))) {
                throw new FedSetupValidationException("OIDC discovery issuer does not match the Direct Installation Trust");
            }
            return new RuntimeMetadata(issuer, requiredUri(metadata.getAuthorizationEndpoint(), "authorization_endpoint", issuer),
                    requiredUri(metadata.getTokenEndpoint(), "token_endpoint", issuer), requiredUri(metadata.getJwksUri(), "jwks_uri", issuer),
                    optionalUri(metadata.getUserinfoEndpoint(), issuer), optionalUri(metadata.getLogoutEndpoint(), issuer));
        } catch (IOException | RuntimeException e) {
            if (e instanceof FedSetupValidationException validation) throw validation;
            throw new FedSetupValidationException("Unable to retrieve OIDC metadata from the trusted issuer", e);
        }
    }

    /** RFC 8414 Section 3 inserts the well-known path before an issuer path. */
    static String discoveryUri(String boundIssuer) {
        String issuer = FedSetupUri.canonicalize(boundIssuer);
        URI uri = URI.create(issuer);
        String issuerPath = uri.getRawPath();
        if (issuerPath == null || "/".equals(issuerPath)) issuerPath = "";
        return uri.getScheme() + "://" + uri.getRawAuthority() + "/.well-known/oauth-authorization-server" + issuerPath;
    }

    private static String requiredUri(String value, String name, String issuer) {
        if (value == null || value.isBlank()) throw new FedSetupValidationException("OIDC discovery is missing " + name);
        return issuerBoundUri(value, issuer, name);
    }

    private static String optionalUri(String value, String issuer) {
        return value == null || value.isBlank() ? null : issuerBoundUri(value, issuer, "OIDC discovery endpoint");
    }

    private static String issuerBoundUri(String value, String issuer, String name) {
        String canonical = FedSetupUri.canonicalize(value);
        if (!FedSetupUri.sameOrigin(issuer, canonical)) {
            throw new FedSetupValidationException(name + " is not on the Direct Installation Trust issuer origin");
        }
        return canonical;
    }

    public record RuntimeMetadata(String issuer, String authorizationEndpoint, String tokenEndpoint, String jwksUri,
                                  String userinfoEndpoint, String logoutEndpoint) {
    }
}
