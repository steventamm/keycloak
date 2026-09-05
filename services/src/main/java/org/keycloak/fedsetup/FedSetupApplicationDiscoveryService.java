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
import java.util.Set;

import org.keycloak.fedsetup.representation.FedSetupDiscoveryRepresentation;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.http.simple.SimpleHttpResponse;
import org.keycloak.models.KeycloakSession;
import org.keycloak.util.JsonSerialization;

import org.apache.http.client.config.RequestConfig;

/** Fetches and strictly validates an external Application's FedSetup discovery document. */
public final class FedSetupApplicationDiscoveryService {

    private FedSetupApplicationDiscoveryService() {
    }

    public static FedSetupDiscoveryRepresentation discover(KeycloakSession session, String applicationBaseUri) {
        String baseUri = FedSetupUri.canonicalize(applicationBaseUri);
        String discoveryUri = discoveryUri(baseUri);
        FedSetupUri.requirePublicAddress(discoveryUri, "Application discovery source");
        RequestConfig noRedirects = RequestConfig.copy(RequestConfig.DEFAULT).setRedirectsEnabled(false).build();
        try (SimpleHttpResponse response = SimpleHttp.create(session).withRequestConfig(noRedirects).doGet(discoveryUri).acceptJson().asResponse()) {
            if (response.getStatus() != 200) throw new FedSetupValidationException("Application discovery endpoint returned HTTP " + response.getStatus());
            FedSetupDiscoveryRepresentation document = JsonSerialization.readValue(response.asString(), FedSetupDiscoveryRepresentation.class);
            validate(baseUri, document);
            return document;
        } catch (IOException | RuntimeException e) {
            if (e instanceof FedSetupValidationException validation) throw validation;
            throw new FedSetupValidationException("Unable to retrieve Application FedSetup discovery", e);
        }
    }

    /** RFC 8414 inserts the well-known suffix before an Application Base URI path. */
    static String discoveryUri(String applicationBaseUri) {
        URI baseUri = URI.create(FedSetupUri.canonicalize(applicationBaseUri));
        String path = baseUri.getRawPath();
        if (path == null || "/".equals(path)) {
            path = "";
        }
        return baseUri.getScheme() + "://" + baseUri.getRawAuthority() + "/.well-known/"
                + FedSetupConstants.WELL_KNOWN_ALIAS + path;
    }

    private static void validate(String applicationBaseUri, FedSetupDiscoveryRepresentation document) {
        if (document == null || !"1.0".equals(document.getFedsetupVersion())
                || !Objects.equals(applicationBaseUri, FedSetupUri.canonicalize(document.getApplicationBaseUri()))) {
            throw new FedSetupValidationException("Application discovery document does not identify the requested canonical Application Base URI");
        }
        String configuration = FedSetupUri.canonicalize(document.getConfigurationEndpoint());
        if (!sameOrigin(applicationBaseUri, configuration)) {
            throw new FedSetupValidationException("Application configuration endpoint is not on the canonical Application origin");
        }
        String template = FedSetupUri.canonicalizeConnectionEndpointTemplate(document.getConnectionEndpointTemplate());
        if (!sameOrigin(applicationBaseUri, template.replace("{connection_id}", "fedsetup-connection-id"))) {
            throw new FedSetupValidationException("Application connection_endpoint_template is not on the canonical Application origin");
        }
        document.setConnectionEndpointTemplate(template);
        String authorizationServer = FedSetupUri.canonicalize(document.getAuthorizationServer());
        String configurationResource = FedSetupUri.canonicalize(document.getConfigurationResource());
        if (!sameOrigin(applicationBaseUri, configurationResource)) {
            throw new FedSetupValidationException("Application configuration resource is not on the canonical Application origin");
        }
        document.setAuthorizationServer(authorizationServer);
        document.setConfigurationResource(configurationResource);
        if (document.getProtocolsSupported() == null || document.getProtocolsSupported().isEmpty()
                || !Set.of("oidc", "saml").containsAll(document.getProtocolsSupported())) {
            throw new FedSetupValidationException("Application discovery document has no supported OIDC or SAML protocol");
        }
        Set<String> profiles = document.getDirectInstallationTrustProfilesSupported() == null ? Set.of()
                : Set.copyOf(document.getDirectInstallationTrustProfilesSupported());
        if (profiles.isEmpty()) {
            throw new FedSetupValidationException("Application discovery document does not advertise a Direct Installation Trust profile");
        }
        if (profiles.contains(FedSetupConstants.BACK_CHANNEL_TRUST_PROFILE_URI)) {
            requireEndpoint(document.getInstallationTrustEndpoint(), applicationBaseUri, "installation_trust_endpoint");
        }
        if (profiles.contains(FedSetupConstants.FRONT_CHANNEL_TRUST_PROFILE_URI)) {
            requireEndpoint(document.getInstallationConsentEndpoint(), applicationBaseUri, "installation_consent_endpoint");
            requireEndpoint(document.getInstallationConfirmationEndpoint(), applicationBaseUri, "installation_confirmation_endpoint");
        }
    }

    private static void requireEndpoint(String endpoint, String baseUri, String label) {
        String canonical = FedSetupUri.canonicalize(endpoint);
        if (!sameOrigin(baseUri, canonical)) throw new FedSetupValidationException(label + " is not on the canonical Application origin");
    }

    private static boolean sameOrigin(String first, String second) {
        URI left = URI.create(first);
        URI right = URI.create(second);
        return left.getScheme().equals(right.getScheme()) && left.getHost().equals(right.getHost())
                && (left.getPort() == -1 ? 443 : left.getPort()) == (right.getPort() == -1 ? 443 : right.getPort());
    }

}
