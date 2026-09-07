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
import java.util.Collection;
import java.util.Objects;

import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.http.simple.SimpleHttpResponse;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;
import org.keycloak.util.JsonSerialization;

import org.apache.http.client.config.RequestConfig;
import org.apache.http.conn.util.DomainType;
import org.apache.http.conn.util.PublicSuffixMatcher;
import org.apache.http.conn.util.PublicSuffixMatcherLoader;

/** Establishes the non-self-asserted issuer-to-installation-runtime binding for deferred proposals. */
public final class FedSetupIdpRuntimeBinding {

    private FedSetupIdpRuntimeBinding() {
    }

    public static void requireBound(KeycloakSession session, RealmFedSetupStore store, String idpIssuer, String cimdUri) {
        if (sameRegistrableDomain(idpIssuer, cimdUri) || store.hasIdpPlatformPolicy(idpIssuer, cimdUri) || metadataBinds(session, idpIssuer, cimdUri)) {
            return;
        }
        throw new FedSetupValidationException("No active Direct Installation Trust authorization matches this request");
    }

    private static boolean sameRegistrableDomain(String idpIssuer, String cimdUri) {
        String issuerHost = URI.create(idpIssuer).getHost();
        String cimdHost = URI.create(cimdUri).getHost();
        if (issuerHost == null || cimdHost == null) return false;
        PublicSuffixMatcher matcher = PublicSuffixMatcherLoader.getDefault();
        String issuerDomain = matcher.getDomainRoot(issuerHost, DomainType.ICANN);
        String cimdDomain = matcher.getDomainRoot(cimdHost, DomainType.ICANN);
        return issuerDomain != null && issuerDomain.equalsIgnoreCase(cimdDomain);
    }

    private static boolean metadataBinds(KeycloakSession session, String idpIssuer, String cimdUri) {
        String discovery = FedSetupOidcMetadataResolver.discoveryUri(idpIssuer);
        FedSetupUri.requirePublicAddress(discovery, "IdP authorization-server metadata");
        RequestConfig noRedirects = RequestConfig.copy(RequestConfig.DEFAULT).setRedirectsEnabled(false).build();
        try (SimpleHttpResponse response = SimpleHttp.create(session).withRequestConfig(noRedirects).doGet(discovery).acceptJson().asResponse()) {
            if (response.getStatus() != 200) return false;
            OIDCConfigurationRepresentation metadata = JsonSerialization.readValue(response.asString(), OIDCConfigurationRepresentation.class);
            if (metadata == null || !Objects.equals(idpIssuer, FedSetupUri.canonicalize(metadata.getIssuer()))) return false;
            Object configured = metadata.getOtherClaims().get("fedsetup_installation_cimd_uris");
            return configured instanceof Collection<?> values && values.stream().anyMatch(cimdUri::equals);
        } catch (IOException | RuntimeException ignored) {
            return false;
        }
    }
}
