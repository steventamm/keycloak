/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup;

import java.lang.reflect.Proxy;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.keycloak.fedsetup.representation.CatalogDiscovery;
import org.keycloak.fedsetup.representation.CatalogSubmission;
import org.keycloak.fedsetup.representation.CatalogTarget;
import org.keycloak.fedsetup.representation.FedSetupSubmissionProfile;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;
import org.keycloak.urls.HostnameProvider;
import org.keycloak.urls.UrlType;
import org.keycloak.util.JsonSerialization;

import org.jboss.resteasy.specimpl.ResteasyUriInfo;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FedSetupSubmissionTest {

    @Test
    void permitsOnlyPublicCatalogDiscoveryTargets() {
        assertEquals("https://8.8.8.8/.well-known/fedsetup-catalog",
                CatalogSubmissionService.canonicalCatalogDiscoveryUri("HTTPS://8.8.8.8:443/.well-known/fedsetup-catalog/"));
        assertThrows(FedSetupSubmissionValidationException.class,
                () -> CatalogSubmissionService.canonicalCatalogDiscoveryUri("https://127.0.0.1/.well-known/fedsetup-catalog"));
        assertThrows(FedSetupSubmissionValidationException.class,
                () -> CatalogSubmissionService.canonicalCatalogDiscoveryUri("https://10.0.0.1/.well-known/fedsetup-catalog"));
        assertThrows(FedSetupSubmissionValidationException.class,
                () -> CatalogSubmissionService.canonicalCatalogDiscoveryUri("https://[fc00::1]/.well-known/fedsetup-catalog"));
    }

    @Test
    void rejectsUnsupportedCatalogSectionsWithoutMutatingTheManifest() {
        CatalogDiscovery discovery = new CatalogDiscovery();
        discovery.setSupportedProtocols(Set.of("oidc"));
        discovery.setSupportedCapabilities(Set.of("express_configuration"));
        Map<String, Object> manifest = new LinkedHashMap<>();
        manifest.put("identity", Map.of("oidc", Map.of()));
        manifest.put("provisioning", Map.of());

        assertThrows(FedSetupSubmissionValidationException.class,
                () -> CatalogSubmissionService.validateCapabilities(discovery, manifest));
        assertTrue(manifest.containsKey("provisioning"));
    }

    @Test
    void acceptsTheCatalogEtagFromEitherAllowedLocation() throws Exception {
        assertEquals("\"sub-4\"", CatalogSubmissionService.responseEtag(
                JsonSerialization.mapper.readTree("{\"etag\":\"\\\"sub-4\\\"\"}"), null));
        assertEquals("\"sub-5\"", CatalogSubmissionService.responseEtag(
                JsonSerialization.mapper.readTree("{\"etag\":\"\\\"sub-4\\\"\"}"), "\"sub-5\""));
    }

    @Test
    void manifestDoesNotAdvertiseExpressConfigurationWithoutEndpointMetadata() {
        Map<String, Object> manifest = SubmissionManifestGenerator.generate(session(), realmWithSamlClient(), listingProfile());

        assertFalse(manifest.containsKey("express_configuration"));
    }

    @Test
    void submissionStateIsConfinedToItsOwnNamespace() {
        Map<String, String> attributes = new LinkedHashMap<>();
        RealmFedSetupSubmissionStore store = new RealmFedSetupSubmissionStore(realm(attributes));
        store.setListingProfile(listingProfile());
        CatalogTarget target = new CatalogTarget();
        target.setName("Catalog");
        store.createCatalogTarget(target);
        CatalogSubmission submission = new CatalogSubmission();
        submission.setCatalogTargetId(target.getId());
        store.createCatalogSubmission(submission);

        assertTrue(attributes.keySet().stream().allMatch(key -> key.startsWith("fedsetup.submission.")));
    }

    private static FedSetupSubmissionProfile listingProfile() {
        FedSetupSubmissionProfile profile = new FedSetupSubmissionProfile();
        profile.setDisplayName("Example service");
        profile.setDescription("An example service");
        profile.setLogoUri("https://service.example/logo.svg");
        profile.setHomepageUri("https://service.example/");
        profile.setPrivacyPolicyUri("https://service.example/privacy");
        profile.setTermsOfServiceUri("https://service.example/terms");
        profile.setManifestVersion("1.0");
        profile.setContacts(List.of(Map.of("name", "Example administrator", "email", "admin@service.example")));
        profile.setSamlClientId("saml-client");
        return profile;
    }

    private static KeycloakSession session() {
        Object[] contextHolder = new Object[1];
        HostnameProvider hostnameProvider = (HostnameProvider) Proxy.newProxyInstance(FedSetupSubmissionTest.class.getClassLoader(),
                new Class<?>[] { HostnameProvider.class }, (proxy, method, args) -> {
                    if (method.getName().equals("getBaseUri")) return URI.create("https://keycloak.example/");
                    return null;
                });
        KeycloakSession session = (KeycloakSession) Proxy.newProxyInstance(FedSetupSubmissionTest.class.getClassLoader(),
                new Class<?>[] { KeycloakSession.class }, (proxy, method, args) -> {
                    if (method.getName().equals("getContext")) return contextHolder[0];
                    if (method.getName().equals("getProvider")) return hostnameProvider;
                    return null;
                });
        KeycloakUriInfo uriInfo = new KeycloakUriInfo(session, UrlType.FRONTEND,
                new ResteasyUriInfo("https://keycloak.example/", "/"));
        KeycloakContext context = (KeycloakContext) Proxy.newProxyInstance(FedSetupSubmissionTest.class.getClassLoader(),
                new Class<?>[] { KeycloakContext.class }, (proxy, method, args) -> {
                    if (method.getName().equals("getUri")) return uriInfo;
                    return null;
                });
        contextHolder[0] = context;
        return session;
    }

    private static RealmModel realmWithSamlClient() {
        ClientModel client = (ClientModel) Proxy.newProxyInstance(FedSetupSubmissionTest.class.getClassLoader(),
                new Class<?>[] { ClientModel.class }, (proxy, method, args) -> switch (method.getName()) {
                    case "getProtocol" -> "saml";
                    case "getClientId" -> "saml-client";
                    case "getRedirectUris" -> Set.of("https://service.example/saml/acs");
                    case "getAttribute" -> null;
                    default -> null;
                });
        return (RealmModel) Proxy.newProxyInstance(FedSetupSubmissionTest.class.getClassLoader(),
                new Class<?>[] { RealmModel.class }, (proxy, method, args) -> {
                    if (method.getName().equals("getClientByClientId")) return client;
                    return null;
                });
    }

    private static RealmModel realm(Map<String, String> attributes) {
        return (RealmModel) Proxy.newProxyInstance(FedSetupSubmissionTest.class.getClassLoader(),
                new Class<?>[] { RealmModel.class }, (proxy, method, args) -> switch (method.getName()) {
                    case "getAttribute" -> attributes.get(args[0]);
                    case "setAttribute" -> attributes.put((String) args[0], (String) args[1]);
                    default -> null;
                });
    }
}
