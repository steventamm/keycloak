/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import jakarta.ws.rs.core.UriInfo;

import org.keycloak.OAuth2Constants;
import org.keycloak.common.Profile;
import org.keycloak.fedsetup.representation.FedSetupSubmissionProfile;
import org.keycloak.fedsetup.representation.FedSetupSubmissionIdJagResourceBinding;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.saml.SamlConfigAttributes;
import org.keycloak.protocol.saml.SamlProtocol;
import org.keycloak.services.Urls;
import org.keycloak.services.resources.RealmsResource;
import org.keycloak.urls.UrlType;

/**
 * Produces the Submission API manifest from administrator-owned Listing data
 * and already-configured Keycloak clients.  This class has no mutating API;
 * manifest generation cannot register a client or establish runtime trust.
 */
public final class SubmissionManifestGenerator {

    private SubmissionManifestGenerator() {
    }

    public static Map<String, Object> generate(KeycloakSession session, RealmModel realm, FedSetupSubmissionProfile profile) {
        requireListingFields(profile);
        UriInfo frontendUri = session.getContext().getUri(UrlType.FRONTEND);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("name", profile.getDisplayName());
        result.put("description", profile.getDescription());
        result.put("logo_uri", profile.getLogoUri());
        result.put("homepage_uri", profile.getHomepageUri());
        result.put("privacy_policy_uri", profile.getPrivacyPolicyUri());
        result.put("terms_of_service_uri", profile.getTermsOfServiceUri());
        result.put("version", profile.getManifestVersion());
        result.put("contacts", copyList(profile.getContacts()));
        putIfNotEmpty(result, "categories", profile.getCategories());
        putIfNotEmpty(result, "deployment_regions", profile.getDeploymentRegions());
        putIfNotBlank(result, "changelog", profile.getChangelog());

        Map<String, Object> identity = new LinkedHashMap<>();
        if (notBlank(profile.getOidcClientId())) {
            identity.put("oidc", oidc(session, realm, profile, frontendUri));
        }
        if (notBlank(profile.getSamlClientId())) {
            identity.put("saml", saml(realm, profile));
        }
        if (identity.isEmpty()) {
            throw new FedSetupSubmissionValidationException("An OIDC or SAML client is required to generate a manifest");
        }
        result.put("identity", identity);

        if (profile.getCapabilities().contains("scim")) {
            result.put("provisioning", provisioning(session, realm, frontendUri));
        }
        if (profile.getCapabilities().contains("id_jag")) {
            result.put("id_jag", idJag(realm, profile, frontendUri));
        }
        // TODO: Add an administrator-configured express_configuration object without
        // depending on the Express Configuration implementation.
        // result.put("express_configuration", expressConfiguration(realm, profile, frontendUri));
        if (!profile.getTestEvidence().isEmpty()) {
            result.put("test_account", new LinkedHashMap<>(profile.getTestEvidence()));
        }
        if (!profile.getCatalogConfiguration().isEmpty()) {
            result.put("catalog", new LinkedHashMap<>(profile.getCatalogConfiguration()));
        }
        return result;
    }

    private static Map<String, Object> oidc(KeycloakSession session, RealmModel realm, FedSetupSubmissionProfile profile, UriInfo frontendUri) {
        ClientModel client = requireClient(realm, profile.getOidcClientId(), "openid-connect");
        OIDCAdvancedConfigWrapper config = OIDCAdvancedConfigWrapper.fromClientModel(client);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("redirect_uris", canonicalUris(client.getRedirectUris(), "OIDC redirect URI"));
        result.put("client_type", client.isPublicClient() ? "spa" : "web");
        putIfNotBlank(result, "initiate_login_uri", profile.getInitiateLoginUri());
        putIfNotEmpty(result, "post_logout_uris", canonicalUris(config.getPostLogoutRedirectUris(), "OIDC post-logout URI"));
        result.put("grant_types", enabledGrantTypes(client));
        result.put("response_types", responseTypes(client));
        result.put("token_endpoint_auth_method", clientAuthenticationMethod(client));
        if (config.isUseJwksUrl() && notBlank(config.getJwksUrl())) {
            result.put("jwks_uri", FedSetupSubmissionUri.canonicalize(config.getJwksUrl()));
        }
        Set<String> scopes = new LinkedHashSet<>(client.getClientScopes(true).keySet());
        scopes.addAll(profile.getOidcScopes());
        scopes.removeAll(Set.of("openid", "profile", "email"));
        putIfNotEmpty(result, "scopes", scopes);
        putIfNotEmpty(result, "scope_justifications", profile.getScopeJustifications());
        putIfNotBlank(result, "documentation_uri", profile.getOidcDocumentationUri());
        String backchannelLogout = config.getBackchannelLogoutUrl();
        if (notBlank(backchannelLogout)) {
            result.put("backchannel_logout_uri", FedSetupSubmissionUri.canonicalize(backchannelLogout));
        }
        // This is emitted for Catalog review and is intentionally not a trust input.
        result.put("keycloak_issuer", Urls.realmIssuer(frontendUri.getBaseUri(), realm.getName()));
        return result;
    }

    private static Map<String, Object> saml(RealmModel realm, FedSetupSubmissionProfile profile) {
        ClientModel client = requireClient(realm, profile.getSamlClientId(), "saml");
        Map<String, Object> result = new LinkedHashMap<>();
        List<Map<String, Object>> acsUrls = new ArrayList<>();
        String acs = client.getAttribute(SamlProtocol.SAML_ASSERTION_CONSUMER_URL_POST_ATTRIBUTE);
        if (notBlank(acs)) {
            acsUrls.add(acsUrl(acs, "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", true));
        }
        for (String redirect : client.getRedirectUris()) {
            String canonical = FedSetupSubmissionUri.canonicalize(redirect);
            if (acsUrls.stream().noneMatch(entry -> canonical.equals(entry.get("url")))) {
                acsUrls.add(acsUrl(canonical, "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", acsUrls.isEmpty()));
            }
        }
        if (acsUrls.isEmpty()) {
            throw new FedSetupSubmissionValidationException("The selected SAML client has no ACS URL");
        }
        result.put("acs_urls", acsUrls);
        result.put("entity_id", client.getClientId());
        putRawIfNotBlank(result, "nameid_format", client.getAttribute(SamlConfigAttributes.SAML_NAME_ID_FORMAT_ATTRIBUTE));
        String slo = firstNonBlank(client.getAttribute(SamlProtocol.SAML_SINGLE_LOGOUT_SERVICE_URL_POST_ATTRIBUTE),
                client.getAttribute(SamlProtocol.SAML_SINGLE_LOGOUT_SERVICE_URL_REDIRECT_ATTRIBUTE),
                client.getAttribute(SamlProtocol.SAML_SINGLE_LOGOUT_SERVICE_URL_ARTIFACT_ATTRIBUTE),
                client.getAttribute(SamlProtocol.SAML_SINGLE_LOGOUT_SERVICE_URL_SOAP_ATTRIBUTE));
        if (slo != null) {
            result.put("slo_url", FedSetupSubmissionUri.canonicalize(slo));
        }
        if (profile.isSamlSpInitiatedSloSupported()) {
            if (slo == null) {
                throw new FedSetupSubmissionValidationException("The selected SAML client needs a Single Logout URL when SP-initiated SLO is enabled");
            }
            result.put("sp_initiated_slo_supported", true);
        }
        putIfNotBlank(result, "documentation_uri", profile.getSamlDocumentationUri());
        return result;
    }

    private static Map<String, Object> provisioning(KeycloakSession session, RealmModel realm, UriInfo frontendUri) {
        if (!Profile.isFeatureEnabled(Profile.Feature.SCIM_API) || !realm.isScimApiEnabled()) {
            throw new FedSetupSubmissionValidationException("The realm's native SCIM API must be enabled before generating scim metadata");
        }
        Map<String, Object> scim = new LinkedHashMap<>();
        scim.put("base_uri", RealmsResource.realmBaseUrl(frontendUri).build(realm.getName()).toString() + "/scim/v2");
        // Core mode; Section 6.3.1 forbids token_endpoint for SAAS_ISSUED_BEARER.
        scim.put("auth_mode", "SAAS_ISSUED_BEARER");
        scim.put("supported_schemas", List.of("urn:ietf:params:scim:schemas:core:2.0:User",
                "urn:ietf:params:scim:schemas:core:2.0:Group"));
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("features", List.of("PUSH_NEW_USERS", "PUSH_USER_DEACTIVATION", "REACTIVATE_USERS", "PUSH_PROFILE_UPDATES", "PUSH_GROUPS"));
        result.put("scim", scim);
        return result;
    }

    /** Emits only Keycloak's resource-app role; Keycloak does not issue ID-JAG assertions in this preview. */
    private static Map<String, Object> idJag(RealmModel realm, FedSetupSubmissionProfile profile, UriInfo frontendUri) {
        if (!Profile.isFeatureEnabled(Profile.Feature.IDENTITY_ASSERTION_JWT) || profile.getIdJagResourceBindings().isEmpty()) {
            throw new FedSetupSubmissionValidationException("The Identity Assertion JWT feature and an ID-JAG resource binding are required to generate id_jag metadata");
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("role", "resource_app");
        result.put("resource_app", idJagResourceApp(Urls.realmIssuer(frontendUri.getBaseUri(), realm.getName()), profile.getIdJagResourceBindings()));
        return result;
    }

    static Map<String, Object> idJagResourceApp(String issuer, List<FedSetupSubmissionIdJagResourceBinding> bindings) {
        Set<String> resources = new LinkedHashSet<>();
        Set<String> scopes = new LinkedHashSet<>();
        for (FedSetupSubmissionIdJagResourceBinding binding : bindings) {
            if (binding == null || !notBlank(binding.getResource()) || binding.getScopes().isEmpty()) {
                throw new FedSetupSubmissionValidationException("Each ID-JAG resource binding requires a resource and at least one scope");
            }
            resources.add(FedSetupSubmissionUri.canonicalize(binding.getResource()));
            scopes.addAll(binding.getScopes());
        }
        Map<String, Object> resourceApp = new LinkedHashMap<>();
        resourceApp.put("issuer_uri", issuer);
        resourceApp.put("protected_resources", resources);
        resourceApp.put("scopes", scopes);
        // Keycloak materializes a managed confidential client for every
        // approved FedSetup Connection. It therefore does not accept an
        // arbitrary CIMD client without that administrator-approved binding.
        resourceApp.put("cimd_supported", false);
        return resourceApp;
    }

    static List<String> enabledGrantTypes(ClientModel client) {
        List<String> result = new ArrayList<>();
        if (client.isStandardFlowEnabled()) result.add(OAuth2Constants.AUTHORIZATION_CODE);
        if (client.isImplicitFlowEnabled()) result.add("implicit");
        if (client.isDirectAccessGrantsEnabled()) result.add("password");
        if (client.isServiceAccountsEnabled()) result.add("client_credentials");
        return result;
    }

    static List<String> responseTypes(ClientModel client) {
        List<String> result = new ArrayList<>();
        if (client.isStandardFlowEnabled()) result.add("code");
        if (client.isImplicitFlowEnabled()) {
            result.add("id_token");
            result.add("id_token token");
        }
        if (client.isStandardFlowEnabled() && client.isImplicitFlowEnabled()) {
            result.add("code id_token");
            result.add("code token");
            result.add("code id_token token");
        }
        return result;
    }

    private static String clientAuthenticationMethod(ClientModel client) {
        if (client.isPublicClient() || "none".equals(client.getClientAuthenticatorType())) return "none";
        String authenticator = client.getClientAuthenticatorType();
        if (authenticator == null || "client-secret".equals(authenticator)) return "client_secret_basic";
        return switch (authenticator) {
            case "client-jwt" -> "private_key_jwt";
            case "client-secret-post" -> "client_secret_post";
            default -> throw new FedSetupSubmissionValidationException("The selected OIDC client authentication method is not representable by the FedSetup profile");
        };
    }

    private static ClientModel requireClient(RealmModel realm, String clientId, String protocol) {
        ClientModel client = realm.getClientByClientId(clientId);
        if (client == null || !protocol.equals(client.getProtocol())) {
            throw new FedSetupSubmissionValidationException("A pre-created " + protocol + " client is required");
        }
        return client;
    }

    private static List<Map<String, Object>> copyList(List<Map<String, Object>> source) {
        List<Map<String, Object>> result = new ArrayList<>();
        for (Map<String, Object> entry : source) result.add(new LinkedHashMap<>(entry));
        return result;
    }

    private static Map<String, Object> acsUrl(String uri, String binding, boolean isDefault) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("url", FedSetupSubmissionUri.canonicalize(uri));
        result.put("binding", binding);
        if (isDefault) result.put("is_default", true);
        return result;
    }

    private static List<String> canonicalUris(Iterable<String> values, String label) {
        List<String> result = new ArrayList<>();
        if (values == null) return result;
        for (String value : values) {
            if (value == null || value.contains("*") || value.contains("${")) {
                throw new FedSetupSubmissionValidationException(label + " must be a concrete HTTPS URI");
            }
            result.add(FedSetupSubmissionUri.canonicalize(value));
        }
        return result;
    }

    private static void requireListingFields(FedSetupSubmissionProfile profile) {
        if (!notBlank(profile.getDisplayName()) || !notBlank(profile.getDescription()) || !notBlank(profile.getLogoUri())
                || !notBlank(profile.getHomepageUri()) || !notBlank(profile.getPrivacyPolicyUri()) || !notBlank(profile.getTermsOfServiceUri())
                || !notBlank(profile.getManifestVersion()) || profile.getContacts().isEmpty()) {
            throw new FedSetupSubmissionValidationException("name, description, logo URI, homepage URI, privacy policy URI, terms URI, manifest version, and contacts are required to generate a manifest");
        }
    }

    private static String firstNonBlank(String... values) {
        for (String value : values) if (notBlank(value)) return value;
        return null;
    }

    private static boolean notBlank(String value) {
        return value != null && !value.isBlank();
    }

    private static void putIfNotBlank(Map<String, Object> target, String name, String value) {
        if (notBlank(value)) target.put(name, FedSetupSubmissionUri.canonicalize(value));
    }

    private static void putRawIfNotBlank(Map<String, Object> target, String name, String value) {
        if (notBlank(value)) target.put(name, value);
    }

    private static void putIfNotEmpty(Map<String, Object> target, String name, Map<?, ?> value) {
        if (value != null && !value.isEmpty()) target.put(name, new LinkedHashMap<>(value));
    }

    private static void putIfNotEmpty(Map<String, Object> target, String name, Iterable<?> value) {
        if (value == null) return;
        List<Object> copy = new ArrayList<>();
        for (Object item : value) copy.add(item);
        if (!copy.isEmpty()) target.put(name, copy);
    }
}
