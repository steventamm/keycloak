/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup.representation;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSetter;

/** Configuration Request body from Section 7 of the Express Configuration draft. */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class InstallationConfigurationRequest {
    @JsonProperty("idp_issuer") private String idpIssuer;
    @JsonProperty("idp_domain") private String idpDomain;
    @JsonProperty("oidc") private OidcConfiguration oidc;
    @JsonProperty("saml") private SamlConfiguration saml;
    @JsonProperty("scim") private ScimConfiguration scim;
    @JsonProperty("provider_delegation") private Map<String, Object> providerDelegation;
    @JsonProperty("id_jag") private FedSetupIdJagConfiguration idJag;
    @JsonProperty("remove") private Set<String> remove = new LinkedHashSet<>();
    @JsonProperty("extensions") private Map<String, Object> extensions = new LinkedHashMap<>();

    // Legacy preview fields are retained only for import of already-created records.
    private String applicationTenantId;
    private String protocol;
    private String brokerAlias;
    private Map<String, String> sso = new LinkedHashMap<>();
    private Set<String> capabilities = new LinkedHashSet<>();
    private Set<String> extensionProfiles = new LinkedHashSet<>();
    private String credentialVaultReference;

    public String getIdpIssuer() { return idpIssuer; }
    public void setIdpIssuer(String value) { idpIssuer = value; }
    public String getIdpDomain() { return idpDomain; }
    public void setIdpDomain(String value) { idpDomain = value; }
    public OidcConfiguration getOidc() { return oidc; }
    public void setOidc(OidcConfiguration value) { oidc = value; }
    public SamlConfiguration getSaml() { return saml; }
    public void setSaml(SamlConfiguration value) { saml = value; }
    public ScimConfiguration getScim() { return scim; }
    public void setScim(ScimConfiguration value) { scim = value; }
    public Map<String, Object> getProviderDelegation() { return providerDelegation; }
    public void setProviderDelegation(Map<String, Object> value) { providerDelegation = value; }
    public FedSetupIdJagConfiguration getIdJag() { return idJag; }
    public void setIdJag(FedSetupIdJagConfiguration value) { idJag = value; }
    public Set<String> getRemove() { return remove; }
    public void setRemove(Set<String> value) { remove = copy(value); }
    public Map<String, Object> getExtensions() { return extensions; }
    public void setExtensions(Map<String, Object> value) { extensions = value == null ? new LinkedHashMap<>() : new LinkedHashMap<>(value); }

    @JsonIgnore public String getApplicationTenantId() { return applicationTenantId; }
    @JsonSetter("applicationTenantId") public void setApplicationTenantId(String value) { applicationTenantId = value; }
    @JsonIgnore public String getProtocol() {
        if (protocol != null) return protocol;
        return oidc != null ? "oidc" : saml != null ? "saml" : null;
    }
    @JsonSetter("protocol") public void setProtocol(String value) { protocol = value; }
    @JsonIgnore public String getBrokerAlias() { return brokerAlias; }
    @JsonSetter("brokerAlias") public void setBrokerAlias(String value) { brokerAlias = value; }
    @JsonIgnore public Map<String, String> getSso() {
        if (!sso.isEmpty()) return sso;
        Map<String, String> result = new LinkedHashMap<>();
        if (oidc != null) {
            put(result, "issuer", oidc.getIssuer());
            put(result, "authorization_endpoint", oidc.getAuthorizationEndpoint());
            put(result, "token_endpoint", oidc.getTokenEndpoint());
            put(result, "client_id", oidc.getClientId());
            put(result, "client_secret", oidc.getClientSecret());
            put(result, "client_auth_method", oidc.getTokenEndpointAuthMethod());
            if (!oidc.getScopes().isEmpty()) result.put("default_scope", String.join(" ", oidc.getScopes()));
        } else if (saml != null) {
            put(result, "entity_id", saml.getIdpEntityId());
            put(result, "single_sign_on_service", saml.getIdpSsoUrl());
            put(result, "single_logout_service", saml.getIdpSloUrl());
            put(result, "signing_certificate", saml.getIdpCertificate());
            put(result, "name_id_format", saml.getNameidFormat());
        }
        return result;
    }
    @JsonSetter("sso") public void setSso(Map<String, String> value) { sso = value == null ? new LinkedHashMap<>() : new LinkedHashMap<>(value); }
    @JsonIgnore public Set<String> getCapabilities() { return capabilities; }
    @JsonSetter("capabilities") public void setCapabilities(Set<String> value) { capabilities = copy(value); }
    @JsonIgnore public Set<String> getExtensionProfiles() { return extensionProfiles; }
    @JsonSetter("extensionProfiles") public void setExtensionProfiles(Set<String> value) { extensionProfiles = copy(value); }
    @JsonIgnore public String getCredentialVaultReference() { return credentialVaultReference; }
    @JsonSetter("credentialVaultReference") public void setCredentialVaultReference(String value) { credentialVaultReference = value; }

    /** Capabilities actually requested by an in-draft configuration body. */
    public Set<String> requestedCapabilities() {
        Set<String> result = new LinkedHashSet<>(capabilities);
        if (scim != null) result.add("scim");
        if (providerDelegation != null) result.add("provider_delegation");
        if (idJag != null) result.add("id_jag");
        return result;
    }

    private static void put(Map<String, String> values, String key, String value) {
        if (value != null && !value.isBlank()) values.put(key, value);
    }

    private static Set<String> copy(Set<String> values) {
        return values == null ? new LinkedHashSet<>() : new LinkedHashSet<>(values);
    }

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public static class OidcConfiguration {
        private String issuer;
        @JsonProperty("client_id") private String clientId;
        @JsonProperty("client_secret") private String clientSecret;
        @JsonProperty("token_endpoint_auth_method") private String tokenEndpointAuthMethod;
        @JsonProperty("authorization_endpoint") private String authorizationEndpoint;
        @JsonProperty("token_endpoint") private String tokenEndpoint;
        private Set<String> scopes = new LinkedHashSet<>();
        public String getIssuer() { return issuer; }
        public void setIssuer(String value) { issuer = value; }
        public String getClientId() { return clientId; }
        public void setClientId(String value) { clientId = value; }
        public String getClientSecret() { return clientSecret; }
        public void setClientSecret(String value) { clientSecret = value; }
        public String getTokenEndpointAuthMethod() { return tokenEndpointAuthMethod; }
        public void setTokenEndpointAuthMethod(String value) { tokenEndpointAuthMethod = value; }
        public String getAuthorizationEndpoint() { return authorizationEndpoint; }
        public void setAuthorizationEndpoint(String value) { authorizationEndpoint = value; }
        public String getTokenEndpoint() { return tokenEndpoint; }
        public void setTokenEndpoint(String value) { tokenEndpoint = value; }
        public Set<String> getScopes() { return scopes; }
        public void setScopes(Set<String> value) { scopes = copy(value); }
    }

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public static class SamlConfiguration {
        @JsonProperty("idp_entity_id") private String idpEntityId;
        @JsonProperty("idp_sso_url") private String idpSsoUrl;
        @JsonProperty("idp_slo_url") private String idpSloUrl;
        @JsonProperty("idp_certificate") private String idpCertificate;
        @JsonProperty("nameid_format") private String nameidFormat;
        @JsonProperty("attribute_mapping") private Map<String, String> attributeMapping = new LinkedHashMap<>();
        @JsonProperty("idp_metadata_url") private String idpMetadataUrl;
        public String getIdpEntityId() { return idpEntityId; }
        public void setIdpEntityId(String value) { idpEntityId = value; }
        public String getIdpSsoUrl() { return idpSsoUrl; }
        public void setIdpSsoUrl(String value) { idpSsoUrl = value; }
        public String getIdpSloUrl() { return idpSloUrl; }
        public void setIdpSloUrl(String value) { idpSloUrl = value; }
        public String getIdpCertificate() { return idpCertificate; }
        public void setIdpCertificate(String value) { idpCertificate = value; }
        public String getNameidFormat() { return nameidFormat; }
        public void setNameidFormat(String value) { nameidFormat = value; }
        public Map<String, String> getAttributeMapping() { return attributeMapping; }
        public void setAttributeMapping(Map<String, String> value) { attributeMapping = value == null ? new LinkedHashMap<>() : new LinkedHashMap<>(value); }
        public String getIdpMetadataUrl() { return idpMetadataUrl; }
        public void setIdpMetadataUrl(String value) { idpMetadataUrl = value; }
    }

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public static class ScimConfiguration {
        private Set<String> features = new LinkedHashSet<>();
        public Set<String> getFeatures() { return features; }
        public void setFeatures(Set<String> value) { features = copy(value); }
    }
}
