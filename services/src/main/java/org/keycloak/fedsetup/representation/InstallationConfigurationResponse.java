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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/** Public, secret-free Connection representation from Section 8.1. */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class InstallationConfigurationResponse {
    @JsonProperty("connection_id") private String connectionId;
    @JsonProperty("connection_name") private String connectionName;
    @JsonProperty("initiate_login_uri") private String initiateLoginUri;
    @JsonProperty("idp_domain") private String idpDomain;
    @JsonProperty("created_at") private String createdAt;
    @JsonProperty("updated_at") private String updatedAt;
    private ScimResponse scim;
    @JsonProperty("id_jag") private FedSetupIdJagConfiguration idJag;
    private Map<String, Object> extensions = new LinkedHashMap<>();

    public String getConnectionId() { return connectionId; }
    public void setConnectionId(String value) { connectionId = value; }
    public String getConnectionName() { return connectionName; }
    public void setConnectionName(String value) { connectionName = value; }
    public String getInitiateLoginUri() { return initiateLoginUri; }
    public void setInitiateLoginUri(String value) { initiateLoginUri = value; }
    public String getIdpDomain() { return idpDomain; }
    public void setIdpDomain(String value) { idpDomain = value; }
    public String getCreatedAt() { return createdAt; }
    public void setCreatedAt(String value) { createdAt = value; }
    public String getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(String value) { updatedAt = value; }
    public ScimResponse getScim() { return scim; }
    public void setScim(ScimResponse value) { scim = value; }
    public FedSetupIdJagConfiguration getIdJag() { return idJag; }
    public void setIdJag(FedSetupIdJagConfiguration value) { idJag = value; }
    public Map<String, Object> getExtensions() { return extensions; }
    public void setExtensions(Map<String, Object> value) { extensions = value == null ? new LinkedHashMap<>() : new LinkedHashMap<>(value); }

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public static class ScimResponse {
        @JsonProperty("provisioning_endpoint") private String provisioningEndpoint;
        @JsonProperty("token_type") private String tokenType;
        @JsonProperty("access_token") private String accessToken;
        private Set<String> features = new LinkedHashSet<>();
        public String getProvisioningEndpoint() { return provisioningEndpoint; }
        public void setProvisioningEndpoint(String value) { provisioningEndpoint = value; }
        public String getTokenType() { return tokenType; }
        public void setTokenType(String value) { tokenType = value; }
        public String getAccessToken() { return accessToken; }
        public void setAccessToken(String value) { accessToken = value; }
        public Set<String> getFeatures() { return features; }
        public void setFeatures(Set<String> value) { features = value == null ? new LinkedHashSet<>() : new LinkedHashSet<>(value); }
    }
}
