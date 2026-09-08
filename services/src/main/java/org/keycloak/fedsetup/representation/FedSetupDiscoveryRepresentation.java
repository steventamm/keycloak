/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup.representation;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/** Public realm-scoped FedSetup discovery document defined by draft-ietf-fedsetup-express-configuration. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class FedSetupDiscoveryRepresentation {
    @JsonProperty("fedsetup_version") private String fedsetupVersion;
    @JsonProperty("application_base_uri") private String applicationBaseUri;
    @JsonProperty("authorization_server") private String authorizationServer;
    @JsonProperty("configuration_endpoint") private String configurationEndpoint;
    @JsonProperty("configuration_resource") private String configurationResource;
    @JsonProperty("connection_endpoint_template") private String connectionEndpointTemplate;
    @JsonProperty("capabilities") private Map<String, Object> capabilities = new LinkedHashMap<>();
    @JsonProperty("connection_query_endpoint") private String connectionQueryEndpoint;
    @JsonProperty("provider_delegation_profiles_supported") private List<String> providerDelegationProfilesSupported = new ArrayList<>();
    @JsonProperty("federation_extension_profiles_supported") private List<String> federationExtensionProfilesSupported = new ArrayList<>();
    @JsonProperty("sso_connection_cardinality") private String ssoConnectionCardinality;
    @JsonProperty("installation_trust_profiles_supported") private List<String> installationTrustProfilesSupported = new ArrayList<>();
    @JsonProperty("installation_trust_endpoint") private String installationTrustEndpoint;
    @JsonProperty("installation_consent_endpoint") private String installationConsentEndpoint;
    @JsonProperty("installation_confirmation_endpoint") private String installationConfirmationEndpoint;
    @JsonProperty("installation_trust_jwks_uri") private String installationTrustJwksUri;
    @JsonProperty("installation_trust_deferred_approval_supported") private Boolean installationTrustDeferredApprovalSupported;

    public String getFedsetupVersion() { return fedsetupVersion; }
    public void setFedsetupVersion(String value) { fedsetupVersion = value; }
    public String getApplicationBaseUri() { return applicationBaseUri; }
    public void setApplicationBaseUri(String value) { applicationBaseUri = value; }
    public String getAuthorizationServer() { return authorizationServer; }
    public void setAuthorizationServer(String value) { authorizationServer = value; }
    public String getConfigurationEndpoint() { return configurationEndpoint; }
    public void setConfigurationEndpoint(String value) { configurationEndpoint = value; }
    public String getConfigurationResource() { return configurationResource; }
    public void setConfigurationResource(String value) { configurationResource = value; }
    public String getConnectionEndpointTemplate() { return connectionEndpointTemplate; }
    public void setConnectionEndpointTemplate(String value) { connectionEndpointTemplate = value; }
    public Map<String, Object> getCapabilities() { return capabilities; }
    public void setCapabilities(Map<String, Object> value) { capabilities = value == null ? new LinkedHashMap<>() : new LinkedHashMap<>(value); }
    public String getConnectionQueryEndpoint() { return connectionQueryEndpoint; }
    public void setConnectionQueryEndpoint(String value) { connectionQueryEndpoint = value; }
    public List<String> getProviderDelegationProfilesSupported() { return providerDelegationProfilesSupported; }
    public void setProviderDelegationProfilesSupported(List<String> value) { providerDelegationProfilesSupported = value == null ? new ArrayList<>() : new ArrayList<>(value); }
    public List<String> getFederationExtensionProfilesSupported() { return federationExtensionProfilesSupported; }
    public void setFederationExtensionProfilesSupported(List<String> value) { federationExtensionProfilesSupported = value == null ? new ArrayList<>() : new ArrayList<>(value); }
    public String getSsoConnectionCardinality() { return ssoConnectionCardinality; }
    public void setSsoConnectionCardinality(String value) { ssoConnectionCardinality = value; }
    public List<String> getInstallationTrustProfilesSupported() { return installationTrustProfilesSupported; }
    public void setInstallationTrustProfilesSupported(List<String> value) { installationTrustProfilesSupported = value == null ? new ArrayList<>() : new ArrayList<>(value); }
    public String getInstallationTrustEndpoint() { return installationTrustEndpoint; }
    public void setInstallationTrustEndpoint(String value) { installationTrustEndpoint = value; }
    public String getInstallationConsentEndpoint() { return installationConsentEndpoint; }
    public void setInstallationConsentEndpoint(String value) { installationConsentEndpoint = value; }
    public String getInstallationConfirmationEndpoint() { return installationConfirmationEndpoint; }
    public void setInstallationConfirmationEndpoint(String value) { installationConfirmationEndpoint = value; }
    public String getInstallationTrustJwksUri() { return installationTrustJwksUri; }
    public void setInstallationTrustJwksUri(String value) { installationTrustJwksUri = value; }
    public Boolean getInstallationTrustDeferredApprovalSupported() { return installationTrustDeferredApprovalSupported; }
    public void setInstallationTrustDeferredApprovalSupported(Boolean value) { installationTrustDeferredApprovalSupported = value; }
}
