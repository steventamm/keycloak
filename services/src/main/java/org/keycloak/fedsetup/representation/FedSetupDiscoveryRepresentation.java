/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup.representation;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/** Public realm-scoped FedSetup discovery document defined by draft-ietf-fedsetup-express-configuration. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class FedSetupDiscoveryRepresentation {
    @JsonProperty("fedsetup_version") private String fedsetupVersion;
    @JsonProperty("application_base_uri") private String applicationBaseUri;
    @JsonProperty("configuration_endpoint") private String configurationEndpoint;
    @JsonProperty("connection_endpoint_template") private String connectionEndpointTemplate;
    @JsonProperty("protocols_supported") private List<String> protocolsSupported = new ArrayList<>();
    @JsonProperty("provisioning_supported") private Boolean provisioningSupported;
    @JsonProperty("id_jag_supported") private Boolean idJagSupported;
    @JsonProperty("id_jag_requester_types_supported") private List<String> idJagRequesterTypesSupported = new ArrayList<>();
    @JsonProperty("saml_sp_initiated_slo_supported") private Boolean samlSpInitiatedSloSupported;
    @JsonProperty("provider_delegation_profiles_supported") private List<String> providerDelegationProfilesSupported = new ArrayList<>();
    @JsonProperty("federation_extension_profiles_supported") private List<String> federationExtensionProfilesSupported = new ArrayList<>();
    @JsonProperty("layered_updates_supported") private Boolean layeredUpdatesSupported;
    @JsonProperty("sso_connection_cardinality") private String ssoConnectionCardinality;
    @JsonProperty("documentation_uri") private String documentationUri;
    @JsonProperty("direct_installation_trust_profiles_supported") private List<String> directInstallationTrustProfilesSupported = new ArrayList<>();
    @JsonProperty("installation_trust_endpoint") private String installationTrustEndpoint;
    @JsonProperty("installation_authorization_endpoint") private String installationAuthorizationEndpoint;
    @JsonProperty("installation_token_endpoint") private String installationTokenEndpoint;

    public String getFedsetupVersion() { return fedsetupVersion; }
    public void setFedsetupVersion(String value) { fedsetupVersion = value; }
    public String getApplicationBaseUri() { return applicationBaseUri; }
    public void setApplicationBaseUri(String value) { applicationBaseUri = value; }
    public String getConfigurationEndpoint() { return configurationEndpoint; }
    public void setConfigurationEndpoint(String value) { configurationEndpoint = value; }
    public String getConnectionEndpointTemplate() { return connectionEndpointTemplate; }
    public void setConnectionEndpointTemplate(String value) { connectionEndpointTemplate = value; }
    public List<String> getProtocolsSupported() { return protocolsSupported; }
    public void setProtocolsSupported(List<String> value) { protocolsSupported = value == null ? new ArrayList<>() : new ArrayList<>(value); }
    public Boolean getProvisioningSupported() { return provisioningSupported; }
    public void setProvisioningSupported(Boolean value) { provisioningSupported = value; }
    public Boolean getIdJagSupported() { return idJagSupported; }
    public void setIdJagSupported(Boolean value) { idJagSupported = value; }
    public List<String> getIdJagRequesterTypesSupported() { return idJagRequesterTypesSupported; }
    public void setIdJagRequesterTypesSupported(List<String> value) { idJagRequesterTypesSupported = value == null ? new ArrayList<>() : new ArrayList<>(value); }
    public Boolean getSamlSpInitiatedSloSupported() { return samlSpInitiatedSloSupported; }
    public void setSamlSpInitiatedSloSupported(Boolean value) { samlSpInitiatedSloSupported = value; }
    public List<String> getProviderDelegationProfilesSupported() { return providerDelegationProfilesSupported; }
    public void setProviderDelegationProfilesSupported(List<String> value) { providerDelegationProfilesSupported = value == null ? new ArrayList<>() : new ArrayList<>(value); }
    public List<String> getFederationExtensionProfilesSupported() { return federationExtensionProfilesSupported; }
    public void setFederationExtensionProfilesSupported(List<String> value) { federationExtensionProfilesSupported = value == null ? new ArrayList<>() : new ArrayList<>(value); }
    public Boolean getLayeredUpdatesSupported() { return layeredUpdatesSupported; }
    public void setLayeredUpdatesSupported(Boolean value) { layeredUpdatesSupported = value; }
    public String getSsoConnectionCardinality() { return ssoConnectionCardinality; }
    public void setSsoConnectionCardinality(String value) { ssoConnectionCardinality = value; }
    public String getDocumentationUri() { return documentationUri; }
    public void setDocumentationUri(String value) { documentationUri = value; }
    public List<String> getDirectInstallationTrustProfilesSupported() { return directInstallationTrustProfilesSupported; }
    public void setDirectInstallationTrustProfilesSupported(List<String> value) { directInstallationTrustProfilesSupported = value == null ? new ArrayList<>() : new ArrayList<>(value); }
    public String getInstallationTrustEndpoint() { return installationTrustEndpoint; }
    public void setInstallationTrustEndpoint(String value) { installationTrustEndpoint = value; }
    public String getInstallationAuthorizationEndpoint() { return installationAuthorizationEndpoint; }
    public void setInstallationAuthorizationEndpoint(String value) { installationAuthorizationEndpoint = value; }
    public String getInstallationTokenEndpoint() { return installationTokenEndpoint; }
    public void setInstallationTokenEndpoint(String value) { installationTokenEndpoint = value; }
}
