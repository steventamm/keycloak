package org.keycloak.fedsetup.representations;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * FedSetup Configuration Discovery Document representation (`/.well-known/fedsetup/...`).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class DiscoveryDocumentRepresentation {

    @JsonProperty("fedsetup_version")
    private String fedsetupVersion = "1.0";

    @JsonProperty("application_base_uri")
    private String applicationBaseUri;

    @JsonProperty("application_name")
    private String applicationName;

    @JsonProperty("application_icon_uri")
    private String applicationIconUri;

    @JsonProperty("application_logo_uri")
    private String applicationLogoUri;

    @JsonProperty("application_tenant_mode")
    private String applicationTenantMode;

    @JsonProperty("sso_connection_cardinality")
    private String ssoConnectionCardinality;

    @JsonProperty("installation_trust_profiles_supported")
    private List<String> installationTrustProfilesSupported;

    @JsonProperty("installation_endpoint")
    private String installationEndpoint;

    @JsonProperty("installation_consent_endpoint")
    private String installationConsentEndpoint;

    @JsonProperty("installation_trust_jwks_uri")
    private String installationTrustJwksUri;

    @JsonProperty("installation_trust_deferred_approval_supported")
    private Boolean installationTrustDeferredApprovalSupported;

    @JsonProperty("configuration_endpoint")
    private String configurationEndpoint;

    @JsonProperty("configuration_resource")
    private String configurationResource;

    @JsonProperty("authorization_server")
    private String authorizationServer;

    @JsonProperty("authorization_server_metadata")
    private Map<String, Object> authorizationServerMetadata;

    @JsonProperty("connection_endpoint_template")
    private String connectionEndpointTemplate;

    @JsonProperty("connection_query_endpoint")
    private String connectionQueryEndpoint;

    @JsonProperty("provider_delegation_profiles_supported")
    private List<String> providerDelegationProfilesSupported;

    @JsonProperty("federation_extension_profiles_supported")
    private List<String> federationExtensionProfilesSupported;

    @JsonProperty("capabilities")
    private Map<String, Object> capabilities;

    @JsonProperty("installation_parameters")
    private List<Map<String, Object>> installationParameters;

    @JsonProperty("documentation_uris")
    private List<Map<String, Object>> documentationUris;

    public String getFedsetupVersion() {
        return fedsetupVersion;
    }

    public void setFedsetupVersion(String fedsetupVersion) {
        this.fedsetupVersion = fedsetupVersion;
    }

    public String getApplicationBaseUri() {
        return applicationBaseUri;
    }

    public void setApplicationBaseUri(String applicationBaseUri) {
        this.applicationBaseUri = applicationBaseUri;
    }

    public String getApplicationName() {
        return applicationName;
    }

    public void setApplicationName(String applicationName) {
        this.applicationName = applicationName;
    }

    public String getApplicationIconUri() {
        return applicationIconUri;
    }

    public void setApplicationIconUri(String applicationIconUri) {
        this.applicationIconUri = applicationIconUri;
    }

    public String getApplicationLogoUri() {
        return applicationLogoUri;
    }

    public void setApplicationLogoUri(String applicationLogoUri) {
        this.applicationLogoUri = applicationLogoUri;
    }

    public String getApplicationTenantMode() {
        return applicationTenantMode;
    }

    public void setApplicationTenantMode(String applicationTenantMode) {
        this.applicationTenantMode = applicationTenantMode;
    }

    public String getSsoConnectionCardinality() {
        return ssoConnectionCardinality;
    }

    public void setSsoConnectionCardinality(String ssoConnectionCardinality) {
        this.ssoConnectionCardinality = ssoConnectionCardinality;
    }

    public List<String> getInstallationTrustProfilesSupported() {
        return installationTrustProfilesSupported;
    }

    public void setInstallationTrustProfilesSupported(List<String> installationTrustProfilesSupported) {
        this.installationTrustProfilesSupported = installationTrustProfilesSupported;
    }

    public String getInstallationEndpoint() {
        return installationEndpoint;
    }

    public void setInstallationEndpoint(String installationEndpoint) {
        this.installationEndpoint = installationEndpoint;
    }

    public String getInstallationConsentEndpoint() {
        return installationConsentEndpoint;
    }

    public void setInstallationConsentEndpoint(String installationConsentEndpoint) {
        this.installationConsentEndpoint = installationConsentEndpoint;
    }

    public String getInstallationTrustJwksUri() {
        return installationTrustJwksUri;
    }

    public void setInstallationTrustJwksUri(String installationTrustJwksUri) {
        this.installationTrustJwksUri = installationTrustJwksUri;
    }

    public Boolean getInstallationTrustDeferredApprovalSupported() {
        return installationTrustDeferredApprovalSupported;
    }

    public void setInstallationTrustDeferredApprovalSupported(Boolean installationTrustDeferredApprovalSupported) {
        this.installationTrustDeferredApprovalSupported = installationTrustDeferredApprovalSupported;
    }

    public String getConfigurationEndpoint() {
        return configurationEndpoint;
    }

    public void setConfigurationEndpoint(String configurationEndpoint) {
        this.configurationEndpoint = configurationEndpoint;
    }

    public String getConfigurationResource() {
        return configurationResource;
    }

    public void setConfigurationResource(String configurationResource) {
        this.configurationResource = configurationResource;
    }

    public String getAuthorizationServer() {
        return authorizationServer;
    }

    public void setAuthorizationServer(String authorizationServer) {
        this.authorizationServer = authorizationServer;
    }

    public Map<String, Object> getAuthorizationServerMetadata() {
        return authorizationServerMetadata;
    }

    public void setAuthorizationServerMetadata(Map<String, Object> authorizationServerMetadata) {
        this.authorizationServerMetadata = authorizationServerMetadata;
    }

    public String getConnectionEndpointTemplate() {
        return connectionEndpointTemplate;
    }

    public void setConnectionEndpointTemplate(String connectionEndpointTemplate) {
        this.connectionEndpointTemplate = connectionEndpointTemplate;
    }

    public String getConnectionQueryEndpoint() {
        return connectionQueryEndpoint;
    }

    public void setConnectionQueryEndpoint(String connectionQueryEndpoint) {
        this.connectionQueryEndpoint = connectionQueryEndpoint;
    }

    public List<String> getProviderDelegationProfilesSupported() {
        return providerDelegationProfilesSupported;
    }

    public void setProviderDelegationProfilesSupported(List<String> providerDelegationProfilesSupported) {
        this.providerDelegationProfilesSupported = providerDelegationProfilesSupported;
    }

    public List<String> getFederationExtensionProfilesSupported() {
        return federationExtensionProfilesSupported;
    }

    public void setFederationExtensionProfilesSupported(List<String> federationExtensionProfilesSupported) {
        this.federationExtensionProfilesSupported = federationExtensionProfilesSupported;
    }

    public Map<String, Object> getCapabilities() {
        return capabilities;
    }

    public void setCapabilities(Map<String, Object> capabilities) {
        this.capabilities = capabilities;
    }

    public List<Map<String, Object>> getInstallationParameters() {
        return installationParameters;
    }

    public void setInstallationParameters(List<Map<String, Object>> installationParameters) {
        this.installationParameters = installationParameters;
    }

    public List<Map<String, Object>> getDocumentationUris() {
        return documentationUris;
    }

    public void setDocumentationUris(List<Map<String, Object>> documentationUris) {
        this.documentationUris = documentationUris;
    }
}
