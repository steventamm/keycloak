package org.keycloak.fedsetup.representations;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * FedSetup Configuration Request representation (POST /install, POST /configure, PATCH /connection/{id}).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ConfigurationRequestRepresentation {

    @JsonProperty("validate_only")
    private Boolean validateOnly;

    @JsonProperty("application_tenant_id")
    private String applicationTenantId;

    @JsonProperty("idp_issuer")
    private String idpIssuer;

    @JsonProperty("idp_domain")
    private String idpDomain;

    @JsonProperty("idp_name")
    private String idpName;

    @JsonProperty("idp_logo_uri")
    private String idpLogoUri;

    @JsonProperty("connection_id")
    private String connectionId;

    @JsonProperty("oidc")
    private OidcRequest oidc;

    @JsonProperty("saml")
    private SamlRequest saml;

    @JsonProperty("scim")
    private ScimRequest scim;

    @JsonProperty("id_jag")
    private IdJagRequest idJag;

    @JsonProperty("provider_delegation")
    private Map<String, Map<String, Object>> providerDelegation;

    @JsonProperty("extensions")
    private Map<String, Map<String, Object>> extensions;

    @JsonProperty("remove")
    private List<String> remove;

    @JsonProperty("remove_provider_delegation")
    private List<String> removeProviderDelegation;

    @JsonProperty("remove_extensions")
    private List<String> removeExtensions;

    @JsonProperty("metadata")
    private Map<String, Object> metadata;

    @JsonProperty("config_values")
    private Map<String, Object> configValues;

    public Boolean getValidateOnly() {
        return validateOnly;
    }

    public void setValidateOnly(Boolean validateOnly) {
        this.validateOnly = validateOnly;
    }

    public String getApplicationTenantId() {
        return applicationTenantId;
    }

    public void setApplicationTenantId(String applicationTenantId) {
        this.applicationTenantId = applicationTenantId;
    }

    public String getIdpIssuer() {
        return idpIssuer;
    }

    public void setIdpIssuer(String idpIssuer) {
        this.idpIssuer = idpIssuer;
    }

    public String getIdpDomain() {
        return idpDomain;
    }

    public void setIdpDomain(String idpDomain) {
        this.idpDomain = idpDomain;
    }

    public String getIdpName() {
        return idpName;
    }

    public void setIdpName(String idpName) {
        this.idpName = idpName;
    }

    public String getIdpLogoUri() {
        return idpLogoUri;
    }

    public void setIdpLogoUri(String idpLogoUri) {
        this.idpLogoUri = idpLogoUri;
    }

    public String getConnectionId() {
        return connectionId;
    }

    public void setConnectionId(String connectionId) {
        this.connectionId = connectionId;
    }

    public OidcRequest getOidc() {
        return oidc;
    }

    public void setOidc(OidcRequest oidc) {
        this.oidc = oidc;
    }

    public SamlRequest getSaml() {
        return saml;
    }

    public void setSaml(SamlRequest saml) {
        this.saml = saml;
    }

    public ScimRequest getScim() {
        return scim;
    }

    public void setScim(ScimRequest scim) {
        this.scim = scim;
    }

    public IdJagRequest getIdJag() {
        return idJag;
    }

    public void setIdJag(IdJagRequest idJag) {
        this.idJag = idJag;
    }

    public Map<String, Map<String, Object>> getProviderDelegation() {
        return providerDelegation;
    }

    public void setProviderDelegation(Map<String, Map<String, Object>> providerDelegation) {
        this.providerDelegation = providerDelegation;
    }

    public Map<String, Map<String, Object>> getExtensions() {
        return extensions;
    }

    public void setExtensions(Map<String, Map<String, Object>> extensions) {
        this.extensions = extensions;
    }

    public List<String> getRemove() {
        return remove;
    }

    public void setRemove(List<String> remove) {
        this.remove = remove;
    }

    public List<String> getRemoveProviderDelegation() {
        return removeProviderDelegation;
    }

    public void setRemoveProviderDelegation(List<String> removeProviderDelegation) {
        this.removeProviderDelegation = removeProviderDelegation;
    }

    public List<String> getRemoveExtensions() {
        return removeExtensions;
    }

    public void setRemoveExtensions(List<String> removeExtensions) {
        this.removeExtensions = removeExtensions;
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    public void setMetadata(Map<String, Object> metadata) {
        this.metadata = metadata;
    }

    public Map<String, Object> getConfigValues() {
        return configValues;
    }

    public void setConfigValues(Map<String, Object> configValues) {
        this.configValues = configValues;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class OidcRequest {
        @JsonProperty("issuer")
        private String issuer;

        @JsonProperty("client_id")
        private String clientId;

        @JsonProperty("client_secret")
        private String clientSecret;

        @JsonProperty("token_endpoint_auth_method")
        private String tokenEndpointAuthMethod;

        @JsonProperty("client_security")
        private Map<String, Object> clientSecurity;

        @JsonProperty("authorization_endpoint")
        private String authorizationEndpoint;

        @JsonProperty("token_endpoint")
        private String tokenEndpoint;

        @JsonProperty("jwks_uri")
        private String jwksUri;

        @JsonProperty("userinfo_endpoint")
        private String userinfoEndpoint;

        @JsonProperty("end_session_endpoint")
        private String endSessionEndpoint;

        @JsonProperty("scopes")
        private List<String> scopes;

        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public String getTokenEndpointAuthMethod() {
            return tokenEndpointAuthMethod;
        }

        public void setTokenEndpointAuthMethod(String tokenEndpointAuthMethod) {
            this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
        }

        public Map<String, Object> getClientSecurity() {
            return clientSecurity;
        }

        public void setClientSecurity(Map<String, Object> clientSecurity) {
            this.clientSecurity = clientSecurity;
        }

        public String getAuthorizationEndpoint() {
            return authorizationEndpoint;
        }

        public void setAuthorizationEndpoint(String authorizationEndpoint) {
            this.authorizationEndpoint = authorizationEndpoint;
        }

        public String getTokenEndpoint() {
            return tokenEndpoint;
        }

        public void setTokenEndpoint(String tokenEndpoint) {
            this.tokenEndpoint = tokenEndpoint;
        }

        public String getJwksUri() {
            return jwksUri;
        }

        public void setJwksUri(String jwksUri) {
            this.jwksUri = jwksUri;
        }

        public String getUserinfoEndpoint() {
            return userinfoEndpoint;
        }

        public void setUserinfoEndpoint(String userinfoEndpoint) {
            this.userinfoEndpoint = userinfoEndpoint;
        }

        public String getEndSessionEndpoint() {
            return endSessionEndpoint;
        }

        public void setEndSessionEndpoint(String endSessionEndpoint) {
            this.endSessionEndpoint = endSessionEndpoint;
        }

        public List<String> getScopes() {
            return scopes;
        }

        public void setScopes(List<String> scopes) {
            this.scopes = scopes;
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class SamlRequest {
        @JsonProperty("idp_entity_id")
        private String idpEntityId;

        @JsonProperty("idp_sso_url")
        private String idpSsoUrl;

        @JsonProperty("idp_slo_url")
        private String idpSloUrl;

        @JsonProperty("idp_certificate")
        private String idpCertificate;

        @JsonProperty("nameid_format")
        private String nameIdFormat;

        @JsonProperty("attribute_mapping")
        private Map<String, String> attributeMapping;

        @JsonProperty("idp_metadata_url")
        private String idpMetadataUrl;

        public String getIdpEntityId() {
            return idpEntityId;
        }

        public void setIdpEntityId(String idpEntityId) {
            this.idpEntityId = idpEntityId;
        }

        public String getIdpSsoUrl() {
            return idpSsoUrl;
        }

        public void setIdpSsoUrl(String idpSsoUrl) {
            this.idpSsoUrl = idpSsoUrl;
        }

        public String getIdpSloUrl() {
            return idpSloUrl;
        }

        public void setIdpSloUrl(String idpSloUrl) {
            this.idpSloUrl = idpSloUrl;
        }

        public String getIdpCertificate() {
            return idpCertificate;
        }

        public void setIdpCertificate(String idpCertificate) {
            this.idpCertificate = idpCertificate;
        }

        public String getNameIdFormat() {
            return nameIdFormat;
        }

        public void setNameIdFormat(String nameIdFormat) {
            this.nameIdFormat = nameIdFormat;
        }

        public Map<String, String> getAttributeMapping() {
            return attributeMapping;
        }

        public void setAttributeMapping(Map<String, String> attributeMapping) {
            this.attributeMapping = attributeMapping;
        }

        public String getIdpMetadataUrl() {
            return idpMetadataUrl;
        }

        public void setIdpMetadataUrl(String idpMetadataUrl) {
            this.idpMetadataUrl = idpMetadataUrl;
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class ScimRequest {
        @JsonProperty("features")
        private List<String> features;

        @JsonProperty("rotate_access_token")
        private Boolean rotateAccessToken;

        public List<String> getFeatures() {
            return features;
        }

        public void setFeatures(List<String> features) {
            this.features = features;
        }

        public Boolean getRotateAccessToken() {
            return rotateAccessToken;
        }

        public void setRotateAccessToken(Boolean rotateAccessToken) {
            this.rotateAccessToken = rotateAccessToken;
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class IdJagRequest {
        @JsonProperty("client_id")
        private String clientId;

        @JsonProperty("cimd_uri")
        private String cimdUri;

        @JsonProperty("client_secret")
        private String clientSecret;

        @JsonProperty("requester_type")
        private String requesterType;

        @JsonProperty("requester_name")
        private String requesterName;

        @JsonProperty("resource_connections")
        private List<ResourceConnection> resourceConnections;

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getCimdUri() {
            return cimdUri;
        }

        public void setCimdUri(String cimdUri) {
            this.cimdUri = cimdUri;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public String getRequesterType() {
            return requesterType;
        }

        public void setRequesterType(String requesterType) {
            this.requesterType = requesterType;
        }

        public String getRequesterName() {
            return requesterName;
        }

        public void setRequesterName(String requesterName) {
            this.requesterName = requesterName;
        }

        public List<ResourceConnection> getResourceConnections() {
            return resourceConnections;
        }

        public void setResourceConnections(List<ResourceConnection> resourceConnections) {
            this.resourceConnections = resourceConnections;
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class ResourceConnection {
        @JsonProperty("resource_connection_id")
        private String resourceConnectionId;

        @JsonProperty("resource_issuer")
        private String resourceIssuer;

        @JsonProperty("resources")
        private List<String> resources;

        @JsonProperty("scopes")
        private List<String> scopes;

        @JsonProperty("conditions")
        private Map<String, Object> conditions;

        public String getResourceConnectionId() {
            return resourceConnectionId;
        }

        public void setResourceConnectionId(String resourceConnectionId) {
            this.resourceConnectionId = resourceConnectionId;
        }

        public String getResourceIssuer() {
            return resourceIssuer;
        }

        public void setResourceIssuer(String resourceIssuer) {
            this.resourceIssuer = resourceIssuer;
        }

        public List<String> getResources() {
            return resources;
        }

        public void setResources(List<String> resources) {
            this.resources = resources;
        }

        public List<String> getScopes() {
            return scopes;
        }

        public void setScopes(List<String> scopes) {
            this.scopes = scopes;
        }

        public Map<String, Object> getConditions() {
            return conditions;
        }

        public void setConditions(Map<String, Object> conditions) {
            this.conditions = conditions;
        }
    }
}
