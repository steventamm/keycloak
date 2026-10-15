package org.keycloak.fedsetup.representations;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * FedSetup Configuration Response representation (201 Created, 200 OK).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ConfigurationResponseRepresentation {

    @JsonProperty("connection_id")
    private String connectionId;

    @JsonProperty("application_tenant_id")
    private String applicationTenantId;

    @JsonProperty("idp_issuer")
    private String idpIssuer;

    @JsonProperty("idp_domain")
    private String idpDomain;

    @JsonProperty("connection_name")
    private String connectionName;

    @JsonProperty("initiate_login_uri")
    private String initiateLoginUri;

    @JsonProperty("trust_established")
    private Boolean trustEstablished;

    @JsonProperty("oidc")
    private OidcResponse oidc;

    @JsonProperty("saml")
    private SamlResponse saml;

    @JsonProperty("scim")
    private ScimResponse scim;

    @JsonProperty("id_jag")
    private IdJagResponse idJag;

    @JsonProperty("extensions")
    private Map<String, Object> extensions;

    @JsonProperty("created_at")
    private String createdAt;

    @JsonProperty("updated_at")
    private String updatedAt;

    public String getConnectionId() {
        return connectionId;
    }

    public void setConnectionId(String connectionId) {
        this.connectionId = connectionId;
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

    public String getConnectionName() {
        return connectionName;
    }

    public void setConnectionName(String connectionName) {
        this.connectionName = connectionName;
    }

    public String getInitiateLoginUri() {
        return initiateLoginUri;
    }

    public void setInitiateLoginUri(String initiateLoginUri) {
        this.initiateLoginUri = initiateLoginUri;
    }

    public Boolean getTrustEstablished() {
        return trustEstablished;
    }

    public void setTrustEstablished(Boolean trustEstablished) {
        this.trustEstablished = trustEstablished;
    }

    public OidcResponse getOidc() {
        return oidc;
    }

    public void setOidc(OidcResponse oidc) {
        this.oidc = oidc;
    }

    public SamlResponse getSaml() {
        return saml;
    }

    public void setSaml(SamlResponse saml) {
        this.saml = saml;
    }

    public ScimResponse getScim() {
        return scim;
    }

    public void setScim(ScimResponse scim) {
        this.scim = scim;
    }

    public IdJagResponse getIdJag() {
        return idJag;
    }

    public void setIdJag(IdJagResponse idJag) {
        this.idJag = idJag;
    }

    public Map<String, Object> getExtensions() {
        return extensions;
    }

    public void setExtensions(Map<String, Object> extensions) {
        this.extensions = extensions;
    }

    public String getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(String createdAt) {
        this.createdAt = createdAt;
    }

    public String getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(String updatedAt) {
        this.updatedAt = updatedAt;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class OidcResponse {
        @JsonProperty("client_id_metadata_uri")
        private String clientIdMetadataUri;

        @JsonProperty("redirect_uris")
        private List<String> redirectUris;

        @JsonProperty("post_logout_redirect_uris")
        private List<String> postLogoutRedirectUris;

        @JsonProperty("jwks_uri")
        private String jwksUri;

        @JsonProperty("client_security")
        private Map<String, Object> clientSecurity;

        public String getClientIdMetadataUri() {
            return clientIdMetadataUri;
        }

        public void setClientIdMetadataUri(String clientIdMetadataUri) {
            this.clientIdMetadataUri = clientIdMetadataUri;
        }

        public List<String> getRedirectUris() {
            return redirectUris;
        }

        public void setRedirectUris(List<String> redirectUris) {
            this.redirectUris = redirectUris;
        }

        public List<String> getPostLogoutRedirectUris() {
            return postLogoutRedirectUris;
        }

        public void setPostLogoutRedirectUris(List<String> postLogoutRedirectUris) {
            this.postLogoutRedirectUris = postLogoutRedirectUris;
        }

        public String getJwksUri() {
            return jwksUri;
        }

        public void setJwksUri(String jwksUri) {
            this.jwksUri = jwksUri;
        }

        public Map<String, Object> getClientSecurity() {
            return clientSecurity;
        }

        public void setClientSecurity(Map<String, Object> clientSecurity) {
            this.clientSecurity = clientSecurity;
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class SamlResponse {
        @JsonProperty("app_acs_url")
        private String appAcsUrl;

        @JsonProperty("app_entity_id")
        private String appEntityId;

        public String getAppAcsUrl() {
            return appAcsUrl;
        }

        public void setAppAcsUrl(String appAcsUrl) {
            this.appAcsUrl = appAcsUrl;
        }

        public String getAppEntityId() {
            return appEntityId;
        }

        public void setAppEntityId(String appEntityId) {
            this.appEntityId = appEntityId;
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class ScimResponse {
        @JsonProperty("provisioning_endpoint")
        private String provisioningEndpoint;

        @JsonProperty("features")
        private List<String> features;

        @JsonProperty("token_type")
        private String tokenType;

        @JsonProperty("access_token")
        private String accessToken;

        public String getProvisioningEndpoint() {
            return provisioningEndpoint;
        }

        public void setProvisioningEndpoint(String provisioningEndpoint) {
            this.provisioningEndpoint = provisioningEndpoint;
        }

        public List<String> getFeatures() {
            return features;
        }

        public void setFeatures(List<String> features) {
            this.features = features;
        }

        public String getTokenType() {
            return tokenType;
        }

        public void setTokenType(String tokenType) {
            this.tokenType = tokenType;
        }

        public String getAccessToken() {
            return accessToken;
        }

        public void setAccessToken(String accessToken) {
            this.accessToken = accessToken;
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class IdJagResponse {
        @JsonProperty("client_id")
        private String clientId;

        @JsonProperty("cimd_uri")
        private String cimdUri;

        @JsonProperty("requester_type")
        private String requesterType;

        @JsonProperty("resource_connections")
        private List<ConfigurationRequestRepresentation.ResourceConnection> resourceConnections;

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

        public String getRequesterType() {
            return requesterType;
        }

        public void setRequesterType(String requesterType) {
            this.requesterType = requesterType;
        }

        public List<ConfigurationRequestRepresentation.ResourceConnection> getResourceConnections() {
            return resourceConnections;
        }

        public void setResourceConnections(List<ConfigurationRequestRepresentation.ResourceConnection> resourceConnections) {
            this.resourceConnections = resourceConnections;
        }
    }
}
