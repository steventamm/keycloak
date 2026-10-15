package org.keycloak.fedsetup.model;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.keycloak.fedsetup.representations.ConfigurationRequestRepresentation;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class ConnectionRecord {

    private String connectionId;
    private String trustId;
    private String authenticatedClientContext;
    private String applicationTenantId;
    private String idpIssuer;
    private String idpDomain;
    private String idpName;
    private String idpLogoUri;
    private String connectionName;
    private String origin = "fedsetup"; // "fedsetup" or "adopted"
    private String status = "active";   // "active" or "deactivated"
    private int version = 1;
    private String etag;
    private String keycloakIdpAlias;

    private OidcState oidcState;
    private SamlState samlState;
    private ScimState scimState;
    private IdJagState idJagState;
    private Map<String, Map<String, Object>> providerDelegationState = new LinkedHashMap<>();
    private Map<String, Map<String, Object>> extensionsState = new LinkedHashMap<>();
    private Map<String, String> staticSecretsHashes = new LinkedHashMap<>();
    private Map<String, Object> metadata = new LinkedHashMap<>();
    private Map<String, Object> configValues = new LinkedHashMap<>();
    private long createdAt;
    private long updatedAt;

    public List<String> getEnabledCapabilities() {
        List<String> caps = new ArrayList<>();
        if (oidcState != null) {
            caps.add("oidc");
        }
        if (samlState != null) {
            caps.add("saml");
        }
        if (scimState != null) {
            caps.add("scim");
        }
        if (idJagState != null) {
            caps.add("id_jag");
        }
        return caps;
    }

    public String getConnectionId() {
        return connectionId;
    }

    public void setConnectionId(String connectionId) {
        this.connectionId = connectionId;
    }

    public String getTrustId() {
        return trustId;
    }

    public void setTrustId(String trustId) {
        this.trustId = trustId;
    }

    public String getAuthenticatedClientContext() {
        return authenticatedClientContext;
    }

    public void setAuthenticatedClientContext(String authenticatedClientContext) {
        this.authenticatedClientContext = authenticatedClientContext;
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

    public String getConnectionName() {
        return connectionName;
    }

    public void setConnectionName(String connectionName) {
        this.connectionName = connectionName;
    }

    public String getOrigin() {
        return origin;
    }

    public void setOrigin(String origin) {
        this.origin = origin;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public int getVersion() {
        return version;
    }

    public void setVersion(int version) {
        this.version = version;
    }

    public String getEtag() {
        return etag != null ? etag : ("\"conn-" + connectionId + "-v" + version + "\"");
    }

    public void setEtag(String etag) {
        this.etag = etag;
    }

    public String getKeycloakIdpAlias() {
        return keycloakIdpAlias;
    }

    public void setKeycloakIdpAlias(String keycloakIdpAlias) {
        this.keycloakIdpAlias = keycloakIdpAlias;
    }

    public OidcState getOidcState() {
        return oidcState;
    }

    public void setOidcState(OidcState oidcState) {
        this.oidcState = oidcState;
    }

    public SamlState getSamlState() {
        return samlState;
    }

    public void setSamlState(SamlState samlState) {
        this.samlState = samlState;
    }

    public ScimState getScimState() {
        return scimState;
    }

    public void setScimState(ScimState scimState) {
        this.scimState = scimState;
    }

    public IdJagState getIdJagState() {
        return idJagState;
    }

    public void setIdJagState(IdJagState idJagState) {
        this.idJagState = idJagState;
    }

    public Map<String, Map<String, Object>> getProviderDelegationState() {
        return providerDelegationState;
    }

    public void setProviderDelegationState(Map<String, Map<String, Object>> providerDelegationState) {
        this.providerDelegationState = providerDelegationState != null ? providerDelegationState : new LinkedHashMap<>();
    }

    public Map<String, Map<String, Object>> getExtensionsState() {
        return extensionsState;
    }

    public void setExtensionsState(Map<String, Map<String, Object>> extensionsState) {
        this.extensionsState = extensionsState != null ? extensionsState : new LinkedHashMap<>();
    }

    public Map<String, String> getStaticSecretsHashes() {
        return staticSecretsHashes;
    }

    public void setStaticSecretsHashes(Map<String, String> staticSecretsHashes) {
        this.staticSecretsHashes = staticSecretsHashes != null ? staticSecretsHashes : new LinkedHashMap<>();
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    public void setMetadata(Map<String, Object> metadata) {
        this.metadata = metadata != null ? metadata : new LinkedHashMap<>();
    }

    public Map<String, Object> getConfigValues() {
        return configValues;
    }

    public void setConfigValues(Map<String, Object> configValues) {
        this.configValues = configValues != null ? configValues : new LinkedHashMap<>();
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(long createdAt) {
        this.createdAt = createdAt;
    }

    public long getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(long updatedAt) {
        this.updatedAt = updatedAt;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class OidcState {
        private String issuer;
        private String clientId;
        private String clientSecret;
        private String tokenEndpointAuthMethod;
        private Map<String, Object> clientSecurity;
        private String authorizationEndpoint;
        private String tokenEndpoint;
        private String jwksUri;
        private String userinfoEndpoint;
        private String endSessionEndpoint;
        private List<String> scopes;
        private boolean useCimd;
        private String appClientIdMetadataUri;

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

        public boolean isUseCimd() {
            return useCimd;
        }

        public void setUseCimd(boolean useCimd) {
            this.useCimd = useCimd;
        }

        public String getAppClientIdMetadataUri() {
            return appClientIdMetadataUri;
        }

        public void setAppClientIdMetadataUri(String appClientIdMetadataUri) {
            this.appClientIdMetadataUri = appClientIdMetadataUri;
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class SamlState {
        private String idpEntityId;
        private String idpSsoUrl;
        private String idpSloUrl;
        private String idpCertificate;
        private String nameIdFormat;
        private Map<String, String> attributeMapping;
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
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ScimState {
        private List<String> features = new ArrayList<>();
        private String authMode = "SAAS_ISSUED_BEARER"; // "SAAS_ISSUED_BEARER", "OAUTH2_CLIENT_CREDENTIALS", "STATIC_SECRET"
        private String accessTokenHash;
        private String keycloakClientId;
        private String scimClientJwksUri;

        public List<String> getFeatures() {
            return features;
        }

        public void setFeatures(List<String> features) {
            this.features = features != null ? features : new ArrayList<>();
        }

        public String getAuthMode() {
            return authMode;
        }

        public void setAuthMode(String authMode) {
            this.authMode = authMode;
        }

        public String getAccessTokenHash() {
            return accessTokenHash;
        }

        public void setAccessTokenHash(String accessTokenHash) {
            this.accessTokenHash = accessTokenHash;
        }

        public String getKeycloakClientId() {
            return keycloakClientId;
        }

        public void setKeycloakClientId(String keycloakClientId) {
            this.keycloakClientId = keycloakClientId;
        }

        public String getScimClientJwksUri() {
            return scimClientJwksUri;
        }

        public void setScimClientJwksUri(String scimClientJwksUri) {
            this.scimClientJwksUri = scimClientJwksUri;
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class IdJagState {
        private String clientId;
        private String cimdUri;
        private String clientSecretHash;
        private String requesterType;
        private String requesterName;
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

        public String getClientSecretHash() {
            return clientSecretHash;
        }

        public void setClientSecretHash(String clientSecretHash) {
            this.clientSecretHash = clientSecretHash;
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

        public List<ConfigurationRequestRepresentation.ResourceConnection> getResourceConnections() {
            return resourceConnections;
        }

        public void setResourceConnections(List<ConfigurationRequestRepresentation.ResourceConnection> resourceConnections) {
            this.resourceConnections = resourceConnections;
        }
    }
}
