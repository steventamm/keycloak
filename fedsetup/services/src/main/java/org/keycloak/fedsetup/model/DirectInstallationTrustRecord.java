package org.keycloak.fedsetup.model;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class DirectInstallationTrustRecord {

    private String id;
    private String applicationTenantId;
    private String idpIssuer;
    private String cimdUri;
    private String softwareId;
    private String clientName;
    private String logoUri;
    private String clientUri;
    private String staticJwksJson;
    private List<String> authorizedCapabilities = new ArrayList<>();
    private List<String> providerDelegationProfiles = new ArrayList<>();
    private List<String> federationExtensionProfiles = new ArrayList<>();
    private String oauthClientId;
    private boolean revoked;
    private long createdAt;
    private long updatedAt;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
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

    public String getCimdUri() {
        return cimdUri;
    }

    public void setCimdUri(String cimdUri) {
        this.cimdUri = cimdUri;
    }

    public String getSoftwareId() {
        return softwareId;
    }

    public void setSoftwareId(String softwareId) {
        this.softwareId = softwareId;
    }

    public String getClientName() {
        return clientName;
    }

    public void setClientName(String clientName) {
        this.clientName = clientName;
    }

    public String getLogoUri() {
        return logoUri;
    }

    public void setLogoUri(String logoUri) {
        this.logoUri = logoUri;
    }

    public String getClientUri() {
        return clientUri;
    }

    public void setClientUri(String clientUri) {
        this.clientUri = clientUri;
    }

    public String getStaticJwksJson() {
        return staticJwksJson;
    }

    public void setStaticJwksJson(String staticJwksJson) {
        this.staticJwksJson = staticJwksJson;
    }

    public List<String> getAuthorizedCapabilities() {
        return authorizedCapabilities;
    }

    public void setAuthorizedCapabilities(List<String> authorizedCapabilities) {
        this.authorizedCapabilities = authorizedCapabilities != null ? authorizedCapabilities : new ArrayList<>();
    }

    public List<String> getProviderDelegationProfiles() {
        return providerDelegationProfiles;
    }

    public void setProviderDelegationProfiles(List<String> providerDelegationProfiles) {
        this.providerDelegationProfiles = providerDelegationProfiles != null ? providerDelegationProfiles : new ArrayList<>();
    }

    public List<String> getFederationExtensionProfiles() {
        return federationExtensionProfiles;
    }

    public void setFederationExtensionProfiles(List<String> federationExtensionProfiles) {
        this.federationExtensionProfiles = federationExtensionProfiles != null ? federationExtensionProfiles : new ArrayList<>();
    }

    public String getOauthClientId() {
        return oauthClientId;
    }

    public void setOauthClientId(String oauthClientId) {
        this.oauthClientId = oauthClientId;
    }

    public boolean isRevoked() {
        return revoked;
    }

    public void setRevoked(boolean revoked) {
        this.revoked = revoked;
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
}
