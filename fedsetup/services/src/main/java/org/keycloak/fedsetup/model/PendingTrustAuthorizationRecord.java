package org.keycloak.fedsetup.model;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class PendingTrustAuthorizationRecord {

    private String id;
    private String applicationTenantId;
    private String idpIssuer;
    private String cimdUri;
    private String staticJwksJson;
    private List<String> authorizedCapabilities = new ArrayList<>();
    private List<String> providerDelegationProfiles = new ArrayList<>();
    private List<String> federationExtensionProfiles = new ArrayList<>();
    private long issuedAt;
    private long expiresAt;
    private boolean revoked;
    private boolean consumed;

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

    public long getIssuedAt() {
        return issuedAt;
    }

    public void setIssuedAt(long issuedAt) {
        this.issuedAt = issuedAt;
    }

    public long getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(long expiresAt) {
        this.expiresAt = expiresAt;
    }

    public boolean isRevoked() {
        return revoked;
    }

    public void setRevoked(boolean revoked) {
        this.revoked = revoked;
    }

    public boolean isConsumed() {
        return consumed;
    }

    public void setConsumed(boolean consumed) {
        this.consumed = consumed;
    }
}
