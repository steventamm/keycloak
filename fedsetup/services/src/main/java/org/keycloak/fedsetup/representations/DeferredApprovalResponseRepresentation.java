package org.keycloak.fedsetup.representations;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Response representation for Deferred Approval proposals (202 Accepted) and approved polls (200 OK).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class DeferredApprovalResponseRepresentation {

    @JsonProperty("pending_id")
    private String pendingId;

    @JsonProperty("interval")
    private Integer interval;

    @JsonProperty("expires_in")
    private Long expiresIn;

    @JsonProperty("trust_established")
    private Boolean trustEstablished;

    @JsonProperty("application_tenant_id")
    private String applicationTenantId;

    @JsonProperty("idp_issuer")
    private String idpIssuer;

    @JsonProperty("authorized_capabilities")
    private List<String> authorizedCapabilities;

    @JsonProperty("provider_delegation_profiles")
    private List<String> providerDelegationProfiles;

    @JsonProperty("federation_extension_profiles")
    private List<String> federationExtensionProfiles;

    public DeferredApprovalResponseRepresentation() {
    }

    public static DeferredApprovalResponseRepresentation pending(String pendingId, int interval, long expiresIn) {
        DeferredApprovalResponseRepresentation resp = new DeferredApprovalResponseRepresentation();
        resp.setPendingId(pendingId);
        resp.setInterval(interval);
        resp.setExpiresIn(expiresIn);
        return resp;
    }

    public static DeferredApprovalResponseRepresentation approved(
            String pendingId,
            String applicationTenantId,
            String idpIssuer,
            List<String> authorizedCapabilities,
            List<String> providerDelegationProfiles,
            List<String> federationExtensionProfiles) {
        DeferredApprovalResponseRepresentation resp = new DeferredApprovalResponseRepresentation();
        resp.setPendingId(pendingId);
        resp.setTrustEstablished(Boolean.TRUE);
        resp.setApplicationTenantId(applicationTenantId);
        resp.setIdpIssuer(idpIssuer);
        resp.setAuthorizedCapabilities(authorizedCapabilities);
        resp.setProviderDelegationProfiles(providerDelegationProfiles);
        resp.setFederationExtensionProfiles(federationExtensionProfiles);
        return resp;
    }

    public String getPendingId() {
        return pendingId;
    }

    public void setPendingId(String pendingId) {
        this.pendingId = pendingId;
    }

    public Integer getInterval() {
        return interval;
    }

    public void setInterval(Integer interval) {
        this.interval = interval;
    }

    public Long getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(Long expiresIn) {
        this.expiresIn = expiresIn;
    }

    public Boolean getTrustEstablished() {
        return trustEstablished;
    }

    public void setTrustEstablished(Boolean trustEstablished) {
        this.trustEstablished = trustEstablished;
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

    public List<String> getAuthorizedCapabilities() {
        return authorizedCapabilities;
    }

    public void setAuthorizedCapabilities(List<String> authorizedCapabilities) {
        this.authorizedCapabilities = authorizedCapabilities;
    }

    public List<String> getProviderDelegationProfiles() {
        return providerDelegationProfiles;
    }

    public void setProviderDelegationProfiles(List<String> providerDelegationProfiles) {
        this.providerDelegationProfiles = providerDelegationProfiles;
    }

    public List<String> getFederationExtensionProfiles() {
        return federationExtensionProfiles;
    }

    public void setFederationExtensionProfiles(List<String> federationExtensionProfiles) {
        this.federationExtensionProfiles = federationExtensionProfiles;
    }
}
