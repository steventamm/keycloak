package org.keycloak.fedsetup.model;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class DeferredApprovalProposalRecord {

    private String pendingId;
    private String applicationTenantId;
    private String idpIssuer;
    private String cimdUri;
    private List<String> requestedCapabilities = new ArrayList<>();
    private List<String> requestedDelegationProfiles = new ArrayList<>();
    private List<String> requestedExtensionProfiles = new ArrayList<>();
    private List<String> approvedCapabilities = new ArrayList<>();
    private List<String> approvedDelegationProfiles = new ArrayList<>();
    private List<String> approvedExtensionProfiles = new ArrayList<>();
    private String approvalNotificationEndpoint;
    private String status; // "pending", "approved", "denied", "consumed"
    private int intervalSeconds = 5;
    private long lastPolledAtMillis;
    private long createdAt;
    private long expiresAt;

    public String getPendingId() {
        return pendingId;
    }

    public void setPendingId(String pendingId) {
        this.pendingId = pendingId;
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

    public List<String> getRequestedCapabilities() {
        return requestedCapabilities;
    }

    public void setRequestedCapabilities(List<String> requestedCapabilities) {
        this.requestedCapabilities = requestedCapabilities != null ? requestedCapabilities : new ArrayList<>();
    }

    public List<String> getRequestedDelegationProfiles() {
        return requestedDelegationProfiles;
    }

    public void setRequestedDelegationProfiles(List<String> requestedDelegationProfiles) {
        this.requestedDelegationProfiles = requestedDelegationProfiles != null ? requestedDelegationProfiles : new ArrayList<>();
    }

    public List<String> getRequestedExtensionProfiles() {
        return requestedExtensionProfiles;
    }

    public void setRequestedExtensionProfiles(List<String> requestedExtensionProfiles) {
        this.requestedExtensionProfiles = requestedExtensionProfiles != null ? requestedExtensionProfiles : new ArrayList<>();
    }

    public List<String> getApprovedCapabilities() {
        return approvedCapabilities;
    }

    public void setApprovedCapabilities(List<String> approvedCapabilities) {
        this.approvedCapabilities = approvedCapabilities != null ? approvedCapabilities : new ArrayList<>();
    }

    public List<String> getAuthorizedCapabilities() {
        return approvedCapabilities;
    }

    public void setAuthorizedCapabilities(List<String> authorizedCapabilities) {
        setApprovedCapabilities(authorizedCapabilities);
        if (this.requestedCapabilities.isEmpty() && authorizedCapabilities != null) {
            this.requestedCapabilities = new ArrayList<>(authorizedCapabilities);
        }
    }

    public List<String> getApprovedDelegationProfiles() {
        return approvedDelegationProfiles;
    }

    public void setApprovedDelegationProfiles(List<String> approvedDelegationProfiles) {
        this.approvedDelegationProfiles = approvedDelegationProfiles != null ? approvedDelegationProfiles : new ArrayList<>();
    }

    public List<String> getProviderDelegationProfiles() {
        return approvedDelegationProfiles;
    }

    public void setProviderDelegationProfiles(List<String> providerDelegationProfiles) {
        setApprovedDelegationProfiles(providerDelegationProfiles);
        if (this.requestedDelegationProfiles.isEmpty() && providerDelegationProfiles != null) {
            this.requestedDelegationProfiles = new ArrayList<>(providerDelegationProfiles);
        }
    }

    public List<String> getApprovedExtensionProfiles() {
        return approvedExtensionProfiles;
    }

    public void setApprovedExtensionProfiles(List<String> approvedExtensionProfiles) {
        this.approvedExtensionProfiles = approvedExtensionProfiles != null ? approvedExtensionProfiles : new ArrayList<>();
    }

    public List<String> getFederationExtensionProfiles() {
        return approvedExtensionProfiles;
    }

    public void setFederationExtensionProfiles(List<String> federationExtensionProfiles) {
        setApprovedExtensionProfiles(federationExtensionProfiles);
        if (this.requestedExtensionProfiles.isEmpty() && federationExtensionProfiles != null) {
            this.requestedExtensionProfiles = new ArrayList<>(federationExtensionProfiles);
        }
    }

    public String getApprovalNotificationEndpoint() {
        return approvalNotificationEndpoint;
    }

    public void setApprovalNotificationEndpoint(String approvalNotificationEndpoint) {
        this.approvalNotificationEndpoint = approvalNotificationEndpoint;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public int getIntervalSeconds() {
        return intervalSeconds;
    }

    public void setIntervalSeconds(int intervalSeconds) {
        this.intervalSeconds = intervalSeconds;
    }

    public long getLastPolledAtMillis() {
        return lastPolledAtMillis;
    }

    public void setLastPolledAtMillis(long lastPolledAtMillis) {
        this.lastPolledAtMillis = lastPolledAtMillis;
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(long createdAt) {
        this.createdAt = createdAt;
    }

    public long getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(long expiresAt) {
        this.expiresAt = expiresAt;
    }
}
