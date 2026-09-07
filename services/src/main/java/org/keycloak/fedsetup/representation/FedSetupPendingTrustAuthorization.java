/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup.representation;

import java.util.LinkedHashSet;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonInclude;

/** A tenant-admin approval operation created by an IdP-initiated Trust request. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class FedSetupPendingTrustAuthorization {
    private String pendingId;
    private String applicationTenantId;
    private String idpIssuer;
    private String cimdUri;
    private String runtimeKeyId;
    private String originalIdempotencyKey;
    private String approvalNotificationEndpoint;
    private long nextPollAt;
    private Set<String> capabilities = new LinkedHashSet<>();
    private Set<String> providerDelegationProfiles = new LinkedHashSet<>();
    private Set<String> federationExtensionProfiles = new LinkedHashSet<>();
    private String status;
    private String trustId;
    private long expiresAt;
    private long createdAt;
    private long updatedAt;
    private long version;

    public String getPendingId() { return pendingId; }
    public void setPendingId(String value) { pendingId = value; }
    public String getApplicationTenantId() { return applicationTenantId; }
    public void setApplicationTenantId(String value) { applicationTenantId = value; }
    public String getIdpIssuer() { return idpIssuer; }
    public void setIdpIssuer(String value) { idpIssuer = value; }
    public String getCimdUri() { return cimdUri; }
    public void setCimdUri(String value) { cimdUri = value; }
    public String getRuntimeKeyId() { return runtimeKeyId; }
    public void setRuntimeKeyId(String value) { runtimeKeyId = value; }
    public String getOriginalIdempotencyKey() { return originalIdempotencyKey; }
    public void setOriginalIdempotencyKey(String value) { originalIdempotencyKey = value; }
    public String getApprovalNotificationEndpoint() { return approvalNotificationEndpoint; }
    public void setApprovalNotificationEndpoint(String value) { approvalNotificationEndpoint = value; }
    public long getNextPollAt() { return nextPollAt; }
    public void setNextPollAt(long value) { nextPollAt = value; }
    public Set<String> getCapabilities() { return capabilities; }
    public void setCapabilities(Set<String> value) { capabilities = copy(value); }
    public Set<String> getProviderDelegationProfiles() { return providerDelegationProfiles; }
    public void setProviderDelegationProfiles(Set<String> value) { providerDelegationProfiles = copy(value); }
    public Set<String> getFederationExtensionProfiles() { return federationExtensionProfiles; }
    public void setFederationExtensionProfiles(Set<String> value) { federationExtensionProfiles = copy(value); }
    public String getStatus() { return status; }
    public void setStatus(String value) { status = value; }
    public String getTrustId() { return trustId; }
    public void setTrustId(String value) { trustId = value; }
    public long getExpiresAt() { return expiresAt; }
    public void setExpiresAt(long value) { expiresAt = value; }
    public long getCreatedAt() { return createdAt; }
    public void setCreatedAt(long value) { createdAt = value; }
    public long getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(long value) { updatedAt = value; }
    public long getVersion() { return version; }
    public void setVersion(long value) { version = value; }

    private static Set<String> copy(Set<String> values) {
        return values == null ? new LinkedHashSet<>() : new LinkedHashSet<>(values);
    }
}
