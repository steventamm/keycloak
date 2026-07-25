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

/** Application-administrator authorization for one back-channel trust request. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class FedSetupTrustPreAuthorization {
    private String id;
    private String applicationTenantId;
    private String idpIssuer;
    private String cimdUri;
    private Set<String> capabilities = new LinkedHashSet<>();
    private Set<String> providerDelegationProfiles = new LinkedHashSet<>();
    private Set<String> federationExtensionProfiles = new LinkedHashSet<>();
    private long expiresAt;
    private long createdAt;
    private long updatedAt;
    private long version;
    private boolean consumed;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getApplicationTenantId() { return applicationTenantId; }
    public void setApplicationTenantId(String applicationTenantId) { this.applicationTenantId = applicationTenantId; }
    public String getIdpIssuer() { return idpIssuer; }
    public void setIdpIssuer(String idpIssuer) { this.idpIssuer = idpIssuer; }
    public String getCimdUri() { return cimdUri; }
    public void setCimdUri(String cimdUri) { this.cimdUri = cimdUri; }
    public Set<String> getCapabilities() { return capabilities; }
    public void setCapabilities(Set<String> capabilities) { this.capabilities = copy(capabilities); }
    public Set<String> getProviderDelegationProfiles() { return providerDelegationProfiles; }
    public void setProviderDelegationProfiles(Set<String> profiles) { this.providerDelegationProfiles = copy(profiles); }
    public Set<String> getFederationExtensionProfiles() { return federationExtensionProfiles; }
    public void setFederationExtensionProfiles(Set<String> profiles) { this.federationExtensionProfiles = copy(profiles); }
    public long getExpiresAt() { return expiresAt; }
    public void setExpiresAt(long expiresAt) { this.expiresAt = expiresAt; }
    public long getCreatedAt() { return createdAt; }
    public void setCreatedAt(long createdAt) { this.createdAt = createdAt; }
    public long getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(long updatedAt) { this.updatedAt = updatedAt; }
    public long getVersion() { return version; }
    public void setVersion(long version) { this.version = version; }
    public boolean isConsumed() { return consumed; }
    public void setConsumed(boolean consumed) { this.consumed = consumed; }

    private static Set<String> copy(Set<String> values) {
        return values == null ? new LinkedHashSet<>() : new LinkedHashSet<>(values);
    }
}
