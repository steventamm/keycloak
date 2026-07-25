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

/** Short-lived browser transaction and later code for front-channel trust establishment. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class FedSetupFrontChannelTransaction {
    private String id;
    private String applicationTenantId;
    private String idpIssuer;
    private String cimdUri;
    private String redirectUri;
    private String state;
    private String trustId;
    private String tokenEndpoint;
    private String consentNonce;
    private Set<String> capabilities = new LinkedHashSet<>();
    private Set<String> providerDelegationProfiles = new LinkedHashSet<>();
    private Set<String> federationExtensionProfiles = new LinkedHashSet<>();
    private String authorizationCodeHash;
    private long expiresAt;
    private long createdAt;
    private long updatedAt;
    private long version;
    private boolean consented;
    private boolean consumed;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getApplicationTenantId() { return applicationTenantId; }
    public void setApplicationTenantId(String applicationTenantId) { this.applicationTenantId = applicationTenantId; }
    public String getIdpIssuer() { return idpIssuer; }
    public void setIdpIssuer(String idpIssuer) { this.idpIssuer = idpIssuer; }
    public String getCimdUri() { return cimdUri; }
    public void setCimdUri(String cimdUri) { this.cimdUri = cimdUri; }
    public String getRedirectUri() { return redirectUri; }
    public void setRedirectUri(String redirectUri) { this.redirectUri = redirectUri; }
    public String getState() { return state; }
    public void setState(String state) { this.state = state; }
    public String getTrustId() { return trustId; }
    public void setTrustId(String trustId) { this.trustId = trustId; }
    public String getTokenEndpoint() { return tokenEndpoint; }
    public void setTokenEndpoint(String tokenEndpoint) { this.tokenEndpoint = tokenEndpoint; }
    public String getConsentNonce() { return consentNonce; }
    public void setConsentNonce(String consentNonce) { this.consentNonce = consentNonce; }
    public Set<String> getCapabilities() { return capabilities; }
    public void setCapabilities(Set<String> values) { this.capabilities = copy(values); }
    public Set<String> getProviderDelegationProfiles() { return providerDelegationProfiles; }
    public void setProviderDelegationProfiles(Set<String> values) { this.providerDelegationProfiles = copy(values); }
    public Set<String> getFederationExtensionProfiles() { return federationExtensionProfiles; }
    public void setFederationExtensionProfiles(Set<String> values) { this.federationExtensionProfiles = copy(values); }
    public String getAuthorizationCodeHash() { return authorizationCodeHash; }
    public void setAuthorizationCodeHash(String authorizationCodeHash) { this.authorizationCodeHash = authorizationCodeHash; }
    public long getExpiresAt() { return expiresAt; }
    public void setExpiresAt(long expiresAt) { this.expiresAt = expiresAt; }
    public long getCreatedAt() { return createdAt; }
    public void setCreatedAt(long createdAt) { this.createdAt = createdAt; }
    public long getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(long updatedAt) { this.updatedAt = updatedAt; }
    public long getVersion() { return version; }
    public void setVersion(long version) { this.version = version; }
    public boolean isConsented() { return consented; }
    public void setConsented(boolean consented) { this.consented = consented; }
    public boolean isConsumed() { return consumed; }
    public void setConsumed(boolean consumed) { this.consumed = consumed; }

    private static Set<String> copy(Set<String> values) {
        return values == null ? new LinkedHashSet<>() : new LinkedHashSet<>(values);
    }
}
