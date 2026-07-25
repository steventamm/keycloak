/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup.representation;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonInclude;

/** Desired and last-applied state for Keycloak acting as the IdP Tenant. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class FedSetupInstallation {
    private String id;
    private String applicationTenantId;
    private String trustId;
    private String canonicalApplicationBaseUri;
    private String configurationEndpoint;
    private String clientId;
    private String protocol;
    /**
     * Administrator-approved mapping of the portable FedSetup profile fields
     * to the SAML Attribute names expected by the Application.  This is used
     * only when this installation provisions SAML.
     */
    private Map<String, String> samlAttributeMapping = new LinkedHashMap<>();
    private Set<String> capabilities = new LinkedHashSet<>();
    private Set<String> scimFeatures = new LinkedHashSet<>();
    private Set<String> extensionProfiles = new LinkedHashSet<>();
    private Map<String, String> desiredSso = new LinkedHashMap<>();
    private Map<String, String> appliedSso = new LinkedHashMap<>();
    private String remoteConnectionId;
    private String remoteEtag;
    private String scimEndpoint;
    private String scimTokenEndpoint;
    private String scimServiceClientId;
    private String scimCredentialReferenceId;
    private String idempotencyKey;
    private String status;
    private String lastError;
    private int dispatchAttempts;
    private long nextAttemptAt;
    private long createdAt;
    private long updatedAt;
    private long version;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getApplicationTenantId() { return applicationTenantId; }
    public void setApplicationTenantId(String applicationTenantId) { this.applicationTenantId = applicationTenantId; }
    public String getTrustId() { return trustId; }
    public void setTrustId(String trustId) { this.trustId = trustId; }
    public String getCanonicalApplicationBaseUri() { return canonicalApplicationBaseUri; }
    public void setCanonicalApplicationBaseUri(String canonicalApplicationBaseUri) { this.canonicalApplicationBaseUri = canonicalApplicationBaseUri; }
    public String getConfigurationEndpoint() { return configurationEndpoint; }
    public void setConfigurationEndpoint(String configurationEndpoint) { this.configurationEndpoint = configurationEndpoint; }
    public String getClientId() { return clientId; }
    public void setClientId(String clientId) { this.clientId = clientId; }
    public String getProtocol() { return protocol; }
    public void setProtocol(String protocol) { this.protocol = protocol; }
    public Map<String, String> getSamlAttributeMapping() { return samlAttributeMapping; }
    public void setSamlAttributeMapping(Map<String, String> value) { samlAttributeMapping = value == null ? new LinkedHashMap<>() : new LinkedHashMap<>(value); }
    public Set<String> getCapabilities() { return capabilities; }
    public void setCapabilities(Set<String> capabilities) { this.capabilities = capabilities == null ? new LinkedHashSet<>() : new LinkedHashSet<>(capabilities); }
    public Set<String> getScimFeatures() { return scimFeatures; }
    public void setScimFeatures(Set<String> value) { scimFeatures = value == null ? new LinkedHashSet<>() : new LinkedHashSet<>(value); }
    public Set<String> getExtensionProfiles() { return extensionProfiles; }
    public void setExtensionProfiles(Set<String> extensionProfiles) { this.extensionProfiles = extensionProfiles == null ? new LinkedHashSet<>() : new LinkedHashSet<>(extensionProfiles); }
    public Map<String, String> getDesiredSso() { return desiredSso; }
    public void setDesiredSso(Map<String, String> desiredSso) { this.desiredSso = desiredSso == null ? new LinkedHashMap<>() : new LinkedHashMap<>(desiredSso); }
    public Map<String, String> getAppliedSso() { return appliedSso; }
    public void setAppliedSso(Map<String, String> appliedSso) { this.appliedSso = appliedSso == null ? new LinkedHashMap<>() : new LinkedHashMap<>(appliedSso); }
    public String getRemoteConnectionId() { return remoteConnectionId; }
    public void setRemoteConnectionId(String remoteConnectionId) { this.remoteConnectionId = remoteConnectionId; }
    public String getRemoteEtag() { return remoteEtag; }
    public void setRemoteEtag(String remoteEtag) { this.remoteEtag = remoteEtag; }
    public String getScimEndpoint() { return scimEndpoint; }
    public void setScimEndpoint(String scimEndpoint) { this.scimEndpoint = scimEndpoint; }
    public String getScimTokenEndpoint() { return scimTokenEndpoint; }
    public void setScimTokenEndpoint(String scimTokenEndpoint) { this.scimTokenEndpoint = scimTokenEndpoint; }
    public String getScimServiceClientId() { return scimServiceClientId; }
    public void setScimServiceClientId(String scimServiceClientId) { this.scimServiceClientId = scimServiceClientId; }
    public String getScimCredentialReferenceId() { return scimCredentialReferenceId; }
    public void setScimCredentialReferenceId(String scimCredentialReferenceId) { this.scimCredentialReferenceId = scimCredentialReferenceId; }
    public String getIdempotencyKey() { return idempotencyKey; }
    public void setIdempotencyKey(String idempotencyKey) { this.idempotencyKey = idempotencyKey; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public String getLastError() { return lastError; }
    public void setLastError(String lastError) { this.lastError = lastError; }
    public int getDispatchAttempts() { return dispatchAttempts; }
    public void setDispatchAttempts(int dispatchAttempts) { this.dispatchAttempts = dispatchAttempts; }
    public long getNextAttemptAt() { return nextAttemptAt; }
    public void setNextAttemptAt(long nextAttemptAt) { this.nextAttemptAt = nextAttemptAt; }
    public long getCreatedAt() { return createdAt; }
    public void setCreatedAt(long createdAt) { this.createdAt = createdAt; }
    public long getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(long updatedAt) { this.updatedAt = updatedAt; }
    public long getVersion() { return version; }
    public void setVersion(long version) { this.version = version; }
}
