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

/**
 * Application-side state for a one-time Direct Installation Trust invitation.
 *
 * <p>The signed invitation and its digest are intentionally not exposed by a
 * list/read API. They are exchanged directly between the two administrators.</p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class DirectInstallationTrustInvitation {
    private String id;
    private String applicationTenantId;
    private String canonicalApplicationBaseUri;
    private String configurationEndpoint;
    private String idpIssuer;
    private String signingKeyJwk;
    private String runtimeJwksUri;
    private String runtimeSigningCertificate;
    private Set<String> capabilities = new LinkedHashSet<>();
    private Set<String> extensionProfiles = new LinkedHashSet<>();
    private String signedInvitationHash;
    private String status;
    private long expiresAt;
    private long createdAt;
    private long updatedAt;
    private long version;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getApplicationTenantId() { return applicationTenantId; }
    public void setApplicationTenantId(String applicationTenantId) { this.applicationTenantId = applicationTenantId; }
    public String getCanonicalApplicationBaseUri() { return canonicalApplicationBaseUri; }
    public void setCanonicalApplicationBaseUri(String canonicalApplicationBaseUri) { this.canonicalApplicationBaseUri = canonicalApplicationBaseUri; }
    public String getConfigurationEndpoint() { return configurationEndpoint; }
    public void setConfigurationEndpoint(String configurationEndpoint) { this.configurationEndpoint = configurationEndpoint; }
    public String getIdpIssuer() { return idpIssuer; }
    public void setIdpIssuer(String idpIssuer) { this.idpIssuer = idpIssuer; }
    public String getSigningKeyJwk() { return signingKeyJwk; }
    public void setSigningKeyJwk(String signingKeyJwk) { this.signingKeyJwk = signingKeyJwk; }
    public String getRuntimeJwksUri() { return runtimeJwksUri; }
    public void setRuntimeJwksUri(String runtimeJwksUri) { this.runtimeJwksUri = runtimeJwksUri; }
    public String getRuntimeSigningCertificate() { return runtimeSigningCertificate; }
    public void setRuntimeSigningCertificate(String runtimeSigningCertificate) { this.runtimeSigningCertificate = runtimeSigningCertificate; }
    public Set<String> getCapabilities() { return capabilities; }
    public void setCapabilities(Set<String> capabilities) { this.capabilities = capabilities == null ? new LinkedHashSet<>() : new LinkedHashSet<>(capabilities); }
    public Set<String> getExtensionProfiles() { return extensionProfiles; }
    public void setExtensionProfiles(Set<String> extensionProfiles) { this.extensionProfiles = extensionProfiles == null ? new LinkedHashSet<>() : new LinkedHashSet<>(extensionProfiles); }
    public String getSignedInvitationHash() { return signedInvitationHash; }
    public void setSignedInvitationHash(String signedInvitationHash) { this.signedInvitationHash = signedInvitationHash; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public long getExpiresAt() { return expiresAt; }
    public void setExpiresAt(long expiresAt) { this.expiresAt = expiresAt; }
    public long getCreatedAt() { return createdAt; }
    public void setCreatedAt(long createdAt) { this.createdAt = createdAt; }
    public long getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(long updatedAt) { this.updatedAt = updatedAt; }
    public long getVersion() { return version; }
    public void setVersion(long version) { this.version = version; }
}
