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

/** The administrator-approved runtime trust binding for one Application Tenant and IdP Tenant. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class DirectInstallationTrust {
    private String id;
    private String applicationTenantId;
    private String canonicalApplicationBaseUri;
    private String authorizationServer;
    private String configurationEndpoint;
    private String configurationResource;
    private String connectionEndpointTemplate;
    private String installationTrustEndpoint;
    private String installationConsentEndpoint;
    private String installationConfirmationEndpoint;
    private String idpIssuer;
    private String trustProfileUri;
    private String installationRuntimeCimdUri;
    private String signingKeyJwk;
    private String runtimeJwksUri;
    private String runtimeSigningCertificate;
    private String receiverCredentialVaultReference;
    private boolean samlSpInitiatedSloSupported;
    private Set<String> capabilities = new LinkedHashSet<>();
    private Set<String> providerDelegationProfiles = new LinkedHashSet<>();
    private Set<String> extensionProfiles = new LinkedHashSet<>();
    private long expiresAt;
    private long createdAt;
    private long updatedAt;
    private long version;
    private boolean active = true;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getApplicationTenantId() { return applicationTenantId; }
    public void setApplicationTenantId(String applicationTenantId) { this.applicationTenantId = applicationTenantId; }
    public String getCanonicalApplicationBaseUri() { return canonicalApplicationBaseUri; }
    public void setCanonicalApplicationBaseUri(String canonicalApplicationBaseUri) { this.canonicalApplicationBaseUri = canonicalApplicationBaseUri; }
    public String getAuthorizationServer() { return authorizationServer; }
    public void setAuthorizationServer(String value) { authorizationServer = value; }
    public String getConfigurationEndpoint() { return configurationEndpoint; }
    public void setConfigurationEndpoint(String configurationEndpoint) { this.configurationEndpoint = configurationEndpoint; }
    public String getConfigurationResource() { return configurationResource; }
    public void setConfigurationResource(String value) { configurationResource = value; }
    public String getConnectionEndpointTemplate() { return connectionEndpointTemplate; }
    public void setConnectionEndpointTemplate(String value) { connectionEndpointTemplate = value; }
    public String getInstallationTrustEndpoint() { return installationTrustEndpoint; }
    public void setInstallationTrustEndpoint(String installationTrustEndpoint) { this.installationTrustEndpoint = installationTrustEndpoint; }
    public String getInstallationConsentEndpoint() { return installationConsentEndpoint; }
    public void setInstallationConsentEndpoint(String value) { installationConsentEndpoint = value; }
    public String getInstallationConfirmationEndpoint() { return installationConfirmationEndpoint; }
    public void setInstallationConfirmationEndpoint(String value) { installationConfirmationEndpoint = value; }
    public String getIdpIssuer() { return idpIssuer; }
    public void setIdpIssuer(String idpIssuer) { this.idpIssuer = idpIssuer; }
    public String getTrustProfileUri() { return trustProfileUri; }
    public void setTrustProfileUri(String trustProfileUri) { this.trustProfileUri = trustProfileUri; }
    public String getInstallationRuntimeCimdUri() { return installationRuntimeCimdUri; }
    public void setInstallationRuntimeCimdUri(String installationRuntimeCimdUri) { this.installationRuntimeCimdUri = installationRuntimeCimdUri; }
    public String getSigningKeyJwk() { return signingKeyJwk; }
    public void setSigningKeyJwk(String signingKeyJwk) { this.signingKeyJwk = signingKeyJwk; }
    public String getRuntimeJwksUri() { return runtimeJwksUri; }
    public void setRuntimeJwksUri(String runtimeJwksUri) { this.runtimeJwksUri = runtimeJwksUri; }
    public String getRuntimeSigningCertificate() { return runtimeSigningCertificate; }
    public void setRuntimeSigningCertificate(String runtimeSigningCertificate) { this.runtimeSigningCertificate = runtimeSigningCertificate; }
    public String getReceiverCredentialVaultReference() { return receiverCredentialVaultReference; }
    public void setReceiverCredentialVaultReference(String receiverCredentialVaultReference) { this.receiverCredentialVaultReference = receiverCredentialVaultReference; }
    public boolean isSamlSpInitiatedSloSupported() { return samlSpInitiatedSloSupported; }
    public void setSamlSpInitiatedSloSupported(boolean value) { samlSpInitiatedSloSupported = value; }
    public Set<String> getCapabilities() { return capabilities; }
    public void setCapabilities(Set<String> capabilities) { this.capabilities = capabilities == null ? new LinkedHashSet<>() : new LinkedHashSet<>(capabilities); }
    public Set<String> getProviderDelegationProfiles() { return providerDelegationProfiles; }
    public void setProviderDelegationProfiles(Set<String> profiles) { this.providerDelegationProfiles = profiles == null ? new LinkedHashSet<>() : new LinkedHashSet<>(profiles); }
    public Set<String> getExtensionProfiles() { return extensionProfiles; }
    public void setExtensionProfiles(Set<String> extensionProfiles) { this.extensionProfiles = extensionProfiles == null ? new LinkedHashSet<>() : new LinkedHashSet<>(extensionProfiles); }
    public long getExpiresAt() { return expiresAt; }
    public void setExpiresAt(long expiresAt) { this.expiresAt = expiresAt; }
    public long getCreatedAt() { return createdAt; }
    public void setCreatedAt(long createdAt) { this.createdAt = createdAt; }
    public long getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(long updatedAt) { this.updatedAt = updatedAt; }
    public long getVersion() { return version; }
    public void setVersion(long version) { this.version = version; }
    public boolean isActive() { return active; }
    public void setActive(boolean active) { this.active = active; }
}
