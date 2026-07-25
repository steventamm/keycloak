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

/** A materialized inbound FedSetup connection. This representation never carries a credential value. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class FedSetupConnection {
    private String id;
    private String trustId;
    private String applicationTenantId;
    private String idpIssuer;
    private String idpDomain;
    private String protocol;
    private String brokerAlias;
    private String status;
    private Map<String, String> sso = new LinkedHashMap<>();
    private Map<String, String> samlAttributeMapping = new LinkedHashMap<>();
    private String samlMetadataUrl;
    private Set<String> capabilities = new LinkedHashSet<>();
    private Set<String> extensionProfiles = new LinkedHashSet<>();
    private FedSetupIdJagConfiguration idJag;
    private String idJagIdentityProviderAlias;
    private Set<String> scimFeatures = new LinkedHashSet<>();
    private String credentialReferenceId;
    private String scimBaseUri;
    private String scimTokenEndpoint;
    private String scimServiceClientId;
    private String scimBootstrapCredentialReferenceId;
    private long createdAt;
    private long updatedAt;
    private long version;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getTrustId() { return trustId; }
    public void setTrustId(String trustId) { this.trustId = trustId; }
    public String getApplicationTenantId() { return applicationTenantId; }
    public void setApplicationTenantId(String applicationTenantId) { this.applicationTenantId = applicationTenantId; }
    public String getIdpIssuer() { return idpIssuer; }
    public void setIdpIssuer(String idpIssuer) { this.idpIssuer = idpIssuer; }
    public String getIdpDomain() { return idpDomain; }
    public void setIdpDomain(String idpDomain) { this.idpDomain = idpDomain; }
    public String getProtocol() { return protocol; }
    public void setProtocol(String protocol) { this.protocol = protocol; }
    public String getBrokerAlias() { return brokerAlias; }
    public void setBrokerAlias(String brokerAlias) { this.brokerAlias = brokerAlias; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public Map<String, String> getSso() { return sso; }
    public void setSso(Map<String, String> sso) { this.sso = sso == null ? new LinkedHashMap<>() : new LinkedHashMap<>(sso); }
    public Map<String, String> getSamlAttributeMapping() { return samlAttributeMapping; }
    public void setSamlAttributeMapping(Map<String, String> value) { samlAttributeMapping = value == null ? new LinkedHashMap<>() : new LinkedHashMap<>(value); }
    public String getSamlMetadataUrl() { return samlMetadataUrl; }
    public void setSamlMetadataUrl(String value) { samlMetadataUrl = value; }
    /** Whether the Connection opted in to SAML SLO when it was installed. */
    public boolean hasSamlSingleLogoutService() {
        return sso != null && sso.get("single_logout_service") != null && !sso.get("single_logout_service").isBlank();
    }
    public Set<String> getCapabilities() { return capabilities; }
    public void setCapabilities(Set<String> capabilities) { this.capabilities = capabilities == null ? new LinkedHashSet<>() : new LinkedHashSet<>(capabilities); }
    public Set<String> getExtensionProfiles() { return extensionProfiles; }
    public void setExtensionProfiles(Set<String> extensionProfiles) { this.extensionProfiles = extensionProfiles == null ? new LinkedHashSet<>() : new LinkedHashSet<>(extensionProfiles); }
    public FedSetupIdJagConfiguration getIdJag() { return idJag; }
    public void setIdJag(FedSetupIdJagConfiguration value) { idJag = value; }
    public String getIdJagIdentityProviderAlias() { return idJagIdentityProviderAlias; }
    public void setIdJagIdentityProviderAlias(String value) { idJagIdentityProviderAlias = value; }
    public Set<String> getScimFeatures() { return scimFeatures; }
    public void setScimFeatures(Set<String> features) { this.scimFeatures = features == null ? new LinkedHashSet<>() : new LinkedHashSet<>(features); }
    public String getCredentialReferenceId() { return credentialReferenceId; }
    public void setCredentialReferenceId(String credentialReferenceId) { this.credentialReferenceId = credentialReferenceId; }
    public String getScimBaseUri() { return scimBaseUri; }
    public void setScimBaseUri(String scimBaseUri) { this.scimBaseUri = scimBaseUri; }
    public String getScimTokenEndpoint() { return scimTokenEndpoint; }
    public void setScimTokenEndpoint(String scimTokenEndpoint) { this.scimTokenEndpoint = scimTokenEndpoint; }
    public String getScimServiceClientId() { return scimServiceClientId; }
    public void setScimServiceClientId(String scimServiceClientId) { this.scimServiceClientId = scimServiceClientId; }
    public String getScimBootstrapCredentialReferenceId() { return scimBootstrapCredentialReferenceId; }
    public void setScimBootstrapCredentialReferenceId(String value) { this.scimBootstrapCredentialReferenceId = value; }
    public long getCreatedAt() { return createdAt; }
    public void setCreatedAt(long createdAt) { this.createdAt = createdAt; }
    public long getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(long updatedAt) { this.updatedAt = updatedAt; }
    public long getVersion() { return version; }
    public void setVersion(long version) { this.version = version; }
}
