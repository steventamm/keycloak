/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup.representation;

import com.fasterxml.jackson.annotation.JsonInclude;

/** Realm-local configuration for a Catalog using the standard Submission API. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CatalogTarget {
    private String id;
    private String name;
    private String discoveryUri;
    private String authenticationMethod = "oauth2_bearer";
    private String credentialVaultReference;
    private CatalogDiscovery discovery;
    private boolean active = true;
    private long createdAt;
    private long updatedAt;
    private long version;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getDiscoveryUri() { return discoveryUri; }
    public void setDiscoveryUri(String discoveryUri) { this.discoveryUri = discoveryUri; }
    public String getAuthenticationMethod() { return authenticationMethod; }
    public void setAuthenticationMethod(String authenticationMethod) { this.authenticationMethod = authenticationMethod; }
    public String getCredentialVaultReference() { return credentialVaultReference; }
    public void setCredentialVaultReference(String credentialVaultReference) { this.credentialVaultReference = credentialVaultReference; }
    public CatalogDiscovery getDiscovery() { return discovery; }
    public void setDiscovery(CatalogDiscovery discovery) { this.discovery = discovery; }
    public boolean isActive() { return active; }
    public void setActive(boolean active) { this.active = active; }
    public long getCreatedAt() { return createdAt; }
    public void setCreatedAt(long createdAt) { this.createdAt = createdAt; }
    public long getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(long updatedAt) { this.updatedAt = updatedAt; }
    public long getVersion() { return version; }
    public void setVersion(long version) { this.version = version; }
}
