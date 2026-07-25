/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup.representation;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonInclude;

/** Realm-owned state used to expose an Express Configuration Application Tenant. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class FedSetupConfigurationProfile {
    private String applicationTenantId;
    private String canonicalBaseUri;
    private String oidcClientId;
    private String samlClientId;
    private String oidcDocumentationUri;
    private Set<String> capabilities = new LinkedHashSet<>();
    private Set<String> extensionProfiles = new LinkedHashSet<>();
    private List<FedSetupIdJagResourceBinding> idJagResourceBindings = new ArrayList<>();
    private boolean samlSpInitiatedSloSupported;

    public String getApplicationTenantId() { return applicationTenantId; }
    public void setApplicationTenantId(String applicationTenantId) { this.applicationTenantId = applicationTenantId; }
    public String getCanonicalBaseUri() { return canonicalBaseUri; }
    public void setCanonicalBaseUri(String canonicalBaseUri) { this.canonicalBaseUri = canonicalBaseUri; }
    public String getOidcClientId() { return oidcClientId; }
    public void setOidcClientId(String oidcClientId) { this.oidcClientId = oidcClientId; }
    public String getSamlClientId() { return samlClientId; }
    public void setSamlClientId(String samlClientId) { this.samlClientId = samlClientId; }
    public String getOidcDocumentationUri() { return oidcDocumentationUri; }
    public void setOidcDocumentationUri(String oidcDocumentationUri) { this.oidcDocumentationUri = oidcDocumentationUri; }
    public Set<String> getCapabilities() { return capabilities; }
    public void setCapabilities(Set<String> capabilities) { this.capabilities = capabilities == null ? new LinkedHashSet<>() : new LinkedHashSet<>(capabilities); }
    public Set<String> getExtensionProfiles() { return extensionProfiles; }
    public void setExtensionProfiles(Set<String> extensionProfiles) { this.extensionProfiles = extensionProfiles == null ? new LinkedHashSet<>() : new LinkedHashSet<>(extensionProfiles); }
    public List<FedSetupIdJagResourceBinding> getIdJagResourceBindings() { return idJagResourceBindings; }
    public void setIdJagResourceBindings(List<FedSetupIdJagResourceBinding> value) { idJagResourceBindings = value == null ? new ArrayList<>() : new ArrayList<>(value); }
    public boolean isSamlSpInitiatedSloSupported() { return samlSpInitiatedSloSupported; }
    public void setSamlSpInitiatedSloSupported(boolean value) { samlSpInitiatedSloSupported = value; }
}
