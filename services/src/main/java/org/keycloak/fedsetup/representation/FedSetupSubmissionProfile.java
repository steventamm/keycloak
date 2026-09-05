/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup.representation;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonInclude;

/** Listing-owned data used to generate a FedSetup Submission Manifest. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class FedSetupSubmissionProfile {
    private String displayName;
    private String description;
    private String logoUri;
    private String homepageUri;
    private String oidcClientId;
    private String samlClientId;
    private String termsOfServiceUri;
    private String privacyPolicyUri;
    private String manifestVersion;
    private String changelog;
    private String oidcDocumentationUri;
    private String samlDocumentationUri;
    private String initiateLoginUri;
    private Set<String> oidcScopes = new LinkedHashSet<>();
    private Map<String, String> scopeJustifications = new LinkedHashMap<>();
    private List<Map<String, Object>> contacts = new ArrayList<>();
    private Set<String> categories = new LinkedHashSet<>();
    private Set<String> deploymentRegions = new LinkedHashSet<>();
    private List<Map<String, Object>> testAccounts = new ArrayList<>();
    private Map<String, Object> listing = new LinkedHashMap<>();
    private List<Map<String, Object>> installationParameters = new ArrayList<>();
    private Map<String, Object> publisher = new LinkedHashMap<>();
    private Map<String, Object> extensions = new LinkedHashMap<>();
    private Set<String> capabilities = new LinkedHashSet<>();
    private String configurationDiscoveryUri;
    private Map<String, Object> expressConfigurationCapabilities = new LinkedHashMap<>();
    private Set<String> providerDelegationProfiles = new LinkedHashSet<>();
    private Set<String> federationExtensionProfiles = new LinkedHashSet<>();
    private List<FedSetupSubmissionIdJagResourceBinding> idJagResourceBindings = new ArrayList<>();
    private boolean samlSpInitiatedSloSupported;

    public String getDisplayName() { return displayName; }
    public void setDisplayName(String displayName) { this.displayName = displayName; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public String getLogoUri() { return logoUri; }
    public void setLogoUri(String logoUri) { this.logoUri = logoUri; }
    public String getHomepageUri() { return homepageUri; }
    public void setHomepageUri(String homepageUri) { this.homepageUri = homepageUri; }
    public String getOidcClientId() { return oidcClientId; }
    public void setOidcClientId(String oidcClientId) { this.oidcClientId = oidcClientId; }
    public String getSamlClientId() { return samlClientId; }
    public void setSamlClientId(String samlClientId) { this.samlClientId = samlClientId; }
    public String getTermsOfServiceUri() { return termsOfServiceUri; }
    public void setTermsOfServiceUri(String termsOfServiceUri) { this.termsOfServiceUri = termsOfServiceUri; }
    public String getPrivacyPolicyUri() { return privacyPolicyUri; }
    public void setPrivacyPolicyUri(String privacyPolicyUri) { this.privacyPolicyUri = privacyPolicyUri; }
    public String getManifestVersion() { return manifestVersion; }
    public void setManifestVersion(String manifestVersion) { this.manifestVersion = manifestVersion; }
    public String getChangelog() { return changelog; }
    public void setChangelog(String changelog) { this.changelog = changelog; }
    public String getOidcDocumentationUri() { return oidcDocumentationUri; }
    public void setOidcDocumentationUri(String oidcDocumentationUri) { this.oidcDocumentationUri = oidcDocumentationUri; }
    public String getSamlDocumentationUri() { return samlDocumentationUri; }
    public void setSamlDocumentationUri(String samlDocumentationUri) { this.samlDocumentationUri = samlDocumentationUri; }
    public String getInitiateLoginUri() { return initiateLoginUri; }
    public void setInitiateLoginUri(String initiateLoginUri) { this.initiateLoginUri = initiateLoginUri; }
    public Set<String> getOidcScopes() { return oidcScopes; }
    public void setOidcScopes(Set<String> oidcScopes) { this.oidcScopes = oidcScopes == null ? new LinkedHashSet<>() : new LinkedHashSet<>(oidcScopes); }
    public Map<String, String> getScopeJustifications() { return scopeJustifications; }
    public void setScopeJustifications(Map<String, String> scopeJustifications) { this.scopeJustifications = scopeJustifications == null ? new LinkedHashMap<>() : new LinkedHashMap<>(scopeJustifications); }
    public List<Map<String, Object>> getContacts() { return contacts; }
    public void setContacts(List<Map<String, Object>> contacts) { this.contacts = contacts == null ? new ArrayList<>() : new ArrayList<>(contacts); }
    public Set<String> getCategories() { return categories; }
    public void setCategories(Set<String> categories) { this.categories = categories == null ? new LinkedHashSet<>() : new LinkedHashSet<>(categories); }
    public Set<String> getDeploymentRegions() { return deploymentRegions; }
    public void setDeploymentRegions(Set<String> deploymentRegions) { this.deploymentRegions = deploymentRegions == null ? new LinkedHashSet<>() : new LinkedHashSet<>(deploymentRegions); }
    public List<Map<String, Object>> getTestAccounts() { return testAccounts; }
    public void setTestAccounts(List<Map<String, Object>> value) { testAccounts = value == null ? new ArrayList<>() : new ArrayList<>(value); }
    public Map<String, Object> getListing() { return listing; }
    public void setListing(Map<String, Object> value) { listing = value == null ? new LinkedHashMap<>() : new LinkedHashMap<>(value); }
    public List<Map<String, Object>> getInstallationParameters() { return installationParameters; }
    public void setInstallationParameters(List<Map<String, Object>> value) { installationParameters = value == null ? new ArrayList<>() : new ArrayList<>(value); }
    public Map<String, Object> getPublisher() { return publisher; }
    public void setPublisher(Map<String, Object> value) { publisher = value == null ? new LinkedHashMap<>() : new LinkedHashMap<>(value); }
    public Map<String, Object> getExtensions() { return extensions; }
    public void setExtensions(Map<String, Object> value) { extensions = value == null ? new LinkedHashMap<>() : new LinkedHashMap<>(value); }
    public Set<String> getCapabilities() { return capabilities; }
    public void setCapabilities(Set<String> capabilities) { this.capabilities = capabilities == null ? new LinkedHashSet<>() : new LinkedHashSet<>(capabilities); }
    public String getConfigurationDiscoveryUri() { return configurationDiscoveryUri; }
    public void setConfigurationDiscoveryUri(String value) { configurationDiscoveryUri = value; }
    public Map<String, Object> getExpressConfigurationCapabilities() { return expressConfigurationCapabilities; }
    public void setExpressConfigurationCapabilities(Map<String, Object> value) { expressConfigurationCapabilities = value == null ? new LinkedHashMap<>() : new LinkedHashMap<>(value); }
    public Set<String> getProviderDelegationProfiles() { return providerDelegationProfiles; }
    public void setProviderDelegationProfiles(Set<String> value) { providerDelegationProfiles = value == null ? new LinkedHashSet<>() : new LinkedHashSet<>(value); }
    public Set<String> getFederationExtensionProfiles() { return federationExtensionProfiles; }
    public void setFederationExtensionProfiles(Set<String> value) { federationExtensionProfiles = value == null ? new LinkedHashSet<>() : new LinkedHashSet<>(value); }
    public List<FedSetupSubmissionIdJagResourceBinding> getIdJagResourceBindings() { return idJagResourceBindings; }
    public void setIdJagResourceBindings(List<FedSetupSubmissionIdJagResourceBinding> value) { idJagResourceBindings = value == null ? new ArrayList<>() : new ArrayList<>(value); }
    public boolean isSamlSpInitiatedSloSupported() { return samlSpInitiatedSloSupported; }
    public void setSamlSpInitiatedSloSupported(boolean value) { samlSpInitiatedSloSupported = value; }
}
