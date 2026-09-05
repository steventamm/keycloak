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
import com.fasterxml.jackson.annotation.JsonProperty;

/** The validated subset of a Catalog's standard FedSetup discovery document. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CatalogDiscovery {
    @JsonProperty("fedsetup_submission_version")
    private String submissionVersion;
    @JsonProperty("submission_endpoint")
    private String submissionEndpoint;
    @JsonProperty("status_endpoint_template")
    private String statusEndpointTemplate;
    @JsonProperty("capabilities")
    private Map<String, Map<String, Object>> capabilities = new LinkedHashMap<>();
    @JsonProperty("sections_supported")
    private Set<String> sectionsSupported = new LinkedHashSet<>();
    @JsonProperty("extensions_supported")
    private Set<String> extensionsSupported = new LinkedHashSet<>();
    @JsonProperty("auth_methods_supported")
    private Set<String> authMethodsSupported = new LinkedHashSet<>();

    public String getSubmissionVersion() { return submissionVersion; }
    public void setSubmissionVersion(String submissionVersion) { this.submissionVersion = submissionVersion; }
    public String getSubmissionEndpoint() { return submissionEndpoint; }
    public void setSubmissionEndpoint(String submissionEndpoint) { this.submissionEndpoint = submissionEndpoint; }
    public String getStatusEndpointTemplate() { return statusEndpointTemplate; }
    public void setStatusEndpointTemplate(String statusEndpointTemplate) { this.statusEndpointTemplate = statusEndpointTemplate; }
    public Map<String, Map<String, Object>> getCapabilities() { return capabilities; }
    public void setCapabilities(Map<String, Map<String, Object>> value) { capabilities = value == null ? new LinkedHashMap<>() : new LinkedHashMap<>(value); }
    public Set<String> getSectionsSupported() { return sectionsSupported; }
    public void setSectionsSupported(Set<String> value) { sectionsSupported = value == null ? new LinkedHashSet<>() : new LinkedHashSet<>(value); }
    public Set<String> getExtensionsSupported() { return extensionsSupported; }
    public void setExtensionsSupported(Set<String> value) { extensionsSupported = value == null ? new LinkedHashSet<>() : new LinkedHashSet<>(value); }
    public Set<String> getAuthMethodsSupported() { return authMethodsSupported; }
    public void setAuthMethodsSupported(Set<String> value) { authMethodsSupported = value == null ? new LinkedHashSet<>() : new LinkedHashSet<>(value); }
}
