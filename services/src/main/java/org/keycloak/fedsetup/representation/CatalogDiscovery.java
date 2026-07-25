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
    @JsonProperty("supported_protocols")
    private Set<String> supportedProtocols = new LinkedHashSet<>();
    @JsonProperty("supported_capabilities")
    private Set<String> supportedCapabilities = new LinkedHashSet<>();
    @JsonProperty("supported_auth_methods")
    private Set<String> supportedAuthMethods = new LinkedHashSet<>();
    @JsonProperty("webhooks_supported")
    private boolean webhooksSupported;

    public String getSubmissionVersion() { return submissionVersion; }
    public void setSubmissionVersion(String submissionVersion) { this.submissionVersion = submissionVersion; }
    public String getSubmissionEndpoint() { return submissionEndpoint; }
    public void setSubmissionEndpoint(String submissionEndpoint) { this.submissionEndpoint = submissionEndpoint; }
    public String getStatusEndpointTemplate() { return statusEndpointTemplate; }
    public void setStatusEndpointTemplate(String statusEndpointTemplate) { this.statusEndpointTemplate = statusEndpointTemplate; }
    public Set<String> getSupportedProtocols() { return supportedProtocols; }
    public void setSupportedProtocols(Set<String> supportedProtocols) { this.supportedProtocols = supportedProtocols == null ? new LinkedHashSet<>() : new LinkedHashSet<>(supportedProtocols); }
    public Set<String> getSupportedCapabilities() { return supportedCapabilities; }
    public void setSupportedCapabilities(Set<String> supportedCapabilities) { this.supportedCapabilities = supportedCapabilities == null ? new LinkedHashSet<>() : new LinkedHashSet<>(supportedCapabilities); }
    public Set<String> getSupportedAuthMethods() { return supportedAuthMethods; }
    public void setSupportedAuthMethods(Set<String> supportedAuthMethods) { this.supportedAuthMethods = supportedAuthMethods == null ? new LinkedHashSet<>() : new LinkedHashSet<>(supportedAuthMethods); }
    public boolean isWebhooksSupported() { return webhooksSupported; }
    public void setWebhooksSupported(boolean webhooksSupported) { this.webhooksSupported = webhooksSupported; }
}
