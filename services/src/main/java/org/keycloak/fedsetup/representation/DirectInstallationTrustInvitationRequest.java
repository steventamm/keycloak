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

/** Values an Application Tenant Admin selects before issuing an invitation. */
public class DirectInstallationTrustInvitationRequest {
    private String idpIssuer;
    private String signingKeyJwk;
    private String runtimeJwksUri;
    private String runtimeSigningCertificate;
    private Set<String> capabilities = new LinkedHashSet<>();
    private Set<String> extensionProfiles = new LinkedHashSet<>();
    private long expiresAt;

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
    public long getExpiresAt() { return expiresAt; }
    public void setExpiresAt(long expiresAt) { this.expiresAt = expiresAt; }
}
