/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup.representation;

import com.fasterxml.jackson.annotation.JsonInclude;

/** One-time artifact returned by an invitation or approval operation. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class DirectInstallationTrustConsentResult {
    private String invitation;
    private String approval;
    private DirectInstallationTrust trust;

    public String getInvitation() { return invitation; }
    public void setInvitation(String invitation) { this.invitation = invitation; }
    public String getApproval() { return approval; }
    public void setApproval(String approval) { this.approval = approval; }
    public DirectInstallationTrust getTrust() { return trust; }
    public void setTrust(DirectInstallationTrust trust) { this.trust = trust; }
}
