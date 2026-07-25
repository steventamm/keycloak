/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup.representation;

/** An IdP administrator's signed approval returned to the Application administrator. */
public class DirectInstallationTrustApprovalRequest {
    private String invitation;
    private String approval;

    public String getInvitation() { return invitation; }
    public void setInvitation(String invitation) { this.invitation = invitation; }
    public String getApproval() { return approval; }
    public void setApproval(String approval) { this.approval = approval; }
}
