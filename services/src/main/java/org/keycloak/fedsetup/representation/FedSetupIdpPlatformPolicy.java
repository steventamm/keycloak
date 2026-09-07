/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup.representation;

import com.fasterxml.jackson.annotation.JsonInclude;

/** An administrator-created binding from an IdP issuer to its installation runtime. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class FedSetupIdpPlatformPolicy {
    private String id;
    private String idpIssuer;
    private String cimdUri;
    private long createdAt;
    private long updatedAt;
    private long version;

    public String getId() { return id; }
    public void setId(String value) { id = value; }
    public String getIdpIssuer() { return idpIssuer; }
    public void setIdpIssuer(String value) { idpIssuer = value; }
    public String getCimdUri() { return cimdUri; }
    public void setCimdUri(String value) { cimdUri = value; }
    public long getCreatedAt() { return createdAt; }
    public void setCreatedAt(long value) { createdAt = value; }
    public long getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(long value) { updatedAt = value; }
    public long getVersion() { return version; }
    public void setVersion(long value) { version = value; }
}
