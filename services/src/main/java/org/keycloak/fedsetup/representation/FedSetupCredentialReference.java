/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup.representation;

import com.fasterxml.jackson.annotation.JsonInclude;

/** Realm-local credential metadata. Response credentials are stored only encrypted. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class FedSetupCredentialReference {
    private String id;
    private String connectionId;
    private String type;
    private String vaultReference;
    private String encryptedSecret;
    private long createdAt;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getConnectionId() { return connectionId; }
    public void setConnectionId(String connectionId) { this.connectionId = connectionId; }
    public String getType() { return type; }
    public void setType(String type) { this.type = type; }
    public String getVaultReference() { return vaultReference; }
    public void setVaultReference(String vaultReference) { this.vaultReference = vaultReference; }
    public String getEncryptedSecret() { return encryptedSecret; }
    public void setEncryptedSecret(String value) { encryptedSecret = value; }
    public long getCreatedAt() { return createdAt; }
    public void setCreatedAt(long createdAt) { this.createdAt = createdAt; }
}
