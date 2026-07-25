/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup.representation;

/** Administrator request to bind an existing broker to an approved trust. */
public class ManualConnectionAdoption {
    private String trustId;
    private String brokerAlias;

    public String getTrustId() { return trustId; }
    public void setTrustId(String trustId) { this.trustId = trustId; }
    public String getBrokerAlias() { return brokerAlias; }
    public void setBrokerAlias(String brokerAlias) { this.brokerAlias = brokerAlias; }
}
