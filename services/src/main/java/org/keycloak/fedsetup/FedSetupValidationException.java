/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup;

import jakarta.ws.rs.BadRequestException;

/** A request failed a FedSetup security or representation invariant. */
public class FedSetupValidationException extends BadRequestException {

    public FedSetupValidationException(String message) {
        super(message);
    }

    public FedSetupValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
