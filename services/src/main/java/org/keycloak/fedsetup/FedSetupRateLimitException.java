/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup;

/** Signals a profile-defined deferred-approval polling floor. */
public final class FedSetupRateLimitException extends FedSetupValidationException {
    private final long retryAfter;

    public FedSetupRateLimitException(long retryAfter) {
        super("The deferred Trust proposal has not reached its polling interval");
        this.retryAfter = Math.max(1, retryAfter);
    }

    public long getRetryAfter() {
        return retryAfter;
    }
}
