/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup.representation;

/** The newly issued, ticket-safe pre-authorization and its public record. */
public record FedSetupTrustPreAuthorizationResult(FedSetupTrustPreAuthorization preAuthorization,
                                                  String trustPreAuthorization) {
}
