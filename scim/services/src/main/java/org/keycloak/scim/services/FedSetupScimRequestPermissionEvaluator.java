/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.scim.services;

import java.util.Set;

import org.keycloak.authorization.fgap.AdminPermissionsSchema;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.Model;
import org.keycloak.scim.resource.spi.ScimRequestPermissionEvaluator;

/**
 * Narrow SCIM-core bridge for an already-authenticated FedSetup connection.
 * Resource-operation negotiation remains enforced by
 * {@link ScimResourceTypeResource}; this class deliberately knows no client
 * attributes and grants no Keycloak Admin REST permission.
 */
final class FedSetupScimRequestPermissionEvaluator implements ScimRequestPermissionEvaluator {

    private static final Set<String> RESOURCE_TYPES = Set.of("Users", "Groups");
    private static final Set<String> SCOPES = Set.of(
            AdminPermissionsSchema.VIEW, AdminPermissionsSchema.QUERY, AdminPermissionsSchema.MANAGE);

    static void activate(KeycloakSession session) {
        session.setAttribute(SESSION_ATTRIBUTE, new FedSetupScimRequestPermissionEvaluator());
    }

    private FedSetupScimRequestPermissionEvaluator() {
    }

    @Override
    public boolean hasPermission(Model model, String realmResourceType, String scope) {
        return RESOURCE_TYPES.contains(realmResourceType) && SCOPES.contains(scope);
    }
}
