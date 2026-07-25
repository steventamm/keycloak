/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.scim.resource.spi;

import org.keycloak.models.Model;

/**
 * Request-local authorization that a SCIM entry point may install after it
 * has authenticated a caller using an authorization mechanism outside of the
 * normal Keycloak admin-permission model.
 *
 * <p>Absent an evaluator, SCIM providers use their normal admin-permission
 * checks. Implementations must be request-local and must grant only the
 * resource types and scopes established by their authenticated entry point.</p>
 */
@FunctionalInterface
public interface ScimRequestPermissionEvaluator {

    String SESSION_ATTRIBUTE = ScimRequestPermissionEvaluator.class.getName();

    /**
     * Returns whether the authenticated request may perform the internal SCIM
     * permission check for the supplied resource type and scope. {@code model}
     * is {@code null} for collection-level checks such as create and query.
     */
    boolean hasPermission(Model model, String realmResourceType, String scope);
}
