/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup;

import org.keycloak.Config;
import org.keycloak.common.Profile;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.EnvironmentDependentProviderFactory;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;

/** Registers the administrator-only FedSetup realm API. */
public class FedSetupAdminRealmResourceProviderFactory implements AdminRealmResourceProviderFactory, EnvironmentDependentProviderFactory {

    @Override
    public AdminRealmResourceProvider create(KeycloakSession session) {
        return new AdminRealmResourceProvider() {
            @Override
            public Object getResource(KeycloakSession resourceSession, RealmModel realm, AdminPermissionEvaluator auth,
                                      AdminEventBuilder adminEvent) {
                return new FedSetupAdminResource(resourceSession, realm, auth, adminEvent);
            }

            @Override
            public void close() {
            }
        };
    }

    @Override public void init(Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public void close() { }
    @Override public String getId() { return FedSetupConstants.ADMIN_RESOURCE_ID; }
    @Override public boolean isSupported(Config.Scope config) { return Profile.isFeatureEnabled(Profile.Feature.FED_SETUP_CONFIGURATION); }
}
