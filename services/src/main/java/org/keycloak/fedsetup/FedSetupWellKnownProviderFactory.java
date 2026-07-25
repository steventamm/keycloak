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
import org.keycloak.provider.EnvironmentDependentProviderFactory;
import org.keycloak.wellknown.WellKnownProvider;
import org.keycloak.wellknown.WellKnownProviderFactory;

/** Exposes realm-scoped FedSetup discovery only when the preview feature and profile are enabled. */
public class FedSetupWellKnownProviderFactory implements WellKnownProviderFactory, EnvironmentDependentProviderFactory {

    @Override
    public WellKnownProvider create(KeycloakSession session) {
        if (new RealmFedSetupStore(session.getContext().getRealm()).getApplicationProfile() == null) {
            return null;
        }
        return new FedSetupWellKnownProvider(session);
    }

    @Override public void init(Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public void close() { }
    @Override public String getId() { return FedSetupConstants.WELL_KNOWN_ALIAS; }
    @Override public boolean isSupported(Config.Scope config) { return Profile.isFeatureEnabled(Profile.Feature.FED_SETUP_CONFIGURATION); }
}
