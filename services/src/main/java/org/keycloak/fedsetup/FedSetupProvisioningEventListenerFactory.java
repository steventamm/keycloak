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
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.EnvironmentDependentProviderFactory;

/** Globally observes admin events, but creates work only for active FedSetup SCIM installations. */
public final class FedSetupProvisioningEventListenerFactory implements EventListenerProviderFactory, EnvironmentDependentProviderFactory {
    @Override public EventListenerProvider create(KeycloakSession session) { return new FedSetupProvisioningEventListener(session); }
    @Override public boolean isGlobal() { return true; }
    @Override public void init(Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public void close() { }
    @Override public String getId() { return "fedsetup-provisioning"; }
    @Override public boolean isSupported(Config.Scope config) { return Profile.isFeatureEnabled(Profile.Feature.FED_SETUP_CONFIGURATION); }
}
