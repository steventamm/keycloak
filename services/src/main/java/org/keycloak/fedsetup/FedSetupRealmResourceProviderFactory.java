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
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;
import org.keycloak.services.scheduled.ClusterAwareScheduledTaskRunner;
import org.keycloak.timer.TimerProvider;

/** Registers the realm-scoped Express Configuration receiver at {@code /realms/{realm}/fedsetup}. */
public class FedSetupRealmResourceProviderFactory implements RealmResourceProviderFactory, EnvironmentDependentProviderFactory {

    private static final long DEFAULT_OUTBOX_INTERVAL_MILLIS = 30_000L;
    private static final long DEFAULT_SAML_METADATA_REFRESH_INTERVAL_MILLIS = 3_600_000L;

    private long outboxIntervalMillis = DEFAULT_OUTBOX_INTERVAL_MILLIS;
    private long samlMetadataRefreshIntervalMillis = DEFAULT_SAML_METADATA_REFRESH_INTERVAL_MILLIS;

    @Override public RealmResourceProvider create(KeycloakSession session) { return new FedSetupRealmResource(session); }
    @Override
    public void init(Config.Scope config) {
        outboxIntervalMillis = config.getLong("outboxIntervalMillis", DEFAULT_OUTBOX_INTERVAL_MILLIS);
        if (outboxIntervalMillis < 1_000L) {
            throw new IllegalArgumentException("FedSetup outboxIntervalMillis must be at least 1000");
        }
        samlMetadataRefreshIntervalMillis = config.getLong("samlMetadataRefreshIntervalMillis", DEFAULT_SAML_METADATA_REFRESH_INTERVAL_MILLIS);
        if (samlMetadataRefreshIntervalMillis < 60_000L) {
            throw new IllegalArgumentException("FedSetup samlMetadataRefreshIntervalMillis must be at least 60000");
        }
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        try (KeycloakSession session = factory.create()) {
            TimerProvider timer = session.getProvider(TimerProvider.class);
            timer.schedule(new ClusterAwareScheduledTaskRunner(factory, new FedSetupInstallationOutboxTask(factory), outboxIntervalMillis),
                    outboxIntervalMillis, outboxIntervalMillis);
            timer.schedule(new ClusterAwareScheduledTaskRunner(factory, new FedSetupSamlMetadataRefreshTask(factory), samlMetadataRefreshIntervalMillis),
                    samlMetadataRefreshIntervalMillis, samlMetadataRefreshIntervalMillis);
        }
    }
    @Override public void close() { }
    @Override public String getId() { return FedSetupConstants.REALM_RESOURCE_ID; }
    @Override public boolean isSupported(Config.Scope config) { return Profile.isFeatureEnabled(Profile.Feature.FED_SETUP_CONFIGURATION); }
}
