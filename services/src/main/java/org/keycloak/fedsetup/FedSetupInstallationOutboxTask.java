/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.fedsetup;

import java.util.List;
import java.util.HashSet;
import java.util.Set;

import org.keycloak.common.util.Time;
import org.keycloak.fedsetup.representation.FedSetupInstallation;
import org.keycloak.fedsetup.representation.FedSetupScimProvisioningTask;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.timer.ScheduledTask;

import org.jboss.logging.Logger;

/**
 * Delivers due, administrator-approved FedSetup installation retries.
 *
 * <p>The task deliberately ignores {@code PENDING_REVIEW}: creating or
 * materially changing an installation always requires an explicit admin
 * dispatch.  The timer runner provides a cluster-wide lock; each realm is
 * then processed in an independent transaction so a transient failure in one
 * realm cannot prevent work in another.</p>
 */
public final class FedSetupInstallationOutboxTask implements ScheduledTask {

    static final String RETRY_PENDING = "RETRY_PENDING";
    static final String DELETE_RETRY_PENDING = "DELETE_RETRY_PENDING";

    private static final Logger LOG = Logger.getLogger(FedSetupInstallationOutboxTask.class);

    private final KeycloakSessionFactory sessionFactory;

    public FedSetupInstallationOutboxTask(KeycloakSessionFactory sessionFactory) {
        this.sessionFactory = sessionFactory;
    }

    @Override
    public void run(KeycloakSession session) {
        List<String> realmIds = session.realms().getRealmsStream().map(RealmModel::getId).toList();
        for (String realmId : realmIds) {
            processRealm(realmId);
        }
    }

    @Override
    public String getTaskName() {
        return "fedsetup-installation-outbox";
    }

    static boolean isDue(FedSetupInstallation installation, long now) {
        return (RETRY_PENDING.equals(installation.getStatus()) || DELETE_RETRY_PENDING.equals(installation.getStatus()))
                && installation.getNextAttemptAt() <= now;
    }

    private void processRealm(String realmId) {
        KeycloakModelUtils.runJobInTransaction(sessionFactory, session -> {
            RealmModel realm = session.realms().getRealm(realmId);
            if (realm == null) {
                return;
            }
            KeycloakContext context = session.getContext();
            context.setRealm(realm);
            RealmFedSetupStore store = new RealmFedSetupStore(realm);
            long now = Time.currentTime();

            for (FedSetupInstallation installation : store.getInstallations()) {
                if ("ACTIVE".equals(installation.getStatus()) && installation.getRemoteConnectionId() != null) {
                    try {
                        new OutboundInstallationDispatcher(session, realm, store).refreshDesiredSso(installation);
                    } catch (FedSetupValidationException e) {
                        LOG.debugf("FedSetup SSO change detection skipped installation %s in realm %s: %s", installation.getId(), realmId, e.getMessage());
                    } catch (RuntimeException e) {
                        LOG.warnf(e, "FedSetup SSO change detection failed for installation %s in realm %s", installation.getId(), realmId);
                    }
                    continue;
                }
                if (!isDue(installation, now)) {
                    continue;
                }
                try {
                    OutboundInstallationDispatcher dispatcher = new OutboundInstallationDispatcher(session, realm, store);
                    if (DELETE_RETRY_PENDING.equals(installation.getStatus())) {
                        dispatcher.delete(installation);
                    } else {
                        dispatcher.dispatch(installation);
                    }
                } catch (FedSetupValidationException e) {
                    // The dispatcher persists normal delivery failures.  This
                    // branch is for a concurrent admin update/version conflict
                    // and must not overwrite the more recent record.
                    LOG.debugf("FedSetup outbox skipped installation %s in realm %s: %s", installation.getId(), realmId, e.getMessage());
                } catch (RuntimeException e) {
                    LOG.warnf(e, "FedSetup outbox failed while processing installation %s in realm %s", installation.getId(), realmId);
                }
            }
            Set<String> scimInstallationsProcessed = new HashSet<>();
            for (FedSetupScimProvisioningTask task : store.getScimTasks()) {
                if (!"PENDING".equals(task.getStatus()) || task.getNextAttemptAt() > now) {
                    continue;
                }
                if (!scimInstallationsProcessed.add(task.getInstallationId())) {
                    continue;
                }
                try {
                    new OutboundScimProvisioningDispatcher(session, realm, store).dispatch(task);
                } catch (FedSetupValidationException e) {
                    LOG.debugf("FedSetup SCIM outbox skipped task %s in realm %s: %s", task.getId(), realmId, e.getMessage());
                } catch (RuntimeException e) {
                    LOG.warnf(e, "FedSetup SCIM outbox failed while processing task %s in realm %s", task.getId(), realmId);
                }
            }
        });
    }
}
