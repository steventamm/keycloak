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

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.timer.ScheduledTask;

/** Performs the per-realm portion of the cluster-single SAML metadata refresh job. */
public final class FedSetupSamlMetadataRefreshTask implements ScheduledTask {

    private static final Logger LOG = Logger.getLogger(FedSetupSamlMetadataRefreshTask.class);

    private final KeycloakSessionFactory sessionFactory;

    public FedSetupSamlMetadataRefreshTask(KeycloakSessionFactory sessionFactory) {
        this.sessionFactory = sessionFactory;
    }

    @Override
    public void run(KeycloakSession session) {
        List<String> realmIds = session.realms().getRealmsStream().map(RealmModel::getId).toList();
        for (String realmId : realmIds) {
            KeycloakModelUtils.runJobInTransaction(sessionFactory, transactionSession -> refreshRealm(transactionSession, realmId));
        }
    }

    private void refreshRealm(KeycloakSession session, String realmId) {
        RealmModel realm = session.realms().getRealm(realmId);
        if (realm == null) {
            return;
        }
        KeycloakContext context = session.getContext();
        context.setRealm(realm);
        try {
            new FedSetupSamlMetadataRefresher(session, realm, new RealmFedSetupStore(realm)).refreshAll();
        } catch (RuntimeException e) {
            LOG.warnf(e, "FedSetup SAML metadata refresh failed for realm %s", realmId);
        }
    }

    @Override
    public String getTaskName() {
        return "fedsetup-saml-metadata-refresh";
    }
}
