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

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import org.keycloak.common.util.Time;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.events.EventStoreProvider;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.AuthDetails;
import org.keycloak.events.admin.OperationType;
import org.keycloak.fedsetup.representation.DirectInstallationTrust;
import org.keycloak.fedsetup.representation.FedSetupConnection;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.jboss.logging.Logger;

/** Emits a redacted, protocol-originated Keycloak admin event. */
final class FedSetupAudit {

    private static final String RESOURCE_TYPE = "FEDSETUP";
    private static final String RUNTIME_CLIENT = "fedsetup-runtime";
    private static final Logger LOG = Logger.getLogger(FedSetupAudit.class);

    private FedSetupAudit() {
    }

    static void success(KeycloakSession session, RealmModel realm, OperationType operation, String action,
                        DirectInstallationTrust trust, FedSetupConnection connection) {
        emit(session, realm, operation, action, trust, connection, null);
    }

    static void failure(KeycloakSession session, RealmModel realm, String action, FedSetupConnection connection, String error) {
        emit(session, realm, OperationType.UPDATE, action, null, connection, error);
    }

    private static void emit(KeycloakSession session, RealmModel realm, OperationType operation, String action,
                             DirectInstallationTrust trust, FedSetupConnection connection, String error) {
        if (!realm.isAdminEventsEnabled()) {
            return;
        }
        AdminEvent event = new AdminEvent();
        event.setId(UUID.randomUUID().toString());
        event.setTime(Time.currentTimeMillis());
        event.setRealmId(realm.getId());
        event.setRealmName(realm.getName());
        event.setOperationType(operation);
        event.setResourceTypeAsString(RESOURCE_TYPE);
        event.setResourcePath("realms/" + realm.getName() + "/fedsetup/" + action
                + (connection == null ? "" : "/connections/" + connection.getId()));
        event.setAuthDetails(authDetails(session, realm));
        event.setDetails(details(action, trust, connection));
        event.setError(error);

        EventStoreProvider store = session.getProvider(EventStoreProvider.class);
        if (store != null) {
            store.onEvent(event, false);
        }
        HashSet<String> configured = new HashSet<>(realm.getEventsListenersStream().toList());
        session.getKeycloakSessionFactory().getProviderFactoriesStream(EventListenerProvider.class)
                .filter(factory -> configured.contains(factory.getId()) || ((EventListenerProviderFactory) factory).isGlobal())
                .forEach(factory -> {
                    EventListenerProvider listener = session.getProvider(EventListenerProvider.class, factory.getId());
                    if (listener != null) {
                        try {
                            listener.onEvent(event, false);
                        } catch (RuntimeException e) {
                            // Mirrors Keycloak's AdminEventBuilder behavior:
                            // an optional listener must not roll back a valid
                            // protocol operation after its state is stored.
                            LOG.warnf(e, "Unable to deliver FedSetup audit event to %s", factory.getId());
                        }
                    }
                });
    }

    static Map<String, String> details(String action, DirectInstallationTrust trust, FedSetupConnection connection) {
        Map<String, String> result = new LinkedHashMap<>();
        result.put("fedsetup_action", action);
        if (trust != null) {
            result.put("trust_id", trust.getId());
            result.put("application_tenant_id", trust.getApplicationTenantId());
            result.put("idp_issuer", trust.getIdpIssuer());
        }
        if (connection != null) {
            result.put("connection_id", connection.getId());
            result.put("application_tenant_id", connection.getApplicationTenantId());
            result.put("idp_issuer", connection.getIdpIssuer());
        }
        return result;
    }

    private static AuthDetails authDetails(KeycloakSession session, RealmModel realm) {
        AuthDetails details = new AuthDetails();
        details.setRealmId(realm.getId());
        details.setRealmName(realm.getName());
        details.setClientId(RUNTIME_CLIENT);
        if (session.getContext().getConnection() != null) {
            details.setIpAddress(session.getContext().getConnection().getRemoteAddr());
        }
        return details;
    }
}
