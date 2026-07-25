/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup;

import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.fedsetup.representation.FedSetupInstallation;
import org.keycloak.fedsetup.representation.FedSetupScimProvisioningTask;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/** Adds durable SCIM work after administrator user/group mutations. */
final class FedSetupProvisioningEventListener implements EventListenerProvider {
    private final KeycloakSession session;

    FedSetupProvisioningEventListener(KeycloakSession session) { this.session = session; }

    @Override public void onEvent(Event event) { }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
        if ((event.getResourceType() != ResourceType.USER && event.getResourceType() != ResourceType.GROUP
                && event.getResourceType() != ResourceType.GROUP_MEMBERSHIP)
                || (event.getOperationType() != OperationType.CREATE && event.getOperationType() != OperationType.UPDATE && event.getOperationType() != OperationType.DELETE)
                || event.getResourceId() == null || event.getRealmId() == null) return;
        RealmModel realm = session.realms().getRealm(event.getRealmId());
        if (realm == null) return;
        RealmFedSetupStore store = new RealmFedSetupStore(realm);
        String resourceType = event.getResourceType() == ResourceType.USER ? "USER" : "GROUP";
        String resourceId = event.getResourceType() == ResourceType.GROUP_MEMBERSHIP ? membershipGroupId(event, realm) : event.getResourceId();
        if (resourceId == null) return;
        for (FedSetupInstallation installation : store.getInstallations()) {
            if (!"ACTIVE".equals(installation.getStatus()) || !installation.getCapabilities().contains("scim")
                    || installation.getScimEndpoint() == null || (installation.getScimCredentialReferenceId() == null
                    && (installation.getScimTokenEndpoint() == null || installation.getScimServiceClientId() == null))) continue;
            String operation = operation(event, resourceType, installation);
            if (operation == null) continue;
            FedSetupScimProvisioningTask task = new FedSetupScimProvisioningTask();
            task.setInstallationId(installation.getId());
            task.setResourceType(resourceType);
            task.setResourceId(resourceId);
            task.setOperation(operation);
            store.enqueueScimTask(task);
        }
    }

    private static String operation(AdminEvent event, String resourceType, FedSetupInstallation installation) {
        if ("GROUP".equals(resourceType)) {
            return selected(installation, "PUSH_GROUPS")
                    ? event.getOperationType() == OperationType.DELETE ? "DELETE" : "UPSERT" : null;
        }
        if (event.getOperationType() == OperationType.CREATE) {
            return selected(installation, "PUSH_NEW_USERS") ? "UPSERT" : null;
        }
        if (event.getOperationType() == OperationType.DELETE) {
            return selected(installation, "PUSH_USER_DEACTIVATION") ? "DEACTIVATE" : null;
        }
        return selected(installation, "PUSH_PROFILE_UPDATES")
                || selected(installation, "PUSH_USER_DEACTIVATION")
                || selected(installation, "REACTIVATE_USERS") ? "UPSERT" : null;
    }

    /** Group-membership events are emitted from a user URI; the group is its final path segment. */
    private static String membershipGroupId(AdminEvent event, RealmModel realm) {
        String path = event.getResourcePath();
        if (path == null || path.isBlank()) return null;
        int separator = path.lastIndexOf('/');
        String id = separator < 0 ? path : path.substring(separator + 1);
        return id.isBlank() || realm.getGroupById(id) == null ? null : id;
    }

    private static boolean selected(FedSetupInstallation installation, String feature) {
        return installation.getScimFeatures().isEmpty() || installation.getScimFeatures().contains(feature);
    }

    @Override public void close() { }
}
