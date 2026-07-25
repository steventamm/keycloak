/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.scim.services;

import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.keycloak.fedsetup.representation.FedSetupConnection;
import org.keycloak.scim.protocol.request.PatchRequest;
import org.keycloak.scim.resource.group.Group;
import org.keycloak.scim.resource.user.User;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FedSetupScimFeaturePolicyTest {

    @Test
    void limitsNativeScimOperationsToTheNegotiatedFeatureSubset() {
        FedSetupConnection connection = connection("PUSH_NEW_USERS", "PUSH_USER_DEACTIVATION");

        assertTrue(ScimResourceTypeResource.allowsRead(connection, User.class));
        assertTrue(ScimResourceTypeResource.allowsRead(connection, Group.class));
        assertTrue(ScimResourceTypeResource.allowsCreate(connection, User.class));
        assertFalse(ScimResourceTypeResource.allowsCreate(connection, Group.class));
        assertFalse(ScimResourceTypeResource.allowsDelete(connection, User.class));
        assertFalse(ScimResourceTypeResource.allowsDelete(connection, Group.class));
        assertFalse(ScimResourceTypeResource.allowsRead(connection, Object.class));

        assertTrue(ScimResourceTypeResource.allowsPatch(connection, User.class,
                patch("active", JsonNodeFactory.instance.booleanNode(false))));
        assertFalse(ScimResourceTypeResource.allowsPatch(connection, User.class,
                patch("active", JsonNodeFactory.instance.booleanNode(true))));
        assertFalse(ScimResourceTypeResource.allowsPatch(connection, User.class,
                PatchRequest.create().replace("displayName", "Ada").build()));
    }

    @Test
    void requiresABooleanActiveValueAndBothFeaturesForMixedPatch() {
        FedSetupConnection connection = connection("PUSH_USER_DEACTIVATION", "PUSH_PROFILE_UPDATES");

        assertFalse(ScimResourceTypeResource.allowsPatch(connection, User.class,
                PatchRequest.create().replace("active", "not-a-boolean").build()));
        assertTrue(ScimResourceTypeResource.allowsPatch(connection, User.class,
                PatchRequest.create().replace("{\"active\":false,\"displayName\":\"Ada\"}").build()));

        connection.setScimFeatures(Set.of("PUSH_USER_DEACTIVATION"));
        assertFalse(ScimResourceTypeResource.allowsPatch(connection, User.class,
                PatchRequest.create().replace("{\"active\":false,\"displayName\":\"Ada\"}").build()));
    }

    @Test
    void appliesActiveTransitionPolicyOnlyToTheCoreActiveAttribute() {
        FedSetupConnection profileUpdates = connection("PUSH_PROFILE_UPDATES");

        assertTrue(ScimResourceTypeResource.allowsPatch(profileUpdates, User.class,
                patch("activity", JsonNodeFactory.instance.textNode("daily"))));
        assertFalse(ScimResourceTypeResource.allowsPatch(profileUpdates, User.class,
                patch("urn:ietf:params:scim:schemas:core:2.0:User:active", JsonNodeFactory.instance.booleanNode(false))));

        FedSetupConnection deactivation = connection("PUSH_USER_DEACTIVATION");
        assertTrue(ScimResourceTypeResource.allowsPatch(deactivation, User.class,
                patch("urn:ietf:params:scim:schemas:core:2.0:User:active", JsonNodeFactory.instance.booleanNode(false))));
    }

    @Test
    void permitsGroupMutationsOnlyWhenGroupPushWasNegotiated() {
        FedSetupConnection connection = connection("PUSH_GROUPS");
        assertTrue(ScimResourceTypeResource.allowsCreate(connection, Group.class));
        assertTrue(ScimResourceTypeResource.allowsDelete(connection, Group.class));
        assertTrue(ScimResourceTypeResource.allowsUpdateOperation(connection, Group.class));
        assertFalse(ScimResourceTypeResource.allowsCreate(connection, User.class));
    }

    @Test
    void previewRecordsWithNoStoredFeaturesRetainTheOriginalBestEffortSubset() {
        FedSetupConnection connection = connection();
        assertTrue(ScimResourceTypeResource.allowsCreate(connection, User.class));
        assertTrue(ScimResourceTypeResource.allowsCreate(connection, Group.class));
        assertTrue(ScimResourceTypeResource.allowsPatch(connection, User.class,
                patch("active", JsonNodeFactory.instance.booleanNode(true))));
    }

    private static FedSetupConnection connection(String... features) {
        FedSetupConnection connection = new FedSetupConnection();
        connection.setScimFeatures(Set.of(features));
        return connection;
    }

    private static PatchRequest patch(String path, com.fasterxml.jackson.databind.JsonNode value) {
        PatchRequest.PatchOperation operation = new PatchRequest.PatchOperation();
        operation.setOp("replace");
        operation.setPath(path);
        operation.setValue(value);
        return new PatchRequest(List.of(operation));
    }
}
