/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.keycloak.OAuth2Constants;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.fedsetup.representation.FedSetupInstallation;
import org.keycloak.fedsetup.representation.FedSetupScimProvisioningTask;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.http.simple.SimpleHttpRequest;
import org.keycloak.http.simple.SimpleHttpResponse;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.util.JsonSerialization;
import org.keycloak.util.KeyWrapperUtil;

import com.fasterxml.jackson.databind.JsonNode;

/** Delivers one durable SCIM provisioning task using its bootstrap bearer or authorized credential extension. */
final class OutboundScimProvisioningDispatcher {
    private final KeycloakSession session;
    private final RealmModel realm;
    private final RealmFedSetupStore store;

    OutboundScimProvisioningDispatcher(KeycloakSession session, RealmModel realm, RealmFedSetupStore store) {
        this.session = session;
        this.realm = realm;
        this.store = store;
    }

    void dispatch(FedSetupScimProvisioningTask task) {
        long version = task.getVersion();
        try {
            FedSetupInstallation installation = store.requireInstallation(task.getInstallationId());
            if (!"ACTIVE".equals(installation.getStatus()) || !installation.getCapabilities().contains("scim")
                    || blank(installation.getScimEndpoint()) || (blank(installation.getScimCredentialReferenceId())
                    && (blank(installation.getScimTokenEndpoint()) || blank(installation.getScimServiceClientId())))) {
                complete(task, version, "SKIPPED", null);
                return;
            }
            if (!store.requireTrust(installation.getTrustId()).isActive()) {
                complete(task, version, "SUPPRESSED", null);
                return;
            }
            try {
                dispatch(task, installation, token(installation, false));
            } catch (ScimUnauthorizedException rejectedBootstrap) {
                // A core Section 8.1 bearer can be opaque, so an IdP cannot
                // always read its expiry locally.  A 401 is the authoritative
                // indication that it is no longer usable.  Only the explicitly
                // authorized Keycloak renewal extension permits a replacement;
                // do not retry a core-only installation with an invented token.
                if (!hasRenewalExtension(installation)) throw rejectedBootstrap;
                dispatch(task, installation, token(installation, true));
            }
            complete(task, version, "COMPLETE", null);
        } catch (Exception e) {
            task.setAttempts(task.getAttempts() + 1);
            task.setStatus("PENDING");
            task.setNextAttemptAt(Time.currentTime() + retryDelay(task.getAttempts()));
            task.setLastError(message(e));
            store.updateScimTask(task, version);
        }
    }

    private void dispatch(FedSetupScimProvisioningTask task, FedSetupInstallation installation, String accessToken) throws Exception {
        String collection = "USER".equals(task.getResourceType()) ? "Users" : "Groups";
        String endpoint = trim(installation.getScimEndpoint()) + "/" + collection;
        RemoteResource remote = remoteResource(endpoint, task.getResourceId(), accessToken);
        if ("USER".equals(task.getResourceType())) dispatchUser(task, installation, endpoint, remote, accessToken);
        else dispatchGroup(task, installation, endpoint, remote, accessToken);
    }

    private String token(FedSetupInstallation installation, boolean forceRenewal) throws Exception {
        if (!forceRenewal && !blank(installation.getScimCredentialReferenceId())) {
            var credential = store.getCredentialReference(installation.getScimCredentialReferenceId());
            if (credential == null || blank(credential.getEncryptedSecret())) {
                throw new FedSetupValidationException("Stored SCIM bootstrap credential is unavailable");
            }
            String bootstrap = FedSetupSecretCipher.open(session, realm, credential.getId(), credential.getEncryptedSecret());
            if (!expired(bootstrap) || blank(installation.getScimTokenEndpoint()) || blank(installation.getScimServiceClientId())) {
                return bootstrap;
            }
        }
        if (blank(installation.getScimTokenEndpoint()) || blank(installation.getScimServiceClientId())) {
            throw new FedSetupValidationException("SCIM bootstrap access token has expired and no authorized renewal extension is configured");
        }
        KeyWrapper key = session.keys().getActiveKey(realm, KeyUse.SIG, Algorithm.RS256);
        if (key == null) throw new FedSetupValidationException("Realm has no active RS256 signing key for SCIM provisioning");
        JsonWebToken assertion = new JsonWebToken().issuer(installation.getScimServiceClientId()).subject(installation.getScimServiceClientId())
                .audience(installation.getScimTokenEndpoint()).id(UUID.randomUUID().toString()).issuedNowWithTTL(300);
        String signed = new JWSBuilder().type("JWT").kid(key.getKid()).jsonContent(assertion).sign(KeyWrapperUtil.createSignatureSignerContext(key));
        SimpleHttpRequest request = SimpleHttp.create(session).doPost(installation.getScimTokenEndpoint())
                .param(OAuth2Constants.GRANT_TYPE, OAuth2Constants.CLIENT_CREDENTIALS)
                .param(OAuth2Constants.CLIENT_ID, installation.getScimServiceClientId())
                .param(OAuth2Constants.CLIENT_ASSERTION_TYPE, OAuth2Constants.CLIENT_ASSERTION_TYPE_JWT)
                .param(OAuth2Constants.CLIENT_ASSERTION, signed).acceptJson();
        try (SimpleHttpResponse response = request.asResponse()) {
            if (response.getStatus() != 200) throw new FedSetupValidationException("SCIM token endpoint returned HTTP " + response.getStatus());
            JsonNode body = JsonSerialization.mapper.readTree(response.asString());
            JsonNode token = body.get("access_token");
            if (token == null || !token.isTextual() || token.asText().isBlank()) throw new FedSetupValidationException("SCIM token endpoint returned no access token");
            return token.asText();
        }
    }

    private void dispatchUser(FedSetupScimProvisioningTask task, FedSetupInstallation installation, String endpoint,
                              RemoteResource remote, String token) throws Exception {
        UserModel user = session.users().getUserById(realm, task.getResourceId());
        boolean deactivate = "DEACTIVATE".equals(task.getOperation()) || user == null || !user.isEnabled();
        if (deactivate) {
            if (remote != null && supports(installation, "PUSH_USER_DEACTIVATION")) {
                setActive(endpoint + "/" + segment(remote.id()), false, token);
            }
            return;
        }
        if (remote == null) {
            if (supports(installation, "PUSH_NEW_USERS")) create(endpoint, userRepresentation(user), token);
            return;
        }
        if (Boolean.FALSE.equals(remote.active())) {
            if (!supports(installation, "REACTIVATE_USERS")) return;
            setActive(endpoint + "/" + segment(remote.id()), true, token);
        }
        if (supports(installation, "PUSH_PROFILE_UPDATES")) {
            replace(endpoint + "/" + segment(remote.id()), userRepresentation(user), token);
        }
    }

    private void dispatchGroup(FedSetupScimProvisioningTask task, FedSetupInstallation installation, String endpoint,
                               RemoteResource remote, String token) throws Exception {
        if (!supports(installation, "PUSH_GROUPS")) return;
        if ("DELETE".equals(task.getOperation())) {
            if (remote != null) delete(endpoint + "/" + segment(remote.id()), token);
            return;
        }
        Map<String, Object> representation = groupRepresentation(task, installation, token);
        if (representation == null) {
            if (remote != null) delete(endpoint + "/" + segment(remote.id()), token);
        } else if (remote == null) {
            create(endpoint, representation, token);
        } else {
            replace(endpoint + "/" + segment(remote.id()), representation, token);
        }
    }

    private RemoteResource remoteResource(String endpoint, String externalId, String token) throws Exception {
        try (SimpleHttpResponse response = SimpleHttp.create(session).doGet(endpoint).param("filter", "externalId eq \"" + filterValue(externalId) + "\"")
                .auth(token).acceptJson().asResponse()) {
            if (response.getStatus() == 401) throw new ScimUnauthorizedException();
            if (response.getStatus() != 200) throw new FedSetupValidationException("SCIM lookup returned HTTP " + response.getStatus());
            JsonNode resources = JsonSerialization.mapper.readTree(response.asString()).path("Resources");
            if (!resources.isArray() || resources.size() == 0) return null;
            JsonNode resource = resources.get(0);
            JsonNode id = resource.get("id");
            if (id == null || !id.isTextual() || id.asText().isBlank()) return null;
            JsonNode active = resource.get("active");
            return new RemoteResource(id.asText(), active != null && active.isBoolean() ? active.booleanValue() : null);
        }
    }

    private Map<String, Object> userRepresentation(UserModel user) {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("externalId", user.getId());
        value.put("userName", user.getUsername());
        value.put("active", user.isEnabled());
        if (!blank(user.getFirstName()) || !blank(user.getLastName())) value.put("displayName", String.join(" ", List.of(nullToEmpty(user.getFirstName()), nullToEmpty(user.getLastName()))).trim());
        if (!blank(user.getEmail())) value.put("emails", List.of(Map.of("value", user.getEmail(), "primary", true)));
        return value;
    }

    private Map<String, Object> groupRepresentation(FedSetupScimProvisioningTask task, FedSetupInstallation installation, String token) throws Exception {
        GroupModel group = realm.getGroupById(task.getResourceId());
        if (group == null) return null;
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("externalId", group.getId());
        value.put("displayName", group.getName());
        List<Map<String, String>> members = new java.util.ArrayList<>();
        String usersEndpoint = trim(installation.getScimEndpoint()) + "/Users";
        for (UserModel member : session.users().getGroupMembersStream(realm, group).toList()) {
            RemoteResource memberResource = remoteResource(usersEndpoint, member.getId(), token);
            if (memberResource != null) members.add(Map.of("value", memberResource.id()));
        }
        value.put("members", members);
        return value;
    }

    private void create(String endpoint, Map<String, Object> body, String token) throws Exception { request(SimpleHttp.create(session).doPost(endpoint).json(body).auth(token).acceptJson(), 201); }
    private void replace(String endpoint, Map<String, Object> body, String token) throws Exception { request(SimpleHttp.create(session).doPut(endpoint).json(body).auth(token).acceptJson(), 200); }
    private void delete(String endpoint, String token) throws Exception { request(SimpleHttp.create(session).doDelete(endpoint).auth(token), 204); }
    private void setActive(String endpoint, boolean active, String token) throws Exception {
        Map<String, Object> body = Map.of("schemas", List.of("urn:ietf:params:scim:api:messages:2.0:PatchOp"),
                "Operations", List.of(Map.of("op", "replace", "path", "active", "value", active)));
        request(SimpleHttp.create(session).doPatch(endpoint).json(body).auth(token).acceptJson(), 200);
    }
    private void request(SimpleHttpRequest request, int expected) throws Exception {
        try (SimpleHttpResponse response = request.asResponse()) {
            if (response.getStatus() == 401) throw new ScimUnauthorizedException();
            if (response.getStatus() != expected) throw new FedSetupValidationException("SCIM endpoint returned HTTP " + response.getStatus());
        }
    }
    private void complete(FedSetupScimProvisioningTask task, long version, String status, String error) { task.setStatus(status); task.setLastError(error); task.setNextAttemptAt(0); store.updateScimTask(task, version); }
    private static String trim(String value) { return value.endsWith("/") ? value.substring(0, value.length() - 1) : value; }
    private static String segment(String value) { if (blank(value) || value.contains("/") || value.contains("?")) throw new FedSetupValidationException("Invalid remote SCIM resource id"); return value; }
    private static int retryDelay(int attempts) { return Math.min(3600, 30 * (1 << Math.min(6, Math.max(0, attempts - 1)))); }
    private static String message(Exception error) { String value = error.getMessage(); return blank(value) ? "SCIM provisioning request failed" : value.substring(0, Math.min(512, value.length())); }
    private static String nullToEmpty(String value) { return value == null ? "" : value; }
    /** Empty is the pre-feature-selection representation used by existing preview installations. */
    private static boolean supports(FedSetupInstallation installation, String feature) {
        return installation.getScimFeatures().isEmpty() || installation.getScimFeatures().contains(feature);
    }
    private static boolean hasRenewalExtension(FedSetupInstallation installation) {
        return !blank(installation.getScimTokenEndpoint()) && !blank(installation.getScimServiceClientId());
    }
    private static String filterValue(String value) { return value.replace("\\", "\\\\").replace("\"", "\\\""); }
    private static boolean expired(String token) {
        try {
            Long expiration = new org.keycloak.jose.jws.JWSInput(token).readJsonContent(JsonWebToken.class).getExp();
            return expiration != null && expiration <= Time.currentTime() + 10;
        } catch (Exception ignored) {
            return false;
        }
    }
    private static boolean blank(String value) { return value == null || value.isBlank(); }
    private record RemoteResource(String id, Boolean active) { }
    private static final class ScimUnauthorizedException extends Exception {
        private ScimUnauthorizedException() { super("SCIM bearer token was rejected"); }
    }
}
