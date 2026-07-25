/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

import org.keycloak.common.util.Time;
import org.keycloak.fedsetup.representation.FedSetupConfigurationProfile;
import org.keycloak.fedsetup.representation.DirectInstallationTrust;
import org.keycloak.fedsetup.representation.DirectInstallationTrustInvitation;
import org.keycloak.fedsetup.representation.FedSetupFrontChannelTransaction;
import org.keycloak.fedsetup.representation.FedSetupConnection;
import org.keycloak.fedsetup.representation.FedSetupCredentialReference;
import org.keycloak.fedsetup.representation.FedSetupInstallation;
import org.keycloak.fedsetup.representation.FedSetupScimProvisioningTask;
import org.keycloak.fedsetup.representation.FedSetupTrustPreAuthorization;
import org.keycloak.models.RealmModel;
import org.keycloak.util.JsonSerialization;

/**
 * Persistent, realm-scoped FedSetup record storage.
 *
 * <p>The realm attribute store is part of Keycloak's normal realm persistence
 * and export/import lifecycle. Separate records and indexes make the scope
 * explicit and ensure no record can be read from another realm. Credentials
 * are represented only by Vault references.</p>
 */
public final class RealmFedSetupStore {

    private static final String PREFIX = "fedsetup.";
    private static final String APPLICATION_PROFILE = PREFIX + "application-profile";
    private static final String TRUST = PREFIX + "trust.";
    private static final String TRUST_INDEX = PREFIX + "trust.ids";
    private static final String INVITATION = PREFIX + "invitation.";
    private static final String INVITATION_INDEX = PREFIX + "invitation.ids";
    private static final String PRE_AUTHORIZATION = PREFIX + "trust-pre-authorization.";
    private static final String PRE_AUTHORIZATION_INDEX = PREFIX + "trust-pre-authorization.ids";
    private static final String FRONT_CHANNEL_TRANSACTION = PREFIX + "front-channel-transaction.";
    private static final String FRONT_CHANNEL_TRANSACTION_INDEX = PREFIX + "front-channel-transaction.ids";
    private static final String CONNECTION = PREFIX + "connection.";
    private static final String CONNECTION_INDEX = PREFIX + "connection.ids";
    private static final String INSTALLATION = PREFIX + "installation.";
    private static final String INSTALLATION_INDEX = PREFIX + "installation.ids";
    private static final String SCIM_TASK = PREFIX + "scim-task.";
    private static final String SCIM_TASK_INDEX = PREFIX + "scim-task.ids";
    private static final String CREDENTIAL = PREFIX + "credential.";
    private static final String CREDENTIAL_INDEX = PREFIX + "credential.ids";
    private static final String IDEMPOTENCY = PREFIX + "idempotency.";

    private final RealmModel realm;

    public RealmFedSetupStore(RealmModel realm) {
        this.realm = Objects.requireNonNull(realm, "realm");
    }

    public FedSetupConfigurationProfile getApplicationProfile() {
        return read(APPLICATION_PROFILE, FedSetupConfigurationProfile.class);
    }

    public void setApplicationProfile(FedSetupConfigurationProfile profile) {
        Objects.requireNonNull(profile, "profile");
        realm.setAttribute(APPLICATION_PROFILE, JsonSerialization.valueAsString(profile));
    }

    public DirectInstallationTrust createTrust(DirectInstallationTrust trust) {
        Objects.requireNonNull(trust, "trust");
        if (trust.getId() == null) {
            trust.setId(UUID.randomUUID().toString());
        }
        if (getTrust(trust.getId()) != null) {
            throw new FedSetupValidationException("Direct Installation Trust already exists");
        }
        if (findTrust(trust.getApplicationTenantId(), trust.getIdpIssuer()) != null) {
            throw new FedSetupValidationException("A Direct Installation Trust already exists for this Application Tenant and IdP issuer");
        }
        long now = Time.currentTime();
        trust.setVersion(1);
        trust.setCreatedAt(now);
        trust.setUpdatedAt(now);
        write(TRUST + trust.getId(), trust);
        addToIndex(TRUST_INDEX, trust.getId());
        return copy(trust, DirectInstallationTrust.class);
    }

    public DirectInstallationTrust updateTrust(DirectInstallationTrust trust, long expectedVersion) {
        DirectInstallationTrust current = requireTrust(trust.getId());
        requireVersion(current.getVersion(), expectedVersion);
        trust.setCreatedAt(current.getCreatedAt());
        trust.setVersion(current.getVersion() + 1);
        trust.setUpdatedAt(Time.currentTime());
        write(TRUST + trust.getId(), trust);
        return copy(trust, DirectInstallationTrust.class);
    }

    public DirectInstallationTrust getTrust(String id) {
        return read(TRUST + id, DirectInstallationTrust.class);
    }

    public DirectInstallationTrust requireTrust(String id) {
        DirectInstallationTrust trust = getTrust(id);
        if (trust == null) {
            throw new FedSetupValidationException("Unknown Direct Installation Trust");
        }
        return trust;
    }

    public DirectInstallationTrust findTrust(String applicationTenantId, String idpIssuer) {
        return getTrusts().stream().filter(trust -> Objects.equals(applicationTenantId, trust.getApplicationTenantId())
                && Objects.equals(idpIssuer, trust.getIdpIssuer())).findFirst().orElse(null);
    }

    public DirectInstallationTrust findTrustByCimdUri(String applicationTenantId, String cimdUri) {
        return getTrusts().stream().filter(trust -> Objects.equals(applicationTenantId, trust.getApplicationTenantId())
                && Objects.equals(cimdUri, trust.getInstallationRuntimeCimdUri())).findFirst().orElse(null);
    }

    public List<DirectInstallationTrust> getTrusts() {
        return readIndexed(TRUST_INDEX, TRUST, DirectInstallationTrust.class);
    }

    public DirectInstallationTrustInvitation createInvitation(DirectInstallationTrustInvitation invitation) {
        Objects.requireNonNull(invitation, "invitation");
        if (invitation.getId() == null) invitation.setId(UUID.randomUUID().toString());
        if (getInvitation(invitation.getId()) != null) {
            throw new FedSetupValidationException("Direct Installation Trust invitation already exists");
        }
        long now = Time.currentTime();
        invitation.setVersion(1);
        invitation.setCreatedAt(now);
        invitation.setUpdatedAt(now);
        write(INVITATION + invitation.getId(), invitation);
        addToIndex(INVITATION_INDEX, invitation.getId());
        return copy(invitation, DirectInstallationTrustInvitation.class);
    }

    public DirectInstallationTrustInvitation getInvitation(String id) {
        return read(INVITATION + id, DirectInstallationTrustInvitation.class);
    }

    public DirectInstallationTrustInvitation requireInvitation(String id) {
        DirectInstallationTrustInvitation invitation = getInvitation(id);
        if (invitation == null) throw new FedSetupValidationException("Unknown Direct Installation Trust invitation");
        return invitation;
    }

    public DirectInstallationTrustInvitation updateInvitation(DirectInstallationTrustInvitation invitation, long expectedVersion) {
        DirectInstallationTrustInvitation current = requireInvitation(invitation.getId());
        requireVersion(current.getVersion(), expectedVersion);
        invitation.setCreatedAt(current.getCreatedAt());
        invitation.setVersion(current.getVersion() + 1);
        invitation.setUpdatedAt(Time.currentTime());
        write(INVITATION + invitation.getId(), invitation);
        return copy(invitation, DirectInstallationTrustInvitation.class);
    }

    public FedSetupTrustPreAuthorization createTrustPreAuthorization(FedSetupTrustPreAuthorization entry) {
        Objects.requireNonNull(entry, "entry");
        if (entry.getId() == null) entry.setId(UUID.randomUUID().toString());
        if (getTrustPreAuthorization(entry.getId()) != null) {
            throw new FedSetupValidationException("Direct Installation Trust pre-authorization already exists");
        }
        long now = Time.currentTime();
        entry.setVersion(1);
        entry.setCreatedAt(now);
        entry.setUpdatedAt(now);
        write(PRE_AUTHORIZATION + entry.getId(), entry);
        addToIndex(PRE_AUTHORIZATION_INDEX, entry.getId());
        return copy(entry, FedSetupTrustPreAuthorization.class);
    }

    public FedSetupTrustPreAuthorization getTrustPreAuthorization(String id) {
        return read(PRE_AUTHORIZATION + id, FedSetupTrustPreAuthorization.class);
    }

    public FedSetupTrustPreAuthorization findTrustPreAuthorization(String applicationTenantId, String idpIssuer, String cimdUri) {
        return getTrustPreAuthorizations().stream().filter(entry -> !entry.isConsumed()
                && Objects.equals(applicationTenantId, entry.getApplicationTenantId())
                && Objects.equals(idpIssuer, entry.getIdpIssuer())
                && Objects.equals(cimdUri, entry.getCimdUri())).findFirst().orElse(null);
    }

    public List<FedSetupTrustPreAuthorization> getTrustPreAuthorizations() {
        return readIndexed(PRE_AUTHORIZATION_INDEX, PRE_AUTHORIZATION, FedSetupTrustPreAuthorization.class);
    }

    public FedSetupTrustPreAuthorization updateTrustPreAuthorization(FedSetupTrustPreAuthorization entry, long expectedVersion) {
        FedSetupTrustPreAuthorization current = getTrustPreAuthorization(entry.getId());
        if (current == null) throw new FedSetupValidationException("Unknown Direct Installation Trust pre-authorization");
        requireVersion(current.getVersion(), expectedVersion);
        entry.setCreatedAt(current.getCreatedAt());
        entry.setVersion(current.getVersion() + 1);
        entry.setUpdatedAt(Time.currentTime());
        write(PRE_AUTHORIZATION + entry.getId(), entry);
        return copy(entry, FedSetupTrustPreAuthorization.class);
    }

    public FedSetupFrontChannelTransaction createFrontChannelTransaction(FedSetupFrontChannelTransaction transaction) {
        Objects.requireNonNull(transaction, "transaction");
        if (transaction.getId() == null) transaction.setId(UUID.randomUUID().toString());
        if (getFrontChannelTransaction(transaction.getId()) != null) {
            throw new FedSetupValidationException("FedSetup front-channel transaction already exists");
        }
        long now = Time.currentTime();
        transaction.setVersion(1);
        transaction.setCreatedAt(now);
        transaction.setUpdatedAt(now);
        write(FRONT_CHANNEL_TRANSACTION + transaction.getId(), transaction);
        addToIndex(FRONT_CHANNEL_TRANSACTION_INDEX, transaction.getId());
        return copy(transaction, FedSetupFrontChannelTransaction.class);
    }

    public FedSetupFrontChannelTransaction getFrontChannelTransaction(String id) {
        return read(FRONT_CHANNEL_TRANSACTION + id, FedSetupFrontChannelTransaction.class);
    }

    public FedSetupFrontChannelTransaction findFrontChannelTransactionByCodeHash(String hash) {
        return getFrontChannelTransactions().stream().filter(transaction -> Objects.equals(hash, transaction.getAuthorizationCodeHash()))
                .findFirst().orElse(null);
    }

    /** Locates the IdP-side browser transaction by its opaque OAuth state value. */
    public FedSetupFrontChannelTransaction findFrontChannelTransactionByState(String state) {
        return getFrontChannelTransactions().stream().filter(transaction -> Objects.equals(state, transaction.getState()))
                .findFirst().orElse(null);
    }

    public List<FedSetupFrontChannelTransaction> getFrontChannelTransactions() {
        return readIndexed(FRONT_CHANNEL_TRANSACTION_INDEX, FRONT_CHANNEL_TRANSACTION, FedSetupFrontChannelTransaction.class);
    }

    public FedSetupFrontChannelTransaction updateFrontChannelTransaction(FedSetupFrontChannelTransaction transaction, long expectedVersion) {
        FedSetupFrontChannelTransaction current = getFrontChannelTransaction(transaction.getId());
        if (current == null) throw new FedSetupValidationException("Unknown FedSetup front-channel transaction");
        requireVersion(current.getVersion(), expectedVersion);
        transaction.setCreatedAt(current.getCreatedAt());
        transaction.setVersion(current.getVersion() + 1);
        transaction.setUpdatedAt(Time.currentTime());
        write(FRONT_CHANNEL_TRANSACTION + transaction.getId(), transaction);
        return copy(transaction, FedSetupFrontChannelTransaction.class);
    }

    public FedSetupConnection createConnection(FedSetupConnection connection) {
        Objects.requireNonNull(connection, "connection");
        if (connection.getId() == null) {
            connection.setId(UUID.randomUUID().toString());
        }
        if (getConnection(connection.getId()) != null) {
            throw new FedSetupValidationException("FedSetup Connection already exists");
        }
        long now = Time.currentTime();
        connection.setVersion(1);
        connection.setCreatedAt(now);
        connection.setUpdatedAt(now);
        write(CONNECTION + connection.getId(), connection);
        addToIndex(CONNECTION_INDEX, connection.getId());
        return copy(connection, FedSetupConnection.class);
    }

    public FedSetupConnection updateConnection(FedSetupConnection connection, long expectedVersion) {
        FedSetupConnection current = requireConnection(connection.getId());
        requireVersion(current.getVersion(), expectedVersion);
        connection.setCreatedAt(current.getCreatedAt());
        connection.setVersion(current.getVersion() + 1);
        connection.setUpdatedAt(Time.currentTime());
        write(CONNECTION + connection.getId(), connection);
        return copy(connection, FedSetupConnection.class);
    }

    public FedSetupConnection getConnection(String id) {
        return read(CONNECTION + id, FedSetupConnection.class);
    }

    public FedSetupConnection requireConnection(String id) {
        FedSetupConnection connection = getConnection(id);
        if (connection == null) {
            throw new FedSetupValidationException("Unknown FedSetup Connection");
        }
        return connection;
    }

    public FedSetupConnection findConnectionByTrust(String trustId) {
        return getConnections().stream().filter(connection -> Objects.equals(trustId, connection.getTrustId()))
                .findFirst().orElse(null);
    }

    public List<FedSetupConnection> getConnections() {
        return readIndexed(CONNECTION_INDEX, CONNECTION, FedSetupConnection.class);
    }

    public FedSetupInstallation createInstallation(FedSetupInstallation installation) {
        Objects.requireNonNull(installation, "installation");
        if (installation.getId() == null) {
            installation.setId(UUID.randomUUID().toString());
        }
        if (getInstallation(installation.getId()) != null) {
            throw new FedSetupValidationException("FedSetup Installation already exists");
        }
        long now = Time.currentTime();
        installation.setVersion(1);
        installation.setCreatedAt(now);
        installation.setUpdatedAt(now);
        write(INSTALLATION + installation.getId(), installation);
        addToIndex(INSTALLATION_INDEX, installation.getId());
        return copy(installation, FedSetupInstallation.class);
    }

    public FedSetupInstallation getInstallation(String id) {
        return read(INSTALLATION + id, FedSetupInstallation.class);
    }

    public FedSetupInstallation requireInstallation(String id) {
        FedSetupInstallation installation = getInstallation(id);
        if (installation == null) {
            throw new FedSetupValidationException("Unknown FedSetup Installation");
        }
        return installation;
    }

    public FedSetupInstallation updateInstallation(FedSetupInstallation installation, long expectedVersion) {
        FedSetupInstallation current = requireInstallation(installation.getId());
        requireVersion(current.getVersion(), expectedVersion);
        installation.setCreatedAt(current.getCreatedAt());
        installation.setVersion(current.getVersion() + 1);
        installation.setUpdatedAt(Time.currentTime());
        write(INSTALLATION + installation.getId(), installation);
        return copy(installation, FedSetupInstallation.class);
    }

    public List<FedSetupInstallation> getInstallations() {
        return readIndexed(INSTALLATION_INDEX, INSTALLATION, FedSetupInstallation.class);
    }

    /** Creates or replaces pending work for the same installation and resource. */
    public FedSetupScimProvisioningTask enqueueScimTask(FedSetupScimProvisioningTask task) {
        FedSetupScimProvisioningTask current = getScimTasks().stream().filter(candidate -> Objects.equals(candidate.getInstallationId(), task.getInstallationId())
                && Objects.equals(candidate.getResourceType(), task.getResourceType()) && Objects.equals(candidate.getResourceId(), task.getResourceId())
                && "PENDING".equals(candidate.getStatus())).findFirst().orElse(null);
        if (current != null) {
            task.setId(current.getId());
            task.setStatus("PENDING");
            task.setAttempts(0);
            task.setLastError(null);
            task.setNextAttemptAt(0);
            return updateScimTask(task, current.getVersion());
        }
        if (task.getId() == null) task.setId(UUID.randomUUID().toString());
        long now = Time.currentTime();
        task.setStatus("PENDING");
        task.setVersion(1);
        task.setCreatedAt(now);
        task.setUpdatedAt(now);
        write(SCIM_TASK + task.getId(), task);
        addToIndex(SCIM_TASK_INDEX, task.getId());
        return copy(task, FedSetupScimProvisioningTask.class);
    }

    public FedSetupScimProvisioningTask updateScimTask(FedSetupScimProvisioningTask task, long expectedVersion) {
        FedSetupScimProvisioningTask current = requireScimTask(task.getId());
        requireVersion(current.getVersion(), expectedVersion);
        task.setCreatedAt(current.getCreatedAt());
        task.setVersion(current.getVersion() + 1);
        task.setUpdatedAt(Time.currentTime());
        write(SCIM_TASK + task.getId(), task);
        return copy(task, FedSetupScimProvisioningTask.class);
    }

    public FedSetupScimProvisioningTask requireScimTask(String id) {
        FedSetupScimProvisioningTask task = read(SCIM_TASK + id, FedSetupScimProvisioningTask.class);
        if (task == null) throw new FedSetupValidationException("Unknown FedSetup SCIM provisioning task");
        return task;
    }

    public List<FedSetupScimProvisioningTask> getScimTasks() {
        return readIndexed(SCIM_TASK_INDEX, SCIM_TASK, FedSetupScimProvisioningTask.class);
    }

    public int suppressPendingScimTasks(String installationId) {
        int suppressed = 0;
        for (FedSetupScimProvisioningTask task : getScimTasks()) {
            if (Objects.equals(installationId, task.getInstallationId()) && "PENDING".equals(task.getStatus())) {
                task.setStatus("SUPPRESSED");
                task.setLastError(null);
                task.setNextAttemptAt(0);
                updateScimTask(task, task.getVersion());
                suppressed++;
            }
        }
        return suppressed;
    }

    public FedSetupCredentialReference createCredentialReference(FedSetupCredentialReference credential) {
        Objects.requireNonNull(credential, "credential");
        if (credential.getId() == null) {
            credential.setId(UUID.randomUUID().toString());
        }
        if (getCredentialReference(credential.getId()) != null) {
            throw new FedSetupValidationException("FedSetup credential reference already exists");
        }
        credential.setCreatedAt(Time.currentTime());
        write(CREDENTIAL + credential.getId(), credential);
        addToIndex(CREDENTIAL_INDEX, credential.getId());
        return copy(credential, FedSetupCredentialReference.class);
    }

    public FedSetupCredentialReference getCredentialReference(String id) {
        return read(CREDENTIAL + id, FedSetupCredentialReference.class);
    }

    /** Replaces an internal credential record; callers must never expose it. */
    public FedSetupCredentialReference replaceCredentialReference(FedSetupCredentialReference credential) {
        if (credential == null || credential.getId() == null || getCredentialReference(credential.getId()) == null) {
            throw new FedSetupValidationException("Unknown FedSetup credential reference");
        }
        write(CREDENTIAL + credential.getId(), credential);
        return copy(credential, FedSetupCredentialReference.class);
    }

    /** Permanently removes an encrypted credential after its connection is revoked. */
    public void deleteCredentialReference(String id) {
        if (id == null || id.isBlank()) return;
        realm.removeAttribute(CREDENTIAL + id);
        Set<String> ids = readIndex(CREDENTIAL_INDEX);
        if (ids.remove(id)) realm.setAttribute(CREDENTIAL_INDEX, JsonSerialization.valueAsString(ids));
    }

    /**
     * Stores an idempotency result without ever storing an authorization JWT.
     * The immutable tenant and IdP binding is part of the key: the draft
     * explicitly permits the same Idempotency-Key value in another approved
     * relationship within this realm.
     */
    public void putIdempotencyResult(String key, String applicationTenantId, String idpIssuer,
                                     String connectionId, String requestHash) {
        realm.setAttribute(IDEMPOTENCY + idempotencyScope(key, applicationTenantId, idpIssuer), connectionId + ":" + requestHash);
    }

    public String getIdempotencyResult(String key, String applicationTenantId, String idpIssuer, String requestHash) {
        String value = realm.getAttribute(IDEMPOTENCY + idempotencyScope(key, applicationTenantId, idpIssuer));
        if (value == null) {
            return null;
        }
        int separator = value.indexOf(':');
        if (separator < 1 || !Objects.equals(value.substring(separator + 1), requestHash)) {
            throw new FedSetupValidationException("Idempotency-Key was used with a different request");
        }
        return value.substring(0, separator);
    }

    private String idempotencyScope(String key, String applicationTenantId, String idpIssuer) {
        if (key == null || applicationTenantId == null || idpIssuer == null) {
            throw new FedSetupValidationException("Idempotency scope is incomplete");
        }
        return InstallationAuthorizationValidator.sha256(key + "\u0000" + applicationTenantId + "\u0000" + idpIssuer);
    }

    private void requireVersion(long actual, long expected) {
        if (actual != expected) {
            throw new FedSetupValidationException("ETag does not match the current resource version");
        }
    }

    private void addToIndex(String indexKey, String id) {
        Set<String> ids = readIndex(indexKey);
        ids.add(id);
        realm.setAttribute(indexKey, JsonSerialization.valueAsString(ids));
    }

    private Set<String> readIndex(String indexKey) {
        String encoded = realm.getAttribute(indexKey);
        if (encoded == null) {
            return new LinkedHashSet<>();
        }
        try {
            return new LinkedHashSet<>(JsonSerialization.mapper.readValue(encoded, JsonSerialization.mapper.getTypeFactory()
                    .constructCollectionType(Set.class, String.class)));
        } catch (Exception e) {
            throw new IllegalStateException("FedSetup record index is corrupt", e);
        }
    }

    private <T> List<T> readIndexed(String indexKey, String prefix, Class<T> type) {
        List<T> records = new ArrayList<>();
        for (String id : readIndex(indexKey)) {
            T record = read(prefix + id, type);
            if (record != null) {
                records.add(record);
            }
        }
        return records;
    }

    private <T> T read(String key, Class<T> type) {
        String encoded = realm.getAttribute(key);
        if (encoded == null) {
            return null;
        }
        try {
            return JsonSerialization.readValue(encoded, type);
        } catch (Exception e) {
            throw new IllegalStateException("FedSetup record is corrupt", e);
        }
    }

    private void write(String key, Object record) {
        realm.setAttribute(key, JsonSerialization.valueAsString(record));
    }

    private <T> T copy(T record, Class<T> type) {
        try {
            return JsonSerialization.readValue(JsonSerialization.valueAsString(record), type);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to copy FedSetup record", e);
        }
    }
}
