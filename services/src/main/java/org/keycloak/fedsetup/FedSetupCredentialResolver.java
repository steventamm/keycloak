/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup;

import org.keycloak.fedsetup.representation.FedSetupConnection;
import org.keycloak.fedsetup.representation.FedSetupCredentialReference;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/** Resolves an opaque, realm-local broker reference to a FedSetup credential. */
public final class FedSetupCredentialResolver {

    private static final String PREFIX = "fedsetup-credential:";

    private FedSetupCredentialResolver() {
    }

    /** Builds the only value that may be stored in a broker configuration for an encrypted FedSetup secret. */
    public static String reference(String credentialId) {
        if (credentialId == null || credentialId.isBlank()) {
            throw new FedSetupValidationException("FedSetup credential identifier is required");
        }
        return PREFIX + credentialId;
    }

    /**
     * Returns ordinary configuration unchanged.  A FedSetup reference is
     * resolved only when it still belongs to a current Connection in the
     * realm, preventing a stale or copied opaque value from becoming a
     * general credential lookup mechanism.
     */
    public static String resolve(KeycloakSession session, String configuredValue) {
        if (configuredValue == null || !configuredValue.startsWith(PREFIX)) {
            return configuredValue;
        }
        String credentialId = configuredValue.substring(PREFIX.length());
        if (credentialId.isBlank()) {
            throw new FedSetupValidationException("FedSetup broker credential reference is invalid");
        }
        RealmModel realm = session.getContext().getRealm();
        RealmFedSetupStore store = new RealmFedSetupStore(realm);
        FedSetupCredentialReference credential = store.getCredentialReference(credentialId);
        if (credential == null || !"oidc-client-secret".equals(credential.getType())
                || credential.getConnectionId() == null || credential.getEncryptedSecret() == null) {
            throw new FedSetupValidationException("FedSetup broker credential is unavailable");
        }
        FedSetupConnection connection = store.getConnection(credential.getConnectionId());
        if (connection == null || !credentialId.equals(connection.getCredentialReferenceId())) {
            throw new FedSetupValidationException("FedSetup broker credential is not bound to a Connection");
        }
        return FedSetupSecretCipher.open(session, realm, credentialId, credential.getEncryptedSecret());
    }
}
