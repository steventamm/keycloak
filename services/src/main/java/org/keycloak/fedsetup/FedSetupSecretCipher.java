/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup;

import java.nio.charset.StandardCharsets;

import org.keycloak.TokenCategory;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwe.JWE;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.util.TokenUtil;

/** Encrypts response credentials with the realm's normal internal encryption key. */
final class FedSetupSecretCipher {

    private static final String SEPARATOR = "\u0000";

    private FedSetupSecretCipher() {
    }

    static String seal(KeycloakSession session, RealmModel realm, String credentialId, String secret) {
        if (blank(credentialId) || blank(secret)) throw new FedSetupValidationException("Credential value is required");
        try {
            String algorithm = session.tokens().cekManagementAlgorithm(TokenCategory.INTERNAL);
            KeyWrapper key = session.keys().getActiveKey(realm, KeyUse.ENC, algorithm);
            if (key == null || key.getSecretKey() == null) {
                throw new FedSetupValidationException("Realm has no active encryption key for FedSetup credentials");
            }
            byte[] plaintext = (credentialId + SEPARATOR + secret).getBytes(StandardCharsets.UTF_8);
            return TokenUtil.jweDirectEncode(key.getKid(), key.getSecretKey(), null, plaintext);
        } catch (FedSetupValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new FedSetupValidationException("Unable to encrypt FedSetup credential", e);
        }
    }

    static String open(KeycloakSession session, RealmModel realm, String credentialId, String encryptedSecret) {
        if (blank(credentialId) || blank(encryptedSecret)) throw new FedSetupValidationException("FedSetup credential is unavailable");
        try {
            String kid = new JWE(encryptedSecret).getHeader().getKeyId();
            String algorithm = session.tokens().cekManagementAlgorithm(TokenCategory.INTERNAL);
            KeyWrapper key = kid == null ? session.keys().getActiveKey(realm, KeyUse.ENC, algorithm)
                    : session.keys().getKey(realm, kid, KeyUse.ENC, algorithm);
            if (key == null || key.getSecretKey() == null) throw new FedSetupValidationException("FedSetup credential encryption key is unavailable");
            String plaintext = new String(TokenUtil.jweDirectVerifyAndDecode(key.getSecretKey(), null, encryptedSecret), StandardCharsets.UTF_8);
            int separator = plaintext.indexOf(SEPARATOR);
            if (separator <= 0 || !credentialId.equals(plaintext.substring(0, separator))) {
                throw new FedSetupValidationException("FedSetup credential does not match its connection");
            }
            String value = plaintext.substring(separator + SEPARATOR.length());
            if (value.isBlank()) throw new FedSetupValidationException("FedSetup credential is unavailable");
            return value;
        } catch (FedSetupValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new FedSetupValidationException("Unable to decrypt FedSetup credential", e);
        }
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }
}
