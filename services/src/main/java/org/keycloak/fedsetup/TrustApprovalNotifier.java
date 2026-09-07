/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup;

import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.fedsetup.representation.FedSetupConfigurationProfile;
import org.keycloak.fedsetup.representation.FedSetupPendingTrustAuthorization;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.http.simple.SimpleHttpRequest;
import org.keycloak.http.simple.SimpleHttpResponse;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.util.KeyWrapperUtil;

import org.apache.http.client.config.RequestConfig;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;

/** Sends the optional, signed deferred-approval wake-up event after approval. */
public final class TrustApprovalNotifier {

    private TrustApprovalNotifier() {
    }

    public static void notifyApproved(KeycloakSession session, RealmModel realm, RealmFedSetupStore store,
                                      FedSetupPendingTrustAuthorization pending) {
        if (!"APPROVED".equals(pending.getStatus()) || pending.getApprovalNotificationEndpoint() == null) return;
        String endpoint = pending.getApprovalNotificationEndpoint();
        try {
            String notification = notification(session, realm, store.getApplicationProfile(), pending, endpoint);
            RequestConfig noRedirects = RequestConfig.copy(RequestConfig.DEFAULT).setRedirectsEnabled(false).build();
            SimpleHttpRequest request = SimpleHttp.create(session).withRequestConfig(noRedirects).doPost(endpoint)
                    .header("Content-Type", "application/jwt")
                    .entity(new StringEntity(notification, ContentType.create("application/jwt", "UTF-8")));
            try (SimpleHttpResponse response = request.asResponse()) {
                if (response.getStatus() >= 200 && response.getStatus() < 300) {
                    pending.setApprovalNotificationEndpoint(null);
                    store.updatePendingTrustAuthorization(pending, pending.getVersion());
                }
            }
        } catch (Exception ignored) {
            // A notification is an advisory doorbell. Approval remains durable;
            // the IdP can resume with a later regular deferred request.
        }
    }

    private static String notification(KeycloakSession session, RealmModel realm, FedSetupConfigurationProfile profile,
                                       FedSetupPendingTrustAuthorization pending, String endpoint) {
        if (profile == null) throw new FedSetupValidationException("Application integration profile is unavailable");
        KeyWrapper key = session.keys().getActiveKey(realm, KeyUse.SIG, Algorithm.RS256);
        if (key == null) throw new FedSetupValidationException("Realm has no active RS256 signing key");
        JsonWebToken token = new JsonWebToken().issuer(profile.getCanonicalBaseUri()).audience(endpoint)
                .issuedNowWithTTL(FedSetupConstants.MAX_AUTHORIZATION_LIFESPAN_SECONDS);
        token.setOtherClaims("pending_id", pending.getPendingId());
        token.setOtherClaims("application_tenant_id", pending.getApplicationTenantId());
        token.setOtherClaims("idp_issuer", pending.getIdpIssuer());
        token.setOtherClaims("cimd_uri", pending.getCimdUri());
        token.setOtherClaims("event", "trust-proposal-updated");
        try {
            return new JWSBuilder().kid(key.getKid()).jsonContent(token).sign(KeyWrapperUtil.createSignatureSignerContext(key));
        } catch (Exception e) {
            throw new FedSetupValidationException("Unable to sign Trust Approval Notification", e);
        }
    }
}
