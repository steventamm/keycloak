/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup;

import java.security.PublicKey;
import java.util.UUID;

import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.authenticators.client.JWTClientAuthenticator;
import org.keycloak.common.constants.ServiceAccountConstants;
import org.keycloak.fedsetup.representation.DirectInstallationTrust;
import org.keycloak.fedsetup.representation.FedSetupConnection;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.managers.ClientManager;
import org.keycloak.services.managers.RealmManager;
import org.keycloak.services.managers.UserSessionManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.urls.UrlType;

/** Creates and verifies the connection-scoped client used at the native SCIM endpoint. */
public final class FedSetupScimConnectionService {

    public static final String CONNECTION_ATTRIBUTE = "fedsetup.scim.connection-id";

    private FedSetupScimConnectionService() {
    }

    public static void create(KeycloakSession session, RealmModel realm, FedSetupConnection connection, DirectInstallationTrust trust) {
        if (!connection.getCapabilities().contains("scim")) return;
        if (connection.getScimServiceClientId() != null) {
            ClientModel existing = realm.getClientByClientId(connection.getScimServiceClientId());
            if (existing != null) removeLegacyRealmManagementRoles(session, realm, existing);
            return;
        }
        try {
            // A re-added SCIM capability must not revive a bearer issued for
            // the previous capability lifecycle.
            String clientId = "fedsetup-scim-" + connection.getId() + "-" + UUID.randomUUID().toString().substring(0, 12);
            ClientModel client = realm.addClient(UUID.randomUUID().toString(), clientId);
            client.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
            client.setEnabled(true);
            client.setPublicClient(false);
            client.setStandardFlowEnabled(false);
            client.setImplicitFlowEnabled(false);
            client.setDirectAccessGrantsEnabled(false);
            client.setServiceAccountsEnabled(true);
            boolean dynamicCimd = trust.getInstallationRuntimeCimdUri() != null && !trust.getInstallationRuntimeCimdUri().isBlank();
            client.setClientAuthenticatorType(dynamicCimd ? FedSetupScimCimdClientAuthenticator.PROVIDER_ID : JWTClientAuthenticator.PROVIDER_ID);
            client.setAttribute(CONNECTION_ATTRIBUTE, connection.getId());
            if (!dynamicCimd) {
                PublicKey key = JWKParser.create(JWKParser.create().parse(trust.getSigningKeyJwk()).getJwk()).toPublicKey();
                client.setAttribute(JWTClientAuthenticator.CERTIFICATE_ATTR, KeycloakModelUtils.getPemFromKey(key));
            }
            new ClientManager(new RealmManager(session)).enableServiceAccount(client);
            removeLegacyRealmManagementRoles(session, realm, client);
            connection.setScimServiceClientId(clientId);
            connection.setScimBaseUri(Urls.realmIssuer(session.getContext().getUri(UrlType.FRONTEND).getBaseUri(), realm.getName()) + "/scim/v2");
            connection.setScimTokenEndpoint(Urls.tokenEndpoint(session.getContext().getUri(UrlType.FRONTEND).getBaseUri(), realm.getName()).toString());
        } catch (Exception e) {
            throw new FedSetupValidationException("Unable to create a connection-scoped SCIM client", e);
        }
    }

    /** Returns the active connection bound to this service client, if any. */
    public static FedSetupConnection getAuthorizedConnection(RealmModel realm, ClientModel client) {
        if (client == null) return null;
        String connectionId = client.getAttribute(CONNECTION_ATTRIBUTE);
        if (connectionId == null || connectionId.isBlank()) return null;
        FedSetupConnection connection = new RealmFedSetupStore(realm).getConnection(connectionId);
        return connection != null && "ACTIVE".equals(connection.getStatus()) && connection.getCapabilities().contains("scim")
                && client.getClientId().equals(connection.getScimServiceClientId()) ? connection : null;
    }

    public static boolean hasConnectionBinding(ClientModel client) {
        String connectionId = client == null ? null : client.getAttribute(CONNECTION_ATTRIBUTE);
        return connectionId != null && !connectionId.isBlank();
    }

    public static void deactivate(RealmModel realm, FedSetupConnection connection) {
        if (connection.getScimServiceClientId() == null) return;
        ClientModel client = realm.getClientByClientId(connection.getScimServiceClientId());
        if (client != null) client.setEnabled(false);
    }

    /**
     * Issues the Section 8.1 SCIM bootstrap bearer token.  It is a normal
     * Keycloak access token for the connection-scoped service account, not a
     * reusable client secret.  Its transient session binding lets the normal
     * SCIM bearer-token authenticator enforce client disablement and realm
     * not-before revocation.
     */
    public static String issueBootstrapAccessToken(KeycloakSession session, RealmModel realm, FedSetupConnection connection) {
        if (connection.getScimServiceClientId() == null || connection.getScimServiceClientId().isBlank()) {
            throw new FedSetupValidationException("SCIM service client is unavailable");
        }
        ClientModel client = realm.getClientByClientId(connection.getScimServiceClientId());
        UserModel serviceAccount = client == null ? null : session.users().getServiceAccount(client);
        if (client == null || serviceAccount == null || !client.isEnabled()) {
            throw new FedSetupValidationException("SCIM service client is unavailable");
        }
        try {
            RootAuthenticationSessionModel root = new AuthenticationSessionManager(session).createAuthenticationSession(realm, false);
            AuthenticationSessionModel authentication = root.createAuthenticationSession(client);
            authentication.setAuthenticatedUser(serviceAccount);
            authentication.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
            authentication.setClientNote(OIDCLoginProtocol.ISSUER,
                    Urls.realmIssuer(session.getContext().getUri(UrlType.FRONTEND).getBaseUri(), realm.getName()));
            authentication.setClientNote(OIDCLoginProtocol.SCOPE_PARAM, "");
            UserSessionModel userSession = new UserSessionManager(session).createUserSession(root.getId(), realm, serviceAccount,
                    serviceAccount.getUsername(), "127.0.0.1", ServiceAccountConstants.CLIENT_AUTH, false, null, null,
                    UserSessionModel.SessionPersistenceState.TRANSIENT);
            AuthenticationManager.setClientScopesInSession(session, authentication);
            ClientSessionContext context = TokenManager.attachAuthenticationSession(session, userSession, authentication);
            context.setAttribute(Constants.GRANT_TYPE, OAuth2Constants.CLIENT_CREDENTIALS);
            AccessToken token = new TokenManager().createClientAccessToken(session, realm, client, serviceAccount, userSession, context, false);
            token.setSessionId(null);
            token.audience(connection.getScimBaseUri());
            return session.tokens().encode(token);
        } catch (FedSetupValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new FedSetupValidationException("Unable to issue SCIM bootstrap access token", e);
        }
    }

    /** Removes roles granted by the first preview implementation. */
    private static void removeLegacyRealmManagementRoles(KeycloakSession session, RealmModel realm, ClientModel client) {
        ClientModel management = realm.getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID);
        UserModel account = session.users().getServiceAccount(client);
        if (management == null || account == null) return;
        for (RoleModel role : account.getRoleMappingsStream().filter(role -> management.equals(role.getContainer())).toList()) {
            account.deleteRoleMapping(role);
        }
    }
}
