/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup;

import java.util.UUID;

import org.keycloak.fedsetup.representation.DirectInstallationTrust;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.AudienceProtocolMapper;
import org.keycloak.services.managers.ClientManager;
import org.keycloak.services.managers.RealmManager;
import org.keycloak.urls.UrlType;

/**
 * Creates the Application-AS client authorization that a successful Direct
 * Installation Trust requires.  The CIMD URI remains an identity and signing
 * key source; it becomes a client only after administrator-approved trust.
 */
public final class FedSetupConfigurationClientService {

    private FedSetupConfigurationClientService() {
    }

    public static void authorize(KeycloakSession session, RealmModel realm, DirectInstallationTrust trust) {
        String cimdUri = trust.getInstallationRuntimeCimdUri();
        if (cimdUri == null || cimdUri.isBlank()) {
            throw new FedSetupValidationException("A CIMD URI is required to create the Configuration API client authorization");
        }
        boolean anotherTrustUsesCimd = new RealmFedSetupStore(realm).getTrusts().stream()
                .anyMatch(candidate -> !candidate.getId().equals(trust.getId()) && cimdUri.equals(candidate.getInstallationRuntimeCimdUri()));
        if (anotherTrustUsesCimd) {
            throw new FedSetupValidationException("A CIMD runtime may authorize only one Application Tenant and IdP Tenant binding");
        }
        ClientModel client = realm.getClientByClientId(cimdUri);
        if (client == null) {
            client = realm.addClient(UUID.randomUUID().toString(), cimdUri);
        } else if (!Boolean.parseBoolean(client.getAttribute(FedSetupConstants.CONFIGURATION_CLIENT_ATTRIBUTE))) {
            throw new FedSetupValidationException("The CIMD URI is already assigned to a non-FedSetup client");
        }
        configure(session, realm, client);
    }

    static boolean isAuthorizedClient(ClientModel client, DirectInstallationTrust trust) {
        return client != null && client.isEnabled()
                && Boolean.parseBoolean(client.getAttribute(FedSetupConstants.CONFIGURATION_CLIENT_ATTRIBUTE))
                && trust.isActive() && trust.getInstallationRuntimeCimdUri() != null
                && trust.getInstallationRuntimeCimdUri().equals(client.getClientId());
    }

    public static void revoke(RealmModel realm, DirectInstallationTrust trust) {
        if (trust.getInstallationRuntimeCimdUri() == null || trust.getInstallationRuntimeCimdUri().isBlank()) return;
        ClientModel client = realm.getClientByClientId(trust.getInstallationRuntimeCimdUri());
        if (client != null && Boolean.parseBoolean(client.getAttribute(FedSetupConstants.CONFIGURATION_CLIENT_ATTRIBUTE))) {
            client.setEnabled(false);
        }
    }

    private static void configure(KeycloakSession session, RealmModel realm, ClientModel client) {
        client.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        client.setEnabled(true);
        client.setPublicClient(false);
        client.setBearerOnly(false);
        client.setStandardFlowEnabled(false);
        client.setImplicitFlowEnabled(false);
        client.setDirectAccessGrantsEnabled(false);
        client.setServiceAccountsEnabled(true);
        client.setClientAuthenticatorType(FedSetupConfigurationCimdClientAuthenticator.PROVIDER_ID);
        client.setAttribute(FedSetupConstants.CONFIGURATION_CLIENT_ATTRIBUTE, Boolean.TRUE.toString());
        client.getProtocolMappersStream().filter(mapper -> FedSetupConstants.CONFIGURATION_RESOURCE_AUDIENCE_MAPPER.equals(mapper.getName()))
                .toList().forEach(client::removeProtocolMapper);
        String resource = FedSetupUrls.resourceBase(session.getContext().getUri(UrlType.FRONTEND), realm);
        ProtocolMapperModel mapper = AudienceProtocolMapper.createClaimMapper(FedSetupConstants.CONFIGURATION_RESOURCE_AUDIENCE_MAPPER,
                null, resource, true, false, true);
        client.addProtocolMapper(mapper);
        new ClientManager(new RealmManager(session)).enableServiceAccount(client);
    }
}
