/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup;

import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.UriInfo;

import org.keycloak.common.Profile;
import org.keycloak.fedsetup.representation.FedSetupConfigurationProfile;
import org.keycloak.fedsetup.representation.FedSetupDiscoveryRepresentation;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.urls.UrlType;
import org.keycloak.wellknown.WellKnownProvider;

/** Builds the public discovery document without exposing trust or credentials. */
public class FedSetupWellKnownProvider implements WellKnownProvider {

    private final KeycloakSession session;

    public FedSetupWellKnownProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getConfig() {
        RealmModel realm = session.getContext().getRealm();
        if (isSupersededRealmScopedRequest(realm)) {
            throw new NotFoundException();
        }
        FedSetupConfigurationProfile profile = new RealmFedSetupStore(realm).getApplicationProfile();
        if (profile == null) {
            throw new NotFoundException();
        }
        UriInfo uriInfo = session.getContext().getUri(UrlType.FRONTEND);
        String endpoint = FedSetupUrls.resourceBase(uriInfo, realm);

        FedSetupDiscoveryRepresentation result = new FedSetupDiscoveryRepresentation();
        result.setFedsetupVersion("1.0");
        result.setApplicationBaseUri(profile.getCanonicalBaseUri());
        result.setConfigurationEndpoint(endpoint + "/connections");
        result.setConnectionEndpointTemplate(endpoint + "/connections/{connection_id}");
        java.util.List<String> protocols = new java.util.ArrayList<>();
        if (profile.getOidcClientId() != null) protocols.add("oidc");
        if (profile.getSamlClientId() != null) protocols.add("saml");
        result.setProtocolsSupported(protocols);
        result.setProvisioningSupported(profile.getCapabilities().contains("scim"));
        boolean idJagSupported = profile.getCapabilities().contains("id_jag")
                && Profile.isFeatureEnabled(Profile.Feature.IDENTITY_ASSERTION_JWT)
                && !profile.getIdJagResourceBindings().isEmpty();
        result.setIdJagSupported(idJagSupported);
        if (idJagSupported) {
            result.setIdJagRequesterTypesSupported(java.util.List.of("app_instance", "workload_principal"));
        }
        result.setSamlSpInitiatedSloSupported(profile.isSamlSpInitiatedSloSupported());
        result.setProviderDelegationProfilesSupported(java.util.List.of());
        result.setFederationExtensionProfilesSupported(new java.util.ArrayList<>(profile.getExtensionProfiles()));
        result.setLayeredUpdatesSupported(true);
        result.setSsoConnectionCardinality("single");
        result.setDocumentationUri(profile.getOidcDocumentationUri());
        result.setDirectInstallationTrustProfilesSupported(java.util.List.of(
                FedSetupConstants.BACK_CHANNEL_TRUST_PROFILE_URI, FedSetupConstants.FRONT_CHANNEL_TRUST_PROFILE_URI));
        result.setInstallationTrustEndpoint(FedSetupUrls.trust(uriInfo, realm));
        result.setInstallationAuthorizationEndpoint(FedSetupUrls.frontAuthorize(uriInfo, realm));
        result.setInstallationTokenEndpoint(FedSetupUrls.frontToken(uriInfo, realm));
        return result;
    }

    private boolean isSupersededRealmScopedRequest(RealmModel realm) {
        String requestPath = session.getContext().getUri().getRequestUri().getPath();
        return requestPath != null && requestPath.endsWith("/realms/" + realm.getName()
                + "/.well-known/" + FedSetupConstants.WELL_KNOWN_ALIAS);
    }

    @Override
    public void close() {
    }
}
