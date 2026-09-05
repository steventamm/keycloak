/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup;

import jakarta.ws.rs.core.UriInfo;

import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.RealmsResource;

/** Realm-scoped public FedSetup endpoint construction. */
public final class FedSetupUrls {

    private FedSetupUrls() {
    }

    public static String resourceBase(UriInfo uriInfo, RealmModel realm) {
        return RealmsResource.realmBaseUrl(uriInfo).path(FedSetupConstants.REALM_RESOURCE_ID).build(realm.getName()).toString();
    }

    public static String cimd(UriInfo uriInfo, RealmModel realm) {
        return resourceBase(uriInfo, realm) + "/cimd";
    }

    public static String trust(UriInfo uriInfo, RealmModel realm) {
        return resourceBase(uriInfo, realm) + "/trust";
    }

    public static String frontConsent(UriInfo uriInfo, RealmModel realm) {
        return resourceBase(uriInfo, realm) + "/front/authorize";
    }

    public static String frontConfirmation(UriInfo uriInfo, RealmModel realm) {
        return resourceBase(uriInfo, realm) + "/front/token";
    }

    public static String frontCallback(UriInfo uriInfo, RealmModel realm) {
        return resourceBase(uriInfo, realm) + "/front/callback";
    }

    /**
     * Internal callback used only while the Application realm authenticates
     * its administrator before displaying front-channel trust consent.  It is
     * deliberately distinct from {@link #frontCallback(UriInfo, RealmModel)},
     * which is the redirect URI advertised in the installation runtime CIMD.
     */
    public static String frontLoginCallback(UriInfo uriInfo, RealmModel realm) {
        return resourceBase(uriInfo, realm) + "/front/login-callback";
    }

    public static String frontApprove(UriInfo uriInfo, RealmModel realm) {
        return resourceBase(uriInfo, realm) + "/front/approve";
    }
}
