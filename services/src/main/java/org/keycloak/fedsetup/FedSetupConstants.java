/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup;

/** Constants shared by the realm-scoped FedSetup resources. */
public final class FedSetupConstants {

    public static final String FEATURE_PROFILE_URI = "https://www.keycloak.org/fedsetup/direct-installation-trust/v1";
    public static final String SCIM_CREDENTIAL_PROFILE_URI = "https://www.keycloak.org/fedsetup/scim-credential/v1";
    public static final String BACK_CHANNEL_TRUST_PROFILE_URI = "urn:ietf:params:fedsetup:trust-profile:back-channel";
    public static final String FRONT_CHANNEL_TRUST_PROFILE_URI = "urn:ietf:params:fedsetup:trust-profile:front-channel";
    public static final String WELL_KNOWN_ALIAS = "fedsetup";
    public static final String REALM_RESOURCE_ID = "fedsetup";
    public static final String ADMIN_RESOURCE_ID = "fedsetup";
    public static final int MAX_AUTHORIZATION_LIFESPAN_SECONDS = 300;
    /** Default and upper bounds for the human-operated back-channel flows. */
    public static final int DEFAULT_PRE_AUTHORIZATION_LIFESPAN_SECONDS = 30 * 24 * 60 * 60;
    public static final int MAX_PRE_AUTHORIZATION_LIFESPAN_SECONDS = 90 * 24 * 60 * 60;
    public static final int DEFAULT_PENDING_TRUST_LIFESPAN_SECONDS = 7 * 24 * 60 * 60;
    public static final int MAX_PENDING_TRUST_LIFESPAN_SECONDS = 14 * 24 * 60 * 60;
    public static final int PENDING_TRUST_POLL_INTERVAL_SECONDS = 60 * 60;
    public static final String TRUST_PRE_AUTHORIZATION_TYPE = "fedsetup-trust-pre-authorization+jwt";
    public static final String IDEMPOTENCY_HEADER = "Idempotency-Key";
    public static final String ETAG_HEADER = "ETag";
    public static final String IF_MATCH_HEADER = "If-Match";
    public static final String FRONT_CHANNEL_INTERNAL_CLIENT = "fedsetup-front-channel";
    /** Marker for the OAuth client authorization created by an installation trust. */
    public static final String CONFIGURATION_CLIENT_ATTRIBUTE = "fedsetup.configuration-client";
    public static final String CONFIGURATION_RESOURCE_AUDIENCE_MAPPER = "FedSetup configuration resource";
    /** The Keycloak IETF-profile runtime publishes and verifies RS256 keys only. */
    public static final String INSTALLATION_SIGNING_ALGORITHM = "RS256";

    private FedSetupConstants() {
    }
}
