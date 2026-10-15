package org.keycloak.fedsetup;

import java.util.Set;

/**
 * Protocol constants, URNs, capability identifiers, and storage attribute prefixes for FedSetup Express Configuration.
 */
public final class FedSetupConstants {

    private FedSetupConstants() {
    }

    public static final String FEDSETUP_VERSION = "1.0";
    public static final String PROVIDER_ID = "fedsetup";

    // SHA-256 base64url of empty byte array ("")
    public static final String EMPTY_BODY_SHA256 = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";

    // Direct Installation Trust Profiles
    public static final String TRUST_PROFILE_BACK_CHANNEL = "urn:ietf:params:fedsetup:trust-profile:back-channel";
    public static final String TRUST_PROFILE_FRONT_CHANNEL = "urn:ietf:params:fedsetup:trust-profile:front-channel";

    // JWT media types (typ header)
    public static final String TYP_TRUST_PRE_AUTHORIZATION = "fedsetup-trust-pre-authorization+jwt";
    public static final String TYP_APPROVAL_NOTIFICATION = "fedsetup-approval-notification+jwt";

    // Capability Identifiers
    public static final String CAP_OIDC = "oidc";
    public static final String CAP_SAML = "saml";
    public static final String CAP_SCIM = "scim";
    public static final String CAP_ID_JAG = "id_jag";
    public static final String CAP_CONNECTION_QUERY = "connection_query";
    public static final String CAP_LAYERED_UPDATES = "layered_updates";

    public static final Set<String> SUPPORTED_CAPABILITIES = Set.of(
            CAP_OIDC,
            CAP_SAML,
            CAP_SCIM,
            CAP_ID_JAG,
            CAP_CONNECTION_QUERY,
            CAP_LAYERED_UPDATES
    );

    public static final Set<String> SSO_CAPABILITIES = Set.of(
            CAP_OIDC,
            CAP_SAML
    );

    // Scopes
    public static final String SCOPE_TRUST = "fedsetup:trust";
    public static final String SCOPE_CONFIG_PREFIX = "fedsetup:config:";

    // Federation Extension Profiles
    public static final String EXT_SCIM_OAUTH_CLIENT_CREDENTIALS = "urn:ietf:params:fedsetup:config-ext:scim-oauth-client-credentials";
    public static final String EXT_SCIM_OAUTH_CC = EXT_SCIM_OAUTH_CLIENT_CREDENTIALS;
    public static final String EXT_STATIC_SECRET_DELIVERY = "urn:ietf:params:fedsetup:config-ext:static-secret-delivery";

    public static final Set<String> SUPPORTED_EXTENSION_PROFILES = Set.of(
            EXT_SCIM_OAUTH_CLIENT_CREDENTIALS,
            EXT_STATIC_SECRET_DELIVERY
    );

    // Provider Delegation Profiles
    public static final String DELEGATE_SSF_STREAM = "urn:ietf:params:fedsetup:config-delegate:ssf-stream";

    public static final Set<String> SUPPORTED_DELEGATION_PROFILES = Set.of(
            DELEGATE_SSF_STREAM
    );

    // Value Delivery Bindings
    public static final String BINDING_CONFIGURATION_SECRET = "configuration_secret";
    public static final String BINDING_SCIM_AUTHORIZATION = "scim_authorization";

    public static final Set<String> SUPPORTED_VALUE_DELIVERY_BINDINGS = Set.of(
            BINDING_CONFIGURATION_SECRET,
            BINDING_SCIM_AUTHORIZATION
    );

    // SCIM Authentication Modes
    public static final String SCIM_AUTH_SAAS_ISSUED_BEARER = "SAAS_ISSUED_BEARER";
    public static final String SCIM_AUTH_OAUTH2_CLIENT_CREDENTIALS = "OAUTH2_CLIENT_CREDENTIALS";

    // SCIM Features
    public static final Set<String> SUPPORTED_SCIM_FEATURES = Set.of(
            "PUSH_NEW_USERS",
            "PUSH_PROFILE_UPDATES",
            "PUSH_USER_DEACTIVATION",
            "PUSH_PASSWORD_UPDATES",
            "PUSH_GROUPS",
            "IMPORT_NEW_USERS",
            "IMPORT_PROFILE_UPDATES",
            "GROUP_PUSH"
    );

    // ID-JAG Requester Types and Client Credential Mechanisms
    public static final String ID_JAG_REQUESTER_APP_INSTANCE = "app_instance";
    public static final String ID_JAG_REQUESTER_WORKLOAD_PRINCIPAL = "workload_principal";
    public static final Set<String> SUPPORTED_ID_JAG_REQUESTER_TYPES = Set.of(
            ID_JAG_REQUESTER_APP_INSTANCE,
            ID_JAG_REQUESTER_WORKLOAD_PRINCIPAL
    );

    public static final String ID_JAG_CRED_CIMD = "CIMD";
    public static final String ID_JAG_CRED_CLIENT_SECRET = "CLIENT_SECRET";
    public static final Set<String> SUPPORTED_ID_JAG_CREDENTIAL_MECHANISMS = Set.of(
            ID_JAG_CRED_CIMD,
            ID_JAG_CRED_CLIENT_SECRET
    );

    // Error Codes
    public static final String ERR_INVALID_REQUEST = "invalid_request";
    public static final String ERR_INVALID_CREDENTIAL = "invalid_credential";
    public static final String ERR_UNTRUSTED_ISSUER = "untrusted_issuer";
    public static final String ERR_INSUFFICIENT_SCOPE = "insufficient_scope";
    public static final String ERR_UNSUPPORTED_PROTOCOL = "unsupported_protocol";
    public static final String ERR_CONFLICT = "conflict";
    public static final String ERR_PRECONDITION_FAILED = "precondition_failed";
    public static final String ERR_NOT_FOUND = "not_found";
    public static final String ERR_SERVER_ERROR = "server_error";

    // Deferred Approval Error Codes
    public static final String ERR_AUTHORIZATION_PENDING = "authorization_pending";
    public static final String ERR_SLOW_DOWN = "slow_down";
    public static final String ERR_EXPIRED_TOKEN = "expired_token";
    public static final String ERR_ACCESS_DENIED = "access_denied";

    // Consent Redirect Error Codes
    public static final String ERR_UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type";
    public static final String ERR_INVALID_SCOPE = "invalid_scope";

    // HTTP Headers
    public static final String HEADER_IDEMPOTENCY_KEY = "Idempotency-Key";
    public static final String HEADER_IF_MATCH = "If-Match";
    public static final String HEADER_ETAG = "ETag";
    public static final String HEADER_WWW_AUTHENTICATE = "WWW-Authenticate";
    public static final String HEADER_CACHE_CONTROL = "Cache-Control";
    public static final String HEADER_PRAGMA = "Pragma";

    // Realm configuration attribute keys
    public static final String ATTR_ENABLED = "fedsetup.enabled";
    public static final String ATTR_TENANT_MODE = "fedsetup.application_tenant_mode";
    public static final String ATTR_SSO_CARDINALITY = "fedsetup.sso_connection_cardinality";
    public static final String ATTR_OAUTH_FLOW_ENABLED = "fedsetup.oauth_flow_enabled";
    public static final String ATTR_OIDC_CIMD_URI = "fedsetup.oidc.client_id_metadata_uri";
    public static final String ATTR_ALLOW_INSECURE_URLS = "fedsetup.allow_insecure_urls";
    public static final String ATTR_DEFERRED_APPROVAL_ENABLED = "fedsetup.deferred_approval_enabled";
    public static final String ATTR_DEFERRED_POLL_INTERVAL = "fedsetup.deferred_poll_interval";
    public static final String ATTR_DEFERRED_EXPIRES_IN = "fedsetup.deferred_expires_in";

    // Storage attribute prefixes on RealmModel
    public static final String PREFIX_PENDING_TRUST = "fedsetup.pending_trust.";
    public static final String PREFIX_TRUST = "fedsetup.trust.";
    public static final String PREFIX_CONNECTION = "fedsetup.connection.";
    public static final String PREFIX_DEFERRED = "fedsetup.deferred.";
    public static final String PREFIX_CONSUME_PREAUTH = "fedsetup.preauth_consumed.";
    public static final String PREFIX_REVOKED_PREAUTH = "fedsetup.preauth_revoked.";
    public static final String PREFIX_RESOURCE_BINDING = "fedsetup.resource_binding.";

    // SingleUseObjectProvider cache prefixes
    public static final String CACHE_JTI_PREFIX = "fedsetup:jti:";
    public static final String CACHE_IDEMPOTENCY_PREFIX = "fedsetup:idem:";
    public static final String CACHE_CONSENT_CODE_PREFIX = "fedsetup:code:";
    public static final String CACHE_DEFERRED_POLL_PREFIX = "fedsetup:poll:";
    public static final String CACHE_CIMD_PREFIX = "fedsetup:cimd:";
}
