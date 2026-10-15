package org.keycloak.fedsetup;

import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.AsymmetricSignatureSignerContext;
import org.keycloak.crypto.AsymmetricSignatureVerifierContext;
import org.keycloak.crypto.KeyStatus;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.fedsetup.model.ConnectionRecord;
import org.keycloak.fedsetup.model.DirectInstallationTrustRecord;
import org.keycloak.fedsetup.model.PendingTrustAuthorizationRecord;
import org.keycloak.fedsetup.representations.ConfigurationResponseRepresentation;
import org.keycloak.fedsetup.representations.ConnectionQueryResponseRepresentation;
import org.keycloak.fedsetup.representations.DeferredApprovalResponseRepresentation;
import org.keycloak.fedsetup.representations.DiscoveryDocumentRepresentation;
import org.keycloak.fedsetup.security.FedSetupFetchService;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.IdentityProviderStorageProvider;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.util.JsonSerialization;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

/**
 * Comprehensive unit and protocol conformance tests for FedSetup Express Configuration,
 * Deferred Direct Installation Trust, and Express Configuration Extensions (including ID-JAG).
 */
public class FedSetupTest {

    private static final String BASE_URI = "https://keycloak.example.com";
    private static final String REALM_NAME = "acme";
    private static final String REALM_BASE_URI = BASE_URI + "/realms/" + REALM_NAME;
    private static final String INSTALL_ENDPOINT = REALM_BASE_URI + "/fedsetup/install";
    private static final String CONFIGURE_ENDPOINT = REALM_BASE_URI + "/fedsetup/configure";
    private static final String IDP_ISSUER = "https://idp.example.com";
    private static final String IDP_CIMD_URI = "https://idp.example.com/fedsetup/client.json";
    private static final String IDP_JWKS_URI = "https://idp.example.com/fedsetup/jwks.json";
    private static final String IDP_CALLBACK_URI = "https://idp.example.com/fedsetup/callback";
    private static final String IDP_NOTIF_URI = "https://idp.example.com/fedsetup/notify";

    private KeyPair realmRsaKeyPair;
    private KeyWrapper realmKeyWrapper;
    private KeyPair idpRsaKeyPair;
    private String idpKid = "idp-key-1";

    private Map<String, String> realmAttributes;
    private Map<String, ClientModel> realmClients;
    private Map<String, IdentityProviderModel> realmIdps;
    private Map<String, Map<String, String>> singleUseStore;

    private RealmModel realm;
    private KeycloakSession session;
    private FedSetupService service;

    @Before
    public void setUp() throws Exception {
        CryptoIntegration.init(FedSetupTest.class.getClassLoader());
        FedSetupFetchService.clearMockDocuments();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        realmRsaKeyPair = kpg.generateKeyPair();
        idpRsaKeyPair = kpg.generateKeyPair();

        realmKeyWrapper = new KeyWrapper();
        realmKeyWrapper.setKid("realm-key-1");
        realmKeyWrapper.setAlgorithm("RS256");
        realmKeyWrapper.setType("RSA");
        realmKeyWrapper.setUse(KeyUse.SIG);
        realmKeyWrapper.setStatus(KeyStatus.ACTIVE);
        realmKeyWrapper.setPrivateKey(realmRsaKeyPair.getPrivate());
        realmKeyWrapper.setPublicKey(realmRsaKeyPair.getPublic());

        realmAttributes = new ConcurrentHashMap<>();
        realmAttributes.put(FedSetupConstants.ATTR_ALLOW_INSECURE_URLS, "true");
        realmClients = new ConcurrentHashMap<>();
        realmIdps = new ConcurrentHashMap<>();
        singleUseStore = new ConcurrentHashMap<>();

        realm = createMockRealm();
        session = createMockSession();
        service = new FedSetupService(session, realm);

        registerMockIdpDocuments();
    }

    @After
    public void tearDown() {
        FedSetupFetchService.clearMockDocuments();
    }

    private void registerMockIdpDocuments() throws Exception {
        JWK publicJwk = JWKBuilder.create().kid(idpKid).algorithm("RS256").rsa(idpRsaKeyPair.getPublic(), KeyUse.SIG);
        JSONWebKeySet jwks = new JSONWebKeySet();
        jwks.setKeys(new JWK[]{publicJwk});
        String jwksJson = JsonSerialization.writeValueAsString(jwks);
        FedSetupFetchService.registerMockDocument(IDP_JWKS_URI, jwksJson);

        Map<String, Object> cimd = new LinkedHashMap<>();
        cimd.put("client_id", IDP_CIMD_URI);
        cimd.put("client_name", "Example IdP Runtime");
        cimd.put("jwks_uri", IDP_JWKS_URI);
        cimd.put("redirect_uris", List.of(IDP_CALLBACK_URI));
        cimd.put("token_endpoint_auth_method", "private_key_jwt");
        FedSetupFetchService.registerMockDocument(IDP_CIMD_URI, JsonSerialization.writeValueAsString(cimd));

        Map<String, Object> oidcDiscovery = new LinkedHashMap<>();
        oidcDiscovery.put("issuer", IDP_ISSUER);
        oidcDiscovery.put("authorization_endpoint", IDP_ISSUER + "/oauth2/authorize");
        oidcDiscovery.put("token_endpoint", IDP_ISSUER + "/oauth2/token");
        oidcDiscovery.put("jwks_uri", IDP_JWKS_URI);
        oidcDiscovery.put("userinfo_endpoint", IDP_ISSUER + "/oauth2/userinfo");
        oidcDiscovery.put("fedsetup_installation_cimd_uris", List.of(IDP_CIMD_URI));
        FedSetupFetchService.registerMockDocument(
                IDP_ISSUER + "/.well-known/openid-configuration",
                JsonSerialization.writeValueAsString(oidcDiscovery));
    }

    // ---- 1. Discovery & Multi-Tenant / Single-Tenant Behavior ----

    @Test
    public void testDiscoveryDocument() {
        DiscoveryDocumentRepresentation doc = service.buildDiscoveryDocument(BASE_URI);
        assertEquals("1.0", doc.getFedsetupVersion());
        assertEquals(REALM_BASE_URI, doc.getApplicationBaseUri());
        assertEquals("multiple", doc.getApplicationTenantMode());
        assertEquals("multiple", doc.getSsoConnectionCardinality());
        assertEquals(INSTALL_ENDPOINT, doc.getInstallationEndpoint());
        assertEquals(REALM_BASE_URI + "/fedsetup/consent", doc.getInstallationConsentEndpoint());
        assertEquals(REALM_BASE_URI + "/fedsetup/trust-jwks.json", doc.getInstallationTrustJwksUri());
        assertTrue(doc.getInstallationTrustDeferredApprovalSupported());
        assertTrue(doc.getCapabilities().containsKey("oidc"));
        assertTrue(doc.getCapabilities().containsKey("saml"));
        assertTrue(doc.getCapabilities().containsKey("scim"));
        assertTrue(doc.getCapabilities().containsKey("id_jag"));
        assertTrue(doc.getCapabilities().containsKey("connection_query"));
        assertTrue(doc.getCapabilities().containsKey("layered_updates"));
        assertTrue(doc.getFederationExtensionProfilesSupported().contains(FedSetupConstants.EXT_STATIC_SECRET_DELIVERY));
        assertTrue(doc.getFederationExtensionProfilesSupported().contains(FedSetupConstants.EXT_SCIM_OAUTH_CLIENT_CREDENTIALS));
        assertTrue(doc.getProviderDelegationProfilesSupported().contains(FedSetupConstants.DELEGATE_SSF_STREAM));
    }

    // ---- 2. Out-of-Band Pending Trust Authorization & Atomic Back-Channel Installation ----

    @Test
    public void testBackChannelAtomicInstallWithPendingTrustAndAllCapabilities() throws Exception {
        // Pre-authorize ID-JAG resource binding in realm
        Map<String, Object> resourceBinding = new LinkedHashMap<>();
        resourceBinding.put("resource_issuer", "https://api.resource.example.com");
        resourceBinding.put("resources", List.of("https://api.resource.example.com/v1/items"));
        resourceBinding.put("scopes", List.of("items:read", "items:write"));
        service.setPreAuthorizedResourceBindings(List.of(resourceBinding));

        service.createPendingTrustAuthorization(
                IDP_ISSUER,
                IDP_CIMD_URI,
                List.of("oidc", "scim", "id_jag", "connection_query", "layered_updates"),
                List.of(FedSetupConstants.DELEGATE_SSF_STREAM),
                List.of(FedSetupConstants.EXT_STATIC_SECRET_DELIVERY, FedSetupConstants.EXT_SCIM_OAUTH_CLIENT_CREDENTIALS),
                null,
                3600);

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("application_tenant_id", REALM_NAME);
        payload.put("idp_issuer", IDP_ISSUER);

        Map<String, Object> oidc = new LinkedHashMap<>();
        oidc.put("issuer", IDP_ISSUER);
        oidc.put("client_id", "idp-client-123");
        oidc.put("client_secret", "oidc-secret-123456");
        oidc.put("token_endpoint_auth_method", "client_secret_basic");
        payload.put("oidc", oidc);

        Map<String, Object> scim = new LinkedHashMap<>();
        scim.put("features", List.of("PUSH_NEW_USERS", "PUSH_PROFILE_UPDATES"));
        payload.put("scim", scim);

        Map<String, Object> idJag = new LinkedHashMap<>();
        idJag.put("client_id", "idjag-client-123");
        idJag.put("requester_type", "app_instance");
        idJag.put("client_secret", "idjag-static-secret-1234567890");
        idJag.put("resource_connections", List.of(resourceBinding));
        payload.put("id_jag", idJag);

        Map<String, Object> extensions = new LinkedHashMap<>();
        extensions.put(FedSetupConstants.EXT_STATIC_SECRET_DELIVERY, Map.of(
                "secrets", Map.of("configuration_secret", "super-secret-oidc-client-secret-value-123456")
        ));
        extensions.put(FedSetupConstants.EXT_SCIM_OAUTH_CLIENT_CREDENTIALS, Map.of(
                "scim_client_jwks_uri", IDP_JWKS_URI
        ));
        payload.put("extensions", extensions);

        Map<String, Object> delegation = new LinkedHashMap<>();
        delegation.put(FedSetupConstants.DELEGATE_SSF_STREAM, Map.of(
                "transmitter_issuer", IDP_ISSUER,
                "access_token", "ssf-stream-mgmt-token-12345",
                "events_requested", List.of("https://schemas.openid.net/secevent/caep/event-type/session-revoked")
        ));
        payload.put("provider_delegation", delegation);

        byte[] bodyBytes = JsonSerialization.writeValueAsBytes(payload);
        String jwt = signIdpJwt("jti-install-1", INSTALL_ENDPOINT, bodyBytes, Map.of(
                "application_tenant_id", REALM_NAME,
                "idp_issuer", IDP_ISSUER,
                "authorized_capabilities", List.of("oidc", "scim", "id_jag", "connection_query", "layered_updates"),
                "provider_delegation_profiles", List.of(FedSetupConstants.DELEGATE_SSF_STREAM),
                "federation_extension_profiles", List.of(FedSetupConstants.EXT_STATIC_SECRET_DELIVERY, FedSetupConstants.EXT_SCIM_OAUTH_CLIENT_CREDENTIALS)
        ));

        Response response = service.handleInstall(
                "Bearer " + jwt,
                "idem-install-1",
                bodyBytes,
                BASE_URI);

        assertEquals(201, response.getStatus());
        String etag = response.getHeaderString("ETag");
        assertNotNull(etag);

        ConfigurationResponseRepresentation configResp = (ConfigurationResponseRepresentation) response.getEntity();
        assertNotNull(configResp.getConnectionId());
        assertEquals(REALM_NAME, configResp.getApplicationTenantId());
        assertNotNull(configResp.getOidc());
        assertFalse(configResp.getOidc().getRedirectUris().isEmpty());
        assertNotNull(configResp.getScim());
        assertEquals(REALM_BASE_URI + "/scim/v2", configResp.getScim().getProvisioningEndpoint());
        assertNull("scim.access_token MUST be omitted when OAuth2 SCIM CC profile is active", configResp.getScim().getAccessToken());
        assertNotNull(configResp.getIdJag());
        assertNotNull(configResp.getIdJag().getClientId());
        assertEquals(1, configResp.getIdJag().getResourceConnections().size());
        assertNotNull(configResp.getExtensions().get(FedSetupConstants.EXT_SCIM_OAUTH_CLIENT_CREDENTIALS));

        // Verify Idempotency-Key replay with new JWT returns cached 201 response
        String replayJwt = signIdpJwt("jti-install-replay", INSTALL_ENDPOINT, bodyBytes, Map.of(
                "application_tenant_id", REALM_NAME,
                "idp_issuer", IDP_ISSUER
        ));
        Response idempotentResponse = service.handleInstall(
                "Bearer " + replayJwt,
                "idem-install-1",
                bodyBytes,
                BASE_URI);
        assertEquals(201, idempotentResponse.getStatus());

        // Verify JTI replay is rejected with 401 invalid_credential
        FedSetupException replayEx = assertThrows(FedSetupException.class, () ->
                service.handleInstall(
                        "Bearer " + jwt,
                        "idem-install-2",
                        bodyBytes,
                        BASE_URI));
        assertEquals(401, replayEx.getStatus().getStatusCode());
        assertEquals(FedSetupConstants.ERR_INVALID_CREDENTIAL, replayEx.getError());
    }

    // ---- 3. Signed Trust Pre-Authorization JWT ({{preauth}}) ----

    @Test
    public void testSignedTrustPreAuthorizationJwtFlowAndSingleUseConsumption() throws Exception {
        PendingTrustAuthorizationRecord rec = service.createPendingTrustAuthorization(
                IDP_ISSUER,
                IDP_CIMD_URI,
                List.of("oidc", "connection_query", "layered_updates"),
                Collections.emptyList(),
                Collections.emptyList(),
                null,
                3600);
        String preAuthJwt = service.serializePendingTrustAuthorizationJwt(rec, BASE_URI);
        assertNotNull(preAuthJwt);

        // Verify Trust JWKS endpoint contains active realm key
        JSONWebKeySet trustJwks = service.getJwtService().getRealmTrustJwks();
        assertNotNull(trustJwks.getKeys());
        assertTrue(trustJwks.getKeys().length > 0);

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("application_tenant_id", REALM_NAME);
        payload.put("idp_issuer", IDP_ISSUER);
        payload.put("oidc", Map.of(
                "issuer", IDP_ISSUER,
                "client_id", "preauth-oidc-client",
                "token_endpoint_auth_method", "none"
        ));
        byte[] bodyBytes = JsonSerialization.writeValueAsBytes(payload);

        String installJwt = signIdpJwt("jti-preauth-1", INSTALL_ENDPOINT, bodyBytes, Map.of(
                "application_tenant_id", REALM_NAME,
                "idp_issuer", IDP_ISSUER,
                "trust_pre_authorization", preAuthJwt
        ));

        Response response = service.handleInstall(
                "Bearer " + installJwt,
                "idem-preauth-1",
                bodyBytes,
                BASE_URI);
        assertEquals(201, response.getStatus());

        // Attempting to reuse the consumed trust_pre_authorization JWT with a new request must fail with 403 untrusted_issuer
        String secondInstallJwt = signIdpJwt("jti-preauth-2", INSTALL_ENDPOINT, bodyBytes, Map.of(
                "application_tenant_id", REALM_NAME,
                "idp_issuer", IDP_ISSUER,
                "trust_pre_authorization", preAuthJwt
        ));
        FedSetupException consumedEx = assertThrows(FedSetupException.class, () ->
                service.handleInstall(
                        "Bearer " + secondInstallJwt,
                        "idem-preauth-2",
                        bodyBytes,
                        BASE_URI));
        assertEquals(403, consumedEx.getStatus().getStatusCode());
        assertEquals(FedSetupConstants.ERR_UNTRUSTED_ISSUER, consumedEx.getError());
    }

    // ---- 4. Deferred Approval Proposal, Polling, Approval Notification JWT & Downscoping ({{deferred}}) ----

    @Test
    public void testDeferredApprovalProposalPollingAndApprovalNotification() throws Exception {
        byte[] emptyBody = new byte[0];

        // 1. Submit initial bodyless Deferred Approval proposal
        Map<String, Object> proposalClaims = new LinkedHashMap<>();
        proposalClaims.put("application_tenant_id", REALM_NAME);
        proposalClaims.put("idp_issuer", IDP_ISSUER);
        proposalClaims.put("authorized_capabilities", List.of("oidc", "scim", "connection_query"));
        proposalClaims.put("approval_notification_endpoint", IDP_NOTIF_URI);

        String propJwt = signIdpJwt("jti-def-1", INSTALL_ENDPOINT, emptyBody, proposalClaims);
        Response propResp = service.handleInstall(
                "Bearer " + propJwt,
                "idem-def-1",
                emptyBody,
                BASE_URI);
        assertEquals(202, propResp.getStatus());
        DeferredApprovalResponseRepresentation pending = (DeferredApprovalResponseRepresentation) propResp.getEntity();
        assertNotNull(pending.getPendingId());
        assertNotNull(pending.getInterval());
        assertNotNull(pending.getExpiresIn());

        // 2. Poll while still pending -> 202 Accepted
        Map<String, Object> pollClaims = new LinkedHashMap<>(proposalClaims);
        pollClaims.remove("approval_notification_endpoint");
        pollClaims.put("pending_id", pending.getPendingId());
        String pollJwt1 = signIdpJwt("jti-def-2", INSTALL_ENDPOINT, emptyBody, pollClaims);
        Response pollResp1 = service.handleInstall(
                "Bearer " + pollJwt1,
                "idem-def-poll-1",
                emptyBody,
                BASE_URI);
        assertEquals(202, pollResp1.getStatus());

        // 3. Application Tenant Admin approves with downscoped capabilities (oidc + connection_query, omitting scim)
        DirectInstallationTrustRecord trust = service.approveDeferredProposal(
                pending.getPendingId(),
                List.of("oidc", "connection_query"),
                Collections.emptyList(),
                Collections.emptyList(),
                BASE_URI);
        assertNotNull(trust);
        assertEquals(List.of("oidc", "connection_query"), trust.getAuthorizedCapabilities());

        // Verify signed approval notification JWT was posted to approval_notification_endpoint
        String notifJwt = FedSetupFetchService.getLastNotificationPayload(IDP_NOTIF_URI);
        assertNotNull(notifJwt);

        // 4. Subsequent poll returns 200 OK with trust_established: true and downscoped capabilities
        String pollJwt2 = signIdpJwt("jti-def-3", INSTALL_ENDPOINT, emptyBody, pollClaims);
        Response pollResp2 = service.handleInstall(
                "Bearer " + pollJwt2,
                "idem-def-poll-2",
                emptyBody,
                BASE_URI);
        assertEquals(200, pollResp2.getStatus());
        DeferredApprovalResponseRepresentation approved = (DeferredApprovalResponseRepresentation) pollResp2.getEntity();
        assertEquals(Boolean.TRUE, approved.getTrustEstablished());
        assertEquals(List.of("oidc", "connection_query"), approved.getAuthorizedCapabilities());
    }

    // ---- 5. Front-Channel Consent UI & Single-Use Confirmation Code Exchange ({{trust-front}}) ----

    @Test
    public void testFrontChannelConsentUiAndConfirmationCodeExchange() throws Exception {
        MultivaluedMap<String, String> query = new MultivaluedHashMap<>();
        query.putSingle("response_type", "code");
        query.putSingle("client_id", IDP_CIMD_URI);
        query.putSingle("redirect_uri", IDP_CALLBACK_URI);
        query.putSingle("scope", FedSetupConstants.SCOPE_TRUST);
        query.putSingle("state", "xyz-state-123");
        query.putSingle("idp_issuer", IDP_ISSUER);
        query.putSingle("application_tenant_id", REALM_NAME);
        query.putSingle("authorized_capabilities", "oidc scim connection_query layered_updates");

        // 1. GET consent without decision renders interactive HTML with framing protections
        Response htmlResp = service.handleConsentRequest(query, null, null, BASE_URI);
        assertEquals(200, htmlResp.getStatus());
        assertEquals("DENY", htmlResp.getHeaderString("X-Frame-Options"));
        assertTrue(htmlResp.getHeaderString("Content-Security-Policy").contains("frame-ancestors 'none'"));
        assertTrue(((String) htmlResp.getEntity()).contains("Example IdP Runtime"));

        // 2. Approve consent with downscoped capabilities (oidc connection_query layered_updates)
        query.putSingle("decision", "approve");
        query.putSingle("approved_capabilities", "oidc connection_query layered_updates");
        Response redirectResp = service.handleConsentRequest(query, "approve", null, BASE_URI);
        assertEquals(302, redirectResp.getStatus());
        String location = redirectResp.getLocation().toString();
        assertTrue(location.startsWith(IDP_CALLBACK_URI + "?code="));
        assertTrue(location.contains("&state=xyz-state-123"));

        String code = location.substring(location.indexOf("code=") + 5, location.indexOf("&state="));

        // 3. Exchange single-use confirmation_code at POST /install
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("application_tenant_id", REALM_NAME);
        payload.put("idp_issuer", IDP_ISSUER);
        payload.put("oidc", Map.of(
                "issuer", IDP_ISSUER,
                "client_id", "front-channel-client",
                "token_endpoint_auth_method", "none"
        ));
        byte[] bodyBytes = JsonSerialization.writeValueAsBytes(payload);

        String installJwt = signIdpJwt("jti-fc-1", INSTALL_ENDPOINT, bodyBytes, Map.of(
                "application_tenant_id", REALM_NAME,
                "idp_issuer", IDP_ISSUER,
                "confirmation_code", code,
                "redirect_uri", IDP_CALLBACK_URI,
                "authorized_capabilities", List.of("oidc", "scim", "connection_query", "layered_updates")
        ));

        Response installResp = service.handleInstall(
                "Bearer " + installJwt,
                "idem-fc-1",
                bodyBytes,
                BASE_URI);
        assertEquals(201, installResp.getStatus());
        ConfigurationResponseRepresentation created = (ConfigurationResponseRepresentation) installResp.getEntity();
        String connectionId = created.getConnectionId();
        String initialEtag = installResp.getHeaderString("ETag");

        // 4. Query Connection via GET /connection/{connection_id} and GET /connections
        String connEndpoint = REALM_BASE_URI + "/fedsetup/connection/" + connectionId;
        String getJwt = signIdpJwt("jti-get-1", connEndpoint, new byte[0], Map.of(
                "application_tenant_id", REALM_NAME,
                "idp_issuer", IDP_ISSUER
        ));
        Response getResp = service.handleGetConnection(connectionId, "Bearer " + getJwt, BASE_URI);
        assertEquals(200, getResp.getStatus());
        assertEquals(initialEtag, getResp.getHeaderString("ETag"));
        ConfigurationResponseRepresentation getEntity = (ConfigurationResponseRepresentation) getResp.getEntity();
        assertEquals(connectionId, getEntity.getConnectionId());
        assertNotNull(getEntity.getOidc());

        // Also test Connection Query collection endpoint GET /connections
        String queryEndpoint = REALM_BASE_URI + "/fedsetup/connections";
        String queryJwt = signIdpJwt("jti-query-1", queryEndpoint, new byte[0], Map.of(
                "application_tenant_id", REALM_NAME,
                "idp_issuer", IDP_ISSUER
        ));
        Response queryResp = service.handleQueryConnections(
                "Bearer " + queryJwt,
                queryEndpoint,
                null,
                "active",
                null,
                null,
                BASE_URI);
        assertEquals(200, queryResp.getStatus());
        ConnectionQueryResponseRepresentation queryCollection = (ConnectionQueryResponseRepresentation) queryResp.getEntity();
        assertEquals(1, queryCollection.getConnections().size());
        assertEquals(connectionId, queryCollection.getConnections().get(0).getConnectionId());
        assertEquals("active", queryCollection.getConnections().get(0).getStatus());

        // 5. Layered Update via PATCH /connection/{connection_id} with If-Match
        Map<String, Object> patchPayload = new LinkedHashMap<>();
        patchPayload.put("oidc", Map.of(
                "issuer", IDP_ISSUER,
                "client_id", "updated-front-channel-client",
                "token_endpoint_auth_method", "none"
        ));
        byte[] patchBytes = JsonSerialization.writeValueAsBytes(patchPayload);

        // Stale ETag must fail with 412 precondition_failed
        String patchJwtStale = signIdpJwt("jti-patch-stale", connEndpoint, patchBytes, Map.of(
                "application_tenant_id", REALM_NAME,
                "idp_issuer", IDP_ISSUER
        ));
        FedSetupException precondEx = assertThrows(FedSetupException.class, () ->
                service.handlePatchConnection(
                        connectionId,
                        "Bearer " + patchJwtStale,
                        "\"stale-etag\"",
                        "idem-patch-stale",
                        patchBytes,
                        BASE_URI));
        assertEquals(412, precondEx.getStatus().getStatusCode());
        assertEquals(FedSetupConstants.ERR_PRECONDITION_FAILED, precondEx.getError());

        // Matching ETag succeeds and rotates ETag
        String patchJwtOk = signIdpJwt("jti-patch-ok", connEndpoint, patchBytes, Map.of(
                "application_tenant_id", REALM_NAME,
                "idp_issuer", IDP_ISSUER
        ));
        Response patchResp = service.handlePatchConnection(
                connectionId,
                "Bearer " + patchJwtOk,
                initialEtag,
                "idem-patch-ok",
                patchBytes,
                BASE_URI);
        assertEquals(200, patchResp.getStatus());
        String updatedEtag = patchResp.getHeaderString("ETag");
        assertNotNull(updatedEtag);
        assertFalse(initialEtag.equals(updatedEtag));

        // 6. Revoke Connection via DELETE /connection/{connection_id} and verify idempotent re-DELETE
        String delJwt1 = signIdpJwt("jti-del-1", connEndpoint, new byte[0], Map.of(
                "application_tenant_id", REALM_NAME,
                "idp_issuer", IDP_ISSUER
        ));
        Response delResp1 = service.handleDeleteConnection(connectionId, "Bearer " + delJwt1, BASE_URI);
        assertEquals(204, delResp1.getStatus());

        String delJwt2 = signIdpJwt("jti-del-2", connEndpoint, new byte[0], Map.of(
                "application_tenant_id", REALM_NAME,
                "idp_issuer", IDP_ISSUER
        ));
        Response delResp2 = service.handleDeleteConnection(connectionId, "Bearer " + delJwt2, BASE_URI);
        assertEquals(204, delResp2.getStatus());
    }

    // ---- 6. Trust Revocation Preserves Active Connections & Connection Adoption ----

    @Test
    public void testTrustRevocationPreservesActiveConnectionsAndConnectionAdoption() throws Exception {
        // Create pre-existing IdentityProviderModel to adopt
        IdentityProviderModel existingIdp = new IdentityProviderModel();
        existingIdp.setAlias("legacy-oidc");
        existingIdp.setProviderId("oidc");
        existingIdp.setEnabled(true);
        existingIdp.getConfig().put("issuer", IDP_ISSUER);
        existingIdp.getConfig().put("clientId", "legacy-client-id");
        realmIdps.put("legacy-oidc", existingIdp);

        // Establish trust via Pending Trust Authorization + Signed Pre-Auth JWT
        PendingTrustAuthorizationRecord pta = service.createPendingTrustAuthorization(
                IDP_ISSUER,
                IDP_CIMD_URI,
                List.of("oidc", "connection_query"),
                Collections.emptyList(),
                Collections.emptyList(),
                null,
                3600);
        String preAuthJwt = service.serializePendingTrustAuthorizationJwt(pta, BASE_URI);

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("application_tenant_id", REALM_NAME);
        payload.put("idp_issuer", IDP_ISSUER);
        payload.put("validate_only", true);
        payload.put("oidc", Map.of(
                "issuer", IDP_ISSUER,
                "client_id", "dry-run-client",
                "token_endpoint_auth_method", "none"
        ));
        byte[] dryRunBytes = JsonSerialization.writeValueAsBytes(payload);

        // Dry run with validate_only: true must NOT consume preAuthJwt or persist connection
        String dryRunJwt = signIdpJwt("jti-dry-1", INSTALL_ENDPOINT, dryRunBytes, Map.of(
                "application_tenant_id", REALM_NAME,
                "idp_issuer", IDP_ISSUER,
                "trust_pre_authorization", preAuthJwt
        ));
        Response dryRunResp = service.handleInstall(
                "Bearer " + dryRunJwt,
                "idem-dry-1",
                dryRunBytes,
                BASE_URI);
        assertEquals(200, dryRunResp.getStatus());
        assertEquals(0, service.getStore().listConnections().size());

        // Now establish trust via real install
        payload.remove("validate_only");
        byte[] realBytes = JsonSerialization.writeValueAsBytes(payload);
        String realJwt = signIdpJwt("jti-real-1", INSTALL_ENDPOINT, realBytes, Map.of(
                "application_tenant_id", REALM_NAME,
                "idp_issuer", IDP_ISSUER,
                "trust_pre_authorization", preAuthJwt
        ));
        Response realResp = service.handleInstall(
                "Bearer " + realJwt,
                "idem-real-1",
                realBytes,
                BASE_URI);
        assertEquals(201, realResp.getStatus());

        List<DirectInstallationTrustRecord> trusts = service.getStore().listTrustRecords();
        assertEquals(1, trusts.size());
        String trustId = trusts.get(0).getId();

        // Adopt pre-existing IdentityProviderModel under this trust
        ConnectionRecord adopted = service.adoptExistingIdentityProvider("legacy-oidc", trustId);
        assertNotNull(adopted.getConnectionId());
        assertEquals("active", adopted.getStatus());

        // Revoke Direct Installation Trust -> existing Connections stay active, but future requests fail with 403 untrusted_issuer
        service.revokeDirectInstallationTrust(trustId);
        assertEquals("active", service.getStore().getConnection(adopted.getConnectionId()).orElseThrow().getStatus());

        String postRevokeJwt = signIdpJwt("jti-get-post-revoke", REALM_BASE_URI + "/fedsetup/connection/" + adopted.getConnectionId(), new byte[0], Map.of(
                "application_tenant_id", REALM_NAME,
                "idp_issuer", IDP_ISSUER
        ));
        FedSetupException revokedEx = assertThrows(FedSetupException.class, () ->
                service.handleGetConnection(adopted.getConnectionId(), "Bearer " + postRevokeJwt, BASE_URI));
        assertEquals(403, revokedEx.getStatus().getStatusCode());
        assertEquals(FedSetupConstants.ERR_UNTRUSTED_ISSUER, revokedEx.getError());
    }

    // ---- Helper methods for signing & mock KeycloakSession ----

    private String signIdpJwt(String jti, String aud, byte[] bodyBytes, Map<String, Object> extraClaims) throws Exception {
        long now = Time.currentTime();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        String reqHash = Base64Url.encode(md.digest(bodyBytes != null ? bodyBytes : new byte[0]));

        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", "RS256");
        header.put("typ", "application/jwt");
        header.put("kid", idpKid);

        String htm = "POST";
        if (jti.contains("-get-") || jti.contains("-query-")) {
            htm = "GET";
        } else if (jti.contains("-patch-")) {
            htm = "PATCH";
        } else if (jti.contains("-del-")) {
            htm = "DELETE";
        }

        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", IDP_CIMD_URI);
        claims.put("sub", IDP_CIMD_URI);
        claims.put("aud", aud);
        claims.put("htm", htm);
        claims.put("htu", aud);
        claims.put("iat", now);
        claims.put("exp", now + 120);
        claims.put("jti", jti);
        claims.put("request_hash", reqHash);
        if (extraClaims != null) {
            claims.putAll(extraClaims);
        }

        String encodedHeader = Base64Url.encode(JsonSerialization.writeValueAsBytes(header));
        String encodedClaims = Base64Url.encode(JsonSerialization.writeValueAsBytes(claims));
        String signingInput = encodedHeader + "." + encodedClaims;

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(idpRsaKeyPair.getPrivate());
        sig.update(signingInput.getBytes(StandardCharsets.US_ASCII));
        String encodedSig = Base64Url.encode(sig.sign());

        return signingInput + "." + encodedSig;
    }

    private RealmModel createMockRealm() {
        return (RealmModel) Proxy.newProxyInstance(
                RealmModel.class.getClassLoader(),
                new Class<?>[]{RealmModel.class},
                (proxy, method, args) -> {
                    String name = method.getName();
                    switch (name) {
                        case "getId":
                        case "getName":
                            return REALM_NAME;
                        case "getDisplayName":
                            return "Acme Enterprise Realm";
                        case "getAttribute":
                            if (args.length == 1) {
                                return realmAttributes.get((String) args[0]);
                            } else if (args.length == 2 && args[1] instanceof Boolean defBool) {
                                String v = realmAttributes.get((String) args[0]);
                                return v != null ? Boolean.parseBoolean(v) : defBool;
                            }
                            return null;
                        case "setAttribute":
                            realmAttributes.put((String) args[0], String.valueOf(args[1]));
                            return null;
                        case "removeAttribute":
                            realmAttributes.remove((String) args[0]);
                            return null;
                        case "getAttributes":
                            return new HashMap<>(realmAttributes);
                        case "getClientByClientId":
                            return realmClients.get((String) args[0]);
                        case "addClient": {
                            String clientId = (String) args[0];
                            ClientModel c = createMockClient(clientId);
                            realmClients.put(clientId, c);
                            return c;
                        }
                        case "removeClient": {
                            String id = (String) args[0];
                            return realmClients.remove(id) != null;
                        }
                        case "getIdentityProviderByAlias":
                            return realmIdps.get((String) args[0]);
                        case "addIdentityProvider": {
                            IdentityProviderModel m = (IdentityProviderModel) args[0];
                            realmIdps.put(m.getAlias(), m);
                            return null;
                        }
                        case "updateIdentityProvider": {
                            IdentityProviderModel m = (IdentityProviderModel) args[0];
                            realmIdps.put(m.getAlias(), m);
                            return null;
                        }
                        case "removeIdentityProviderByAlias":
                            realmIdps.remove((String) args[0]);
                            return null;
                        case "getIdentityProvidersStream":
                            return realmIdps.values().stream();
                        default:
                            return defaultReturnValue(method.getReturnType());
                    }
                });
    }

    private ClientModel createMockClient(String initialClientId) {
        Map<String, String> attrs = new ConcurrentHashMap<>();
        String[] state = new String[]{initialClientId, null, "client-secret"};
        boolean[] flags = new boolean[]{true, false, true, false};
        java.util.Set<String> redirectUris = ConcurrentHashMap.newKeySet();
        java.util.Set<String> webOrigins = ConcurrentHashMap.newKeySet();

        return (ClientModel) Proxy.newProxyInstance(
                ClientModel.class.getClassLoader(),
                new Class<?>[]{ClientModel.class},
                (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "getId":
                        case "getClientId":
                            return state[0];
                        case "setClientId":
                            state[0] = (String) args[0];
                            return null;
                        case "getSecret":
                            return state[1];
                        case "setSecret":
                            state[1] = (String) args[0];
                            return null;
                        case "getClientAuthenticatorType":
                            return state[2];
                        case "setClientAuthenticatorType":
                            state[2] = (String) args[0];
                            return null;
                        case "isEnabled":
                            return flags[0];
                        case "setEnabled":
                            flags[0] = (Boolean) args[0];
                            return null;
                        case "isPublicClient":
                            return flags[1];
                        case "setPublicClient":
                            flags[1] = (Boolean) args[0];
                            return null;
                        case "isServiceAccountsEnabled":
                            return flags[2];
                        case "setServiceAccountsEnabled":
                            flags[2] = (Boolean) args[0];
                            return null;
                        case "isStandardFlowEnabled":
                            return flags[3];
                        case "setStandardFlowEnabled":
                            flags[3] = (Boolean) args[0];
                            return null;
                        case "getAttribute":
                            return attrs.get((String) args[0]);
                        case "setAttribute":
                            if (args[1] == null) {
                                attrs.remove((String) args[0]);
                            } else {
                                attrs.put((String) args[0], (String) args[1]);
                            }
                            return null;
                        case "removeAttribute":
                            attrs.remove((String) args[0]);
                            return null;
                        case "getAttributes":
                            return attrs;
                        case "getRedirectUris":
                            return redirectUris;
                        case "setRedirectUris":
                            redirectUris.clear();
                            if (args[0] != null) {
                                redirectUris.addAll((java.util.Collection<String>) args[0]);
                            }
                            return null;
                        case "getWebOrigins":
                            return webOrigins;
                        case "setWebOrigins":
                            webOrigins.clear();
                            if (args[0] != null) {
                                webOrigins.addAll((java.util.Collection<String>) args[0]);
                            }
                            return null;
                        default:
                            return defaultReturnValue(method.getReturnType());
                    }
                });
    }

    private KeycloakSession createMockSession() {
        KeyManager keyManager = (KeyManager) Proxy.newProxyInstance(
                KeyManager.class.getClassLoader(),
                new Class<?>[]{KeyManager.class},
                (proxy, method, args) -> {
                    if ("getActiveKey".equals(method.getName())) {
                        return realmKeyWrapper;
                    }
                    if ("getKey".equals(method.getName())) {
                        return realmKeyWrapper.getKid().equals(args[1]) ? realmKeyWrapper : null;
                    }
                    if ("getKeysStream".equals(method.getName())) {
                        return Stream.of(realmKeyWrapper);
                    }
                    return defaultReturnValue(method.getReturnType());
                });

        SingleUseObjectProvider singleUse = (SingleUseObjectProvider) Proxy.newProxyInstance(
                SingleUseObjectProvider.class.getClassLoader(),
                new Class<?>[]{SingleUseObjectProvider.class},
                (proxy, method, args) -> {
                    String m = method.getName();
                    if ("putIfAbsent".equals(m)) {
                        String key = (String) args[0];
                        return singleUseStore.putIfAbsent(key, Map.of("used", "true")) == null;
                    }
                    if ("put".equals(m)) {
                        String key = (String) args[0];
                        @SuppressWarnings("unchecked")
                        Map<String, String> notes = (Map<String, String>) args[2];
                        singleUseStore.put(key, new HashMap<>(notes));
                        return null;
                    }
                    if ("get".equals(m)) {
                        return singleUseStore.get((String) args[0]);
                    }
                    if ("remove".equals(m)) {
                        return singleUseStore.remove((String) args[0]);
                    }
                    return defaultReturnValue(method.getReturnType());
                });

        IdentityProviderStorageProvider idpProvider = (IdentityProviderStorageProvider) Proxy.newProxyInstance(
                IdentityProviderStorageProvider.class.getClassLoader(),
                new Class<?>[]{IdentityProviderStorageProvider.class},
                (proxy, method, args) -> {
                    String m = method.getName();
                    if ("getByAlias".equals(m)) {
                        return realmIdps.get((String) args[0]);
                    }
                    if ("create".equals(m)) {
                        IdentityProviderModel model = (IdentityProviderModel) args[0];
                        realmIdps.put(model.getAlias(), model);
                        return model;
                    }
                    if ("update".equals(m)) {
                        IdentityProviderModel model = (IdentityProviderModel) args[0];
                        realmIdps.put(model.getAlias(), model);
                        return null;
                    }
                    if ("remove".equals(m)) {
                        return realmIdps.remove((String) args[0]) != null;
                    }
                    if ("getAllStream".equals(m)) {
                        return realmIdps.values().stream();
                    }
                    return defaultReturnValue(method.getReturnType());
                });

        SignatureProvider rsaSigProvider = new SignatureProvider() {
            @Override
            public SignatureSignerContext signer() {
                return new AsymmetricSignatureSignerContext(realmKeyWrapper);
            }

            @Override
            public SignatureSignerContext signer(KeyWrapper key) {
                return new AsymmetricSignatureSignerContext(key);
            }

            @Override
            public SignatureVerifierContext verifier(String kid) {
                return new AsymmetricSignatureVerifierContext(realmKeyWrapper);
            }

            @Override
            public SignatureVerifierContext verifier(KeyWrapper key) {
                return new AsymmetricSignatureVerifierContext(key);
            }

            @Override
            public boolean isAsymmetricAlgorithm() {
                return true;
            }

            @Override
            public void close() {
            }
        };

        return (KeycloakSession) Proxy.newProxyInstance(
                KeycloakSession.class.getClassLoader(),
                new Class<?>[]{KeycloakSession.class},
                (proxy, method, args) -> {
                    String m = method.getName();
                    if ("keys".equals(m)) {
                        return keyManager;
                    }
                    if ("singleUseObjects".equals(m)) {
                        return singleUse;
                    }
                    if ("identityProviders".equals(m)) {
                        return idpProvider;
                    }
                    if ("getProvider".equals(m) && args.length == 2 && SignatureProvider.class.equals(args[0])) {
                        return rsaSigProvider;
                    }
                    return defaultReturnValue(method.getReturnType());
                });
    }

    private static Object defaultReturnValue(Class<?> returnType) {
        if (!returnType.isPrimitive()) {
            return null;
        }
        if (boolean.class.equals(returnType)) {
            return false;
        }
        if (int.class.equals(returnType)) {
            return 0;
        }
        if (long.class.equals(returnType)) {
            return 0L;
        }
        return null;
    }

    public static void main(String[] args) throws Exception {
        org.junit.runner.Result result = org.junit.runner.JUnitCore.runClasses(FedSetupTest.class);
        for (org.junit.runner.notification.Failure failure : result.getFailures()) {
            System.err.println("FAIL: " + failure.toString());
            failure.getException().printStackTrace(System.err);
        }
        System.out.println("Tests run: " + result.getRunCount() + ", Failures: " + result.getFailureCount());
        if (!result.wasSuccessful()) {
            System.exit(1);
        }
    }
}
