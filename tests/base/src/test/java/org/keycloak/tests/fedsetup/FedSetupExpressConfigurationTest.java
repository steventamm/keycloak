/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.tests.fedsetup;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.BearerAuthFilter;
import org.keycloak.common.Profile;
import org.keycloak.fedsetup.FedSetupConstants;
import org.keycloak.fedsetup.FedSetupScimConnectionService;
import org.keycloak.fedsetup.RealmFedSetupStore;
import org.keycloak.fedsetup.representation.DirectInstallationTrust;
import org.keycloak.fedsetup.representation.DirectInstallationTrustApprovalRequest;
import org.keycloak.fedsetup.representation.DirectInstallationTrustConsentResult;
import org.keycloak.fedsetup.representation.DirectInstallationTrustInvitationRequest;
import org.keycloak.fedsetup.representation.FedSetupConfigurationProfile;
import org.keycloak.fedsetup.representation.FedSetupConnection;
import org.keycloak.fedsetup.representation.FedSetupInstallation;
import org.keycloak.fedsetup.representation.FedSetupTrustPreAuthorization;
import org.keycloak.fedsetup.representation.ManualConnectionAdoption;
import org.keycloak.protocol.saml.SamlProtocol;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.testframework.annotations.InjectAdminClient;
import org.keycloak.testframework.annotations.InjectHttpClient;
import org.keycloak.testframework.annotations.InjectKeycloakUrls;
import org.keycloak.testframework.annotations.InjectRealm;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.https.CertificatesConfig;
import org.keycloak.testframework.https.CertificatesConfigBuilder;
import org.keycloak.testframework.https.InjectCertificates;
import org.keycloak.testframework.https.ManagedCertificates;
import org.keycloak.testframework.realm.ClientBuilder;
import org.keycloak.testframework.realm.ManagedRealm;
import org.keycloak.testframework.realm.RealmBuilder;
import org.keycloak.testframework.realm.RealmConfig;
import org.keycloak.testframework.realm.UserBuilder;
import org.keycloak.testframework.remote.runonserver.InjectRunOnServer;
import org.keycloak.testframework.remote.runonserver.RunOnServerClient;
import org.keycloak.testframework.server.KeycloakServerConfig;
import org.keycloak.testframework.server.KeycloakServerConfigBuilder;
import org.keycloak.testframework.server.KeycloakUrls;
import org.keycloak.util.JsonSerialization;

import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Contract-level integration coverage for the current CIMD-backed Direct
 * Installation Trust back-channel profile. The public IP in this test is
 * routed through a local CONNECT proxy so that the production SSRF checks are
 * exercised instead of bypassed for localhost.
 */
@KeycloakIntegrationTest(config = FedSetupExpressConfigurationTest.FedSetupServerConfig.class)
class FedSetupExpressConfigurationTest {

    private static final int PROXY_PORT = 8600;
    private static final String PUBLIC_HOST = "1.1.1.1";
    private static final String PUBLIC_BASE = "https://" + PUBLIC_HOST + ":8443";
    private static final String APPLICATION_TENANT = "application-tenant";
    private static final String APPLICATION_CLIENT = "application-oidc-client";
    private static final String APPLICATION_SAML_CLIENT = "application-saml-client";
    private static final String UNAUTHORIZED_SCIM_CLIENT = "ordinary-service-client";
    private static final String IDP_CLIENT = "idp-oidc-client";
    private static final String IDP_SAML_CLIENT = "idp-saml-client";
    private static final String APPLICATION_ADMIN = "application-admin";
    private static final String APPLICATION_ADMIN_PASSWORD = "application-admin-password";
    private static final Pattern FORM_ACTION = Pattern.compile("<form[^>]*\\baction=\\\"([^\\\"]+)\\\"", Pattern.CASE_INSENSITIVE);
    private static final Pattern HIDDEN_INPUT = Pattern.compile("<input[^>]*\\bname=\\\"([^\\\"]+)\\\"[^>]*\\bvalue=\\\"([^\\\"]*)\\\"", Pattern.CASE_INSENSITIVE);

    private static ConnectProxy proxy;

    @InjectRealm(ref = "application", config = ApplicationRealmConfig.class)
    ManagedRealm applicationRealm;

    @InjectRealm(ref = "idp", config = IdpRealmConfig.class)
    ManagedRealm idpRealm;

    @InjectAdminClient
    Keycloak adminClient;

    @InjectHttpClient(followRedirects = false)
    org.apache.http.client.HttpClient browser;

    @InjectKeycloakUrls
    KeycloakUrls keycloakUrls;

    @InjectCertificates(config = TlsConfig.class)
    ManagedCertificates certificates;

    @InjectRunOnServer(ref = "application", realmRef = "application")
    RunOnServerClient applicationRunOnServer;

    @BeforeAll
    static void startProxy() throws IOException {
        proxy = new ConnectProxy(PROXY_PORT, Map.of(PUBLIC_HOST, new InetSocketAddress("127.0.0.1", 8443)));
        proxy.start();
    }

    @AfterAll
    static void stopProxy() {
        if (proxy != null) {
            proxy.close();
        }
    }

    @Test
    void backChannelTrustMaterializesOidcConnectionAcrossIndependentRealms() throws Exception {
        String applicationTenant = APPLICATION_TENANT + "-back-channel";
        FedSetupConfigurationProfile profile = applicationProfile(applicationTenant);
        // Administrative callers send only the configured profile fields. In
        // particular, this keeps empty optional extension arrays out of the
        // initial profile document.
        AdminResponse putProfile = put(applicationRealm.getName(), "application-profile", Map.of(
                "applicationTenantId", profile.getApplicationTenantId(),
                "canonicalBaseUri", profile.getCanonicalBaseUri(),
                "oidcClientId", profile.getOidcClientId(),
                "capabilities", profile.getCapabilities()));
        assertEquals(200, putProfile.status(), putProfile.body());

        Map<?, ?> discovery = getPublic("/.well-known/fedsetup/realms/" + applicationRealm.getName(), Map.class);
        assertEquals(profile.getCanonicalBaseUri(), discovery.get("application_base_uri"));
        assertTrue(((List<?>) discovery.get("direct_installation_trust_profiles_supported"))
                .contains(FedSetupConstants.BACK_CHANNEL_TRUST_PROFILE_URI));
        assertPublicStatus("/realms/" + applicationRealm.getName() + "/.well-known/fedsetup", 404);

        FedSetupTrustPreAuthorization preAuthorization = new FedSetupTrustPreAuthorization();
        preAuthorization.setApplicationTenantId(applicationTenant);
        preAuthorization.setIdpIssuer(realmIssuer(idpRealm));
        preAuthorization.setCimdUri(cimdUri(idpRealm));
        preAuthorization.setCapabilities(Set.of("oidc"));
        preAuthorization.setFederationExtensionProfiles(Set.of(FedSetupConstants.FEATURE_PROFILE_URI));
        assertEquals(201, post(applicationRealm.getName(), "trust-pre-authorizations", preAuthorization).status());

        DirectInstallationTrust outboundTrust = outboundBackChannelTrust(applicationTenant);
        AdminResponse createdTrust = post(idpRealm.getName(), "trusts", outboundTrust);
        assertEquals(201, createdTrust.status());
        DirectInstallationTrust storedOutboundTrust = read(createdTrust.body(), DirectInstallationTrust.class);

        AdminResponse establish = post(idpRealm.getName(), "trusts/" + storedOutboundTrust.getId() + "/establish", null);
        assertEquals(200, establish.status());
        assertEquals("ESTABLISHED", read(establish.body(), Map.class).get("status"));

        List<DirectInstallationTrust> inboundTrusts = getList(applicationRealm.getName(), "trusts", DirectInstallationTrust.class);
        DirectInstallationTrust inboundTrust = trustForTenant(inboundTrusts, applicationTenant);
        assertEquals(applicationTenant, inboundTrust.getApplicationTenantId());
        assertEquals(realmIssuer(idpRealm), inboundTrust.getIdpIssuer());

        FedSetupInstallation installation = new FedSetupInstallation();
        installation.setApplicationTenantId(applicationTenant);
        installation.setTrustId(storedOutboundTrust.getId());
        installation.setCanonicalApplicationBaseUri(realmIssuer(applicationRealm));
        installation.setConfigurationEndpoint(resourceBase(applicationRealm) + "/connections");
        installation.setClientId(IDP_CLIENT);
        installation.setProtocol("oidc");
        installation.setCapabilities(Set.of("oidc"));
        installation.setExtensionProfiles(Set.of(FedSetupConstants.FEATURE_PROFILE_URI));

        AdminResponse createdInstallation = post(idpRealm.getName(), "installations", installation);
        assertEquals(201, createdInstallation.status());
        FedSetupInstallation pending = read(createdInstallation.body(), FedSetupInstallation.class);
        assertEquals("PENDING_REVIEW", pending.getStatus());

        AdminResponse dispatched = post(idpRealm.getName(), "installations/" + pending.getId() + "/dispatch", null);
        assertEquals(200, dispatched.status());
        FedSetupInstallation active = read(dispatched.body(), FedSetupInstallation.class);
        assertEquals("ACTIVE", active.getStatus());
        assertNotNull(active.getRemoteConnectionId());
        assertNotNull(active.getRemoteEtag());

        List<FedSetupConnection> connections = getList(applicationRealm.getName(), "connections", FedSetupConnection.class);
        FedSetupConnection connection = connectionForTenant(connections, applicationTenant);
        assertEquals(active.getRemoteConnectionId(), connection.getId());
        assertEquals("oidc", connection.getProtocol());
        assertEquals("ACTIVE", connection.getStatus());
        assertEquals(realmIssuer(idpRealm), connection.getIdpIssuer());
        assertFalse(connection.getSso().containsKey("client_secret"));

        IdentityProviderRepresentation broker = applicationRealm.admin().identityProviders().get(connection.getBrokerAlias()).toRepresentation();
        assertEquals(realmIssuer(idpRealm), broker.getConfig().get("issuer"));
        String brokerAlias = connection.getBrokerAlias();
        assertEquals("fedsetup-oidc", broker.getProviderId());
        applicationRunOnServer.run(session -> assertEquals("fedsetup-oidc",
                session.getContext().getRealm().getIdentityProviderByAlias(brokerAlias).getProviderId()));

        // A subsequent dispatch is a PATCH using the recorded remote ETag,
        // proving that the connection is not recreated on administrative retry.
        AdminResponse redispatched = post(idpRealm.getName(), "installations/" + active.getId() + "/dispatch", null);
        assertEquals(200, redispatched.status());
        FedSetupInstallation updated = read(redispatched.body(), FedSetupInstallation.class);
        assertEquals(active.getRemoteConnectionId(), updated.getRemoteConnectionId());
        assertTrue(updated.getDispatchAttempts() > active.getDispatchAttempts());
    }

    @Test
    void frontChannelTrustRequiresApplicationAdministratorConsentAndCreatesPairedTrusts() throws Exception {
        String applicationTenant = APPLICATION_TENANT + "-front-channel";
        FedSetupConfigurationProfile profile = applicationProfile(applicationTenant);
        AdminResponse putProfile = put(applicationRealm.getName(), "application-profile", Map.of(
                "applicationTenantId", profile.getApplicationTenantId(),
                "canonicalBaseUri", profile.getCanonicalBaseUri(),
                "oidcClientId", profile.getOidcClientId(),
                "capabilities", profile.getCapabilities()));
        assertEquals(200, putProfile.status(), putProfile.body());

        DirectInstallationTrust trust = outboundFrontChannelTrust(applicationTenant);
        AdminResponse createdTrust = post(idpRealm.getName(), "trusts", trust);
        assertEquals(201, createdTrust.status(), createdTrust.body());
        DirectInstallationTrust outboundTrust = read(createdTrust.body(), DirectInstallationTrust.class);

        AdminResponse started = post(idpRealm.getName(), "trusts/" + outboundTrust.getId() + "/front-channel", null);
        assertEquals(200, started.status(), started.body());
        String authorizationUri = (String) read(started.body(), Map.class).get("authorization_uri");
        assertNotNull(authorizationUri);

        HttpClientContext browserContext = HttpClientContext.create();
        browserContext.setCookieStore(new BasicCookieStore());

        BrowserResponse authorize = browserGet(authorizationUri, browserContext);
        assertRedirect(authorize, "Application authorization endpoint");
        BrowserResponse login = browserGet(authorize.location(), browserContext);
        assertEquals(200, login.status(), login.body());

        BrowserResponse loginComplete = browserPost(formAction(login.body()), browserContext, List.of(
                new BasicNameValuePair("username", APPLICATION_ADMIN),
                new BasicNameValuePair("password", APPLICATION_ADMIN_PASSWORD)));
        assertRedirect(loginComplete, "Application administrator login");

        BrowserResponse consent = browserGet(loginComplete.location(), browserContext);
        assertEquals(200, consent.status(), consent.body());
        assertTrue(consent.body().contains("Approve Direct Installation Trust"), consent.body());
        BrowserResponse approved = browserPost(resourceBase(applicationRealm) + "/front/approve", browserContext, List.of(
                new BasicNameValuePair("transaction", hiddenValue(consent.body(), "transaction")),
                new BasicNameValuePair("consent_nonce", hiddenValue(consent.body(), "consent_nonce"))));
        assertRedirect(approved, "Application trust approval");

        BrowserResponse completed = browserGet(approved.location(), browserContext);
        assertEquals(200, completed.status(), completed.body());
        assertTrue(completed.body().contains("FedSetup complete"), completed.body());

        List<DirectInstallationTrust> applicationTrusts = getList(applicationRealm.getName(), "trusts", DirectInstallationTrust.class);
        DirectInstallationTrust applicationTrust = trustForTenant(applicationTrusts, applicationTenant);
        assertEquals(FedSetupConstants.FRONT_CHANNEL_TRUST_PROFILE_URI, applicationTrust.getTrustProfileUri());
        assertEquals(realmIssuer(idpRealm), applicationTrust.getIdpIssuer());

        List<DirectInstallationTrust> idpTrusts = getList(idpRealm.getName(), "trusts", DirectInstallationTrust.class);
        DirectInstallationTrust idpTrust = trustForTenant(idpTrusts, applicationTenant);
        assertEquals(FedSetupConstants.FRONT_CHANNEL_TRUST_PROFILE_URI, idpTrust.getTrustProfileUri());
        assertEquals(applicationTenant, idpTrust.getApplicationTenantId());
    }

    @Test
    void administratorHandoffConsentCreatesOneTimePairedTrustsWithoutCrossRealmAuthentication() throws Exception {
        String applicationTenant = APPLICATION_TENANT + "-handoff";
        FedSetupConfigurationProfile profile = applicationProfile(applicationTenant);
        AdminResponse putProfile = put(applicationRealm.getName(), "application-profile", Map.of(
                "applicationTenantId", profile.getApplicationTenantId(),
                "canonicalBaseUri", profile.getCanonicalBaseUri(),
                "oidcClientId", profile.getOidcClientId(),
                "capabilities", profile.getCapabilities()));
        assertEquals(200, putProfile.status(), putProfile.body());

        Map<?, ?> keySet = getPublic("/realms/" + idpRealm.getName() + "/protocol/openid-connect/certs", Map.class);
        String signingJwk = activeRs256Jwk(keySet);

        DirectInstallationTrustInvitationRequest invitationRequest = new DirectInstallationTrustInvitationRequest();
        invitationRequest.setIdpIssuer(realmIssuer(idpRealm));
        invitationRequest.setSigningKeyJwk(signingJwk);
        invitationRequest.setRuntimeJwksUri(realmIssuer(idpRealm) + "/protocol/openid-connect/certs");
        invitationRequest.setCapabilities(Set.of("oidc"));
        invitationRequest.setExtensionProfiles(Set.of(FedSetupConstants.FEATURE_PROFILE_URI));
        AdminResponse invitationResponse = post(applicationRealm.getName(), "trust-invitations", invitationRequest);
        assertEquals(201, invitationResponse.status(), invitationResponse.body());
        DirectInstallationTrustConsentResult invitation = read(invitationResponse.body(), DirectInstallationTrustConsentResult.class);
        assertNotNull(invitation.getInvitation());
        assertEquals(null, invitation.getApproval());

        DirectInstallationTrustApprovalRequest approvalRequest = new DirectInstallationTrustApprovalRequest();
        approvalRequest.setInvitation(invitation.getInvitation());
        AdminResponse approvalResponse = post(idpRealm.getName(), "trust-invitations/approve", approvalRequest);
        assertEquals(201, approvalResponse.status(), approvalResponse.body());
        DirectInstallationTrustConsentResult approval = read(approvalResponse.body(), DirectInstallationTrustConsentResult.class);
        assertNotNull(approval.getApproval());
        assertNotNull(approval.getTrust());
        assertEquals(applicationTenant, approval.getTrust().getApplicationTenantId());

        approvalRequest.setApproval(approval.getApproval());
        AdminResponse consumed = post(applicationRealm.getName(), "trust-invitations/consume", approvalRequest);
        assertEquals(201, consumed.status(), consumed.body());
        DirectInstallationTrust applicationTrust = read(consumed.body(), DirectInstallationTrust.class);
        assertEquals(applicationTenant, applicationTrust.getApplicationTenantId());
        assertEquals(realmIssuer(idpRealm), applicationTrust.getIdpIssuer());

        // The artifacts move between two independent tenant administrators;
        // neither is a reusable cross-realm login or consent session.
        AdminResponse replay = post(applicationRealm.getName(), "trust-invitations/consume", approvalRequest);
        assertEquals(400, replay.status(), replay.body());
        assertNotNull(trustForTenant(getList(applicationRealm.getName(), "trusts", DirectInstallationTrust.class), applicationTenant));
        assertNotNull(trustForTenant(getList(idpRealm.getName(), "trusts", DirectInstallationTrust.class), applicationTenant));
    }

    @Test
    void nativeScimUsesTheConnectionScopedCredentialAndNegotiatedFeatureSubset() throws Exception {
        String applicationTenant = APPLICATION_TENANT + "-scim";
        FedSetupConfigurationProfile profile = applicationProfile(applicationTenant);
        profile.setCapabilities(Set.of("oidc", "scim"));
        AdminResponse putProfile = put(applicationRealm.getName(), "application-profile", Map.of(
                "applicationTenantId", profile.getApplicationTenantId(),
                "canonicalBaseUri", profile.getCanonicalBaseUri(),
                "oidcClientId", profile.getOidcClientId(),
                "capabilities", profile.getCapabilities()));
        assertEquals(200, putProfile.status(), putProfile.body());

        FedSetupTrustPreAuthorization preAuthorization = new FedSetupTrustPreAuthorization();
        preAuthorization.setApplicationTenantId(applicationTenant);
        preAuthorization.setIdpIssuer(realmIssuer(idpRealm));
        preAuthorization.setCimdUri(cimdUri(idpRealm));
        preAuthorization.setCapabilities(Set.of("oidc", "scim"));
        preAuthorization.setFederationExtensionProfiles(Set.of(FedSetupConstants.FEATURE_PROFILE_URI,
                FedSetupConstants.SCIM_CREDENTIAL_PROFILE_URI));
        assertEquals(201, post(applicationRealm.getName(), "trust-pre-authorizations", preAuthorization).status());

        DirectInstallationTrust trust = outboundBackChannelTrust(applicationTenant);
        trust.setCapabilities(Set.of("oidc", "scim"));
        trust.setExtensionProfiles(Set.of(FedSetupConstants.FEATURE_PROFILE_URI, FedSetupConstants.SCIM_CREDENTIAL_PROFILE_URI));
        AdminResponse createdTrust = post(idpRealm.getName(), "trusts", trust);
        assertEquals(201, createdTrust.status(), createdTrust.body());
        DirectInstallationTrust outboundTrust = read(createdTrust.body(), DirectInstallationTrust.class);
        assertEquals(200, post(idpRealm.getName(), "trusts/" + outboundTrust.getId() + "/establish", null).status());

        FedSetupInstallation installation = new FedSetupInstallation();
        installation.setApplicationTenantId(applicationTenant);
        installation.setTrustId(outboundTrust.getId());
        installation.setCanonicalApplicationBaseUri(realmIssuer(applicationRealm));
        installation.setConfigurationEndpoint(resourceBase(applicationRealm) + "/connections");
        installation.setClientId(IDP_CLIENT);
        installation.setProtocol("oidc");
        installation.setCapabilities(Set.of("oidc", "scim"));
        installation.setScimFeatures(Set.of("PUSH_NEW_USERS"));
        installation.setExtensionProfiles(Set.of(FedSetupConstants.FEATURE_PROFILE_URI, FedSetupConstants.SCIM_CREDENTIAL_PROFILE_URI));
        FedSetupInstallation pending = read(post(idpRealm.getName(), "installations", installation).body(), FedSetupInstallation.class);
        AdminResponse dispatched = post(idpRealm.getName(), "installations/" + pending.getId() + "/dispatch", null);
        assertEquals(200, dispatched.status(), dispatched.body());
        assertEquals("ACTIVE", read(dispatched.body(), FedSetupInstallation.class).getStatus());

        FedSetupConnection connection = connectionForTenant(getList(applicationRealm.getName(), "connections", FedSetupConnection.class), applicationTenant);
        assertNotNull(connection.getScimServiceClientId());
        assertNotNull(connection.getScimBaseUri());
        assertEquals(Set.of("PUSH_NEW_USERS"), connection.getScimFeatures());
        String connectionId = connection.getId();
        String bootstrapAccessToken = applicationRunOnServer.fetchString(session -> {
            var realm = session.getContext().getRealm();
            var storedConnection = new RealmFedSetupStore(realm).requireConnection(connectionId);
            return FedSetupScimConnectionService.issueBootstrapAccessToken(session, realm, storedConnection);
        });

        HttpClientContext context = HttpClientContext.create();
        HttpPost createUser = new HttpPost(keycloakUrls.getBase() + "/realms/" + applicationRealm.getName() + "/scim/v2/Users");
        createUser.setHeader("Authorization", "Bearer " + bootstrapAccessToken);
        createUser.setHeader("Content-Type", "application/scim+json");
        createUser.setEntity(new StringEntity("{\"userName\":\"fedsetup-scim-user\",\"name\":{\"givenName\":\"FedSetup\",\"familyName\":\"User\"},\"emails\":[{\"value\":\"fedsetup-scim-user@example.test\",\"primary\":true}],\"active\":true}", ContentType.APPLICATION_JSON));
        BrowserResponse createdUser = browser(createUser, context);
        assertEquals(201, createdUser.status(), createdUser.body());

        HttpPost createGroup = new HttpPost(keycloakUrls.getBase() + "/realms/" + applicationRealm.getName() + "/scim/v2/Groups");
        createGroup.setHeader("Authorization", "Bearer " + bootstrapAccessToken);
        createGroup.setHeader("Content-Type", "application/scim+json");
        createGroup.setEntity(new StringEntity("{\"displayName\":\"must-not-be-created\"}", ContentType.APPLICATION_JSON));
        assertEquals(403, browser(createGroup, context).status());

        // An ordinary service account has neither a Connection binding nor
        // the native SCIM audience. It cannot borrow the special SCIM path.
        BrowserResponse ordinaryToken = browserPost("/realms/" + applicationRealm.getName() + "/protocol/openid-connect/token", context, List.of(
                new BasicNameValuePair("grant_type", "client_credentials"),
                new BasicNameValuePair("client_id", UNAUTHORIZED_SCIM_CLIENT),
                new BasicNameValuePair("client_secret", "ordinary-service-secret")));
        assertEquals(200, ordinaryToken.status(), ordinaryToken.body());
        String ordinaryAccessToken = (String) read(ordinaryToken.body(), Map.class).get("access_token");
        HttpGet ordinaryScimRequest = new HttpGet(keycloakUrls.getBase() + "/realms/" + applicationRealm.getName() + "/scim/v2/Users");
        ordinaryScimRequest.setHeader("Authorization", "Bearer " + ordinaryAccessToken);
        assertEquals(401, browser(ordinaryScimRequest, context).status());
    }

    @Test
    void backChannelTrustMaterializesSamlAndRefreshesIssuerBoundMetadata() throws Exception {
        String applicationTenant = APPLICATION_TENANT + "-saml";
        FedSetupConfigurationProfile profile = samlApplicationProfile(applicationTenant);
        AdminResponse putProfile = put(applicationRealm.getName(), "application-profile", Map.of(
                "applicationTenantId", profile.getApplicationTenantId(),
                "canonicalBaseUri", profile.getCanonicalBaseUri(),
                "samlClientId", profile.getSamlClientId(),
                "capabilities", profile.getCapabilities()));
        assertEquals(200, putProfile.status(), putProfile.body());

        FedSetupTrustPreAuthorization preAuthorization = new FedSetupTrustPreAuthorization();
        preAuthorization.setApplicationTenantId(applicationTenant);
        preAuthorization.setIdpIssuer(realmIssuer(idpRealm));
        preAuthorization.setCimdUri(cimdUri(idpRealm));
        preAuthorization.setCapabilities(Set.of("saml"));
        preAuthorization.setFederationExtensionProfiles(Set.of(FedSetupConstants.FEATURE_PROFILE_URI));
        assertEquals(201, post(applicationRealm.getName(), "trust-pre-authorizations", preAuthorization).status());

        DirectInstallationTrust trust = outboundBackChannelTrust(applicationTenant);
        trust.setCapabilities(Set.of("saml"));
        AdminResponse createdTrust = post(idpRealm.getName(), "trusts", trust);
        assertEquals(201, createdTrust.status(), createdTrust.body());
        DirectInstallationTrust outboundTrust = read(createdTrust.body(), DirectInstallationTrust.class);
        assertEquals(200, post(idpRealm.getName(), "trusts/" + outboundTrust.getId() + "/establish", null).status());

        FedSetupInstallation installation = new FedSetupInstallation();
        installation.setApplicationTenantId(applicationTenant);
        installation.setTrustId(outboundTrust.getId());
        installation.setCanonicalApplicationBaseUri(realmIssuer(applicationRealm));
        installation.setConfigurationEndpoint(resourceBase(applicationRealm) + "/connections");
        installation.setClientId(IDP_SAML_CLIENT);
        installation.setProtocol("saml");
        installation.setCapabilities(Set.of("saml"));
        installation.setExtensionProfiles(Set.of(FedSetupConstants.FEATURE_PROFILE_URI));
        installation.setSamlAttributeMapping(Map.of("email", "mail", "given_name", "givenName"));
        FedSetupInstallation pending = read(post(idpRealm.getName(), "installations", installation).body(), FedSetupInstallation.class);
        AdminResponse dispatched = post(idpRealm.getName(), "installations/" + pending.getId() + "/dispatch", null);
        assertEquals(200, dispatched.status(), dispatched.body());
        assertEquals("ACTIVE", read(dispatched.body(), FedSetupInstallation.class).getStatus());

        FedSetupConnection connection = connectionForTenant(getList(applicationRealm.getName(), "connections", FedSetupConnection.class), applicationTenant);
        assertEquals("saml", connection.getProtocol());
        assertEquals(realmIssuer(idpRealm), connection.getSso().get("entity_id"));
        assertEquals(realmIssuer(idpRealm) + "/protocol/saml", connection.getSso().get("single_sign_on_service"));
        assertEquals(realmIssuer(idpRealm) + "/protocol/saml/descriptor", connection.getSamlMetadataUrl());
        assertEquals(Map.of("email", "mail", "given_name", "givenName"), connection.getSamlAttributeMapping());

        IdentityProviderRepresentation broker = applicationRealm.admin().identityProviders().get(connection.getBrokerAlias()).toRepresentation();
        assertEquals("saml", broker.getProviderId());
        assertEquals(realmIssuer(idpRealm), broker.getConfig().get("idpEntityId"));

        // The metadata URL was accepted during installation only because it
        // was issuer-bound in the trust. Refresh uses the same guard before
        // atomically updating the FedSetup-managed broker configuration.
        applicationRunOnServer.run(session -> new org.keycloak.fedsetup.FedSetupSamlMetadataRefresher(
                session, session.getContext().getRealm(), new RealmFedSetupStore(session.getContext().getRealm())).refreshAll());
        FedSetupConnection refreshed = connectionForTenant(getList(applicationRealm.getName(), "connections", FedSetupConnection.class), applicationTenant);
        assertEquals(realmIssuer(idpRealm) + "/protocol/saml", refreshed.getSso().get("single_sign_on_service"));
        assertFalse(refreshed.getSso().get("signing_certificate").isBlank());
        assertFalse(refreshed.getSso().get("signing_certificate").contains("BEGIN CERTIFICATE"));
    }

    @Test
    void applicationAdministratorCanAdoptOnlyAnExistingBrokerBoundToItsTrust() throws Exception {
        String applicationTenant = APPLICATION_TENANT + "-manual-adoption";
        FedSetupConfigurationProfile profile = applicationProfile(applicationTenant);
        assertEquals(200, put(applicationRealm.getName(), "application-profile", Map.of(
                "applicationTenantId", profile.getApplicationTenantId(),
                "canonicalBaseUri", profile.getCanonicalBaseUri(),
                "oidcClientId", profile.getOidcClientId(),
                "capabilities", profile.getCapabilities())).status());

        FedSetupTrustPreAuthorization preAuthorization = new FedSetupTrustPreAuthorization();
        preAuthorization.setApplicationTenantId(applicationTenant);
        preAuthorization.setIdpIssuer(realmIssuer(idpRealm));
        preAuthorization.setCimdUri(cimdUri(idpRealm));
        preAuthorization.setCapabilities(Set.of("oidc"));
        preAuthorization.setFederationExtensionProfiles(Set.of(FedSetupConstants.FEATURE_PROFILE_URI));
        assertEquals(201, post(applicationRealm.getName(), "trust-pre-authorizations", preAuthorization).status());

        DirectInstallationTrust outboundTrust = outboundBackChannelTrust(applicationTenant);
        AdminResponse createdTrust = post(idpRealm.getName(), "trusts", outboundTrust);
        assertEquals(201, createdTrust.status(), createdTrust.body());
        DirectInstallationTrust idpTrust = read(createdTrust.body(), DirectInstallationTrust.class);
        assertEquals(200, post(idpRealm.getName(), "trusts/" + idpTrust.getId() + "/establish", null).status());
        DirectInstallationTrust applicationTrust = trustForTenant(
                getList(applicationRealm.getName(), "trusts", DirectInstallationTrust.class), applicationTenant);

        String alias = "manual-fedsetup-broker";
        Map<String, String> manualConfig = new LinkedHashMap<>();
        manualConfig.put("issuer", realmIssuer(idpRealm));
        manualConfig.put("authorizationUrl", realmIssuer(idpRealm) + "/protocol/openid-connect/auth");
        manualConfig.put("tokenUrl", realmIssuer(idpRealm) + "/protocol/openid-connect/token");
        manualConfig.put("clientId", "manually-registered-client");
        if (applicationTrust.getRuntimeJwksUri() != null) {
            manualConfig.put("jwksUrl", applicationTrust.getRuntimeJwksUri());
        }
        IdentityProviderRepresentation manualBroker = new IdentityProviderRepresentation();
        manualBroker.setAlias(alias);
        manualBroker.setProviderId("oidc");
        manualBroker.setEnabled(true);
        Map<String, String> mismatchedConfig = new LinkedHashMap<>(manualConfig);
        mismatchedConfig.put("issuer", "https://untrusted.example/realm");
        manualBroker.setConfig(mismatchedConfig);
        try (Response response = applicationRealm.admin().identityProviders().create(manualBroker)) {
            assertEquals(201, response.getStatus());
        }

        ManualConnectionAdoption adoption = new ManualConnectionAdoption();
        adoption.setTrustId(applicationTrust.getId());
        adoption.setBrokerAlias(alias);
        assertEquals(400, post(applicationRealm.getName(), "connections/adopt", adoption).status());

        manualBroker.setConfig(new LinkedHashMap<>(manualConfig));
        applicationRealm.admin().identityProviders().get(alias).update(manualBroker);
        AdminResponse adopted = post(applicationRealm.getName(), "connections/adopt", adoption);
        assertEquals(201, adopted.status(), adopted.body());
        FedSetupConnection connection = read(adopted.body(), FedSetupConnection.class);
        assertEquals(alias, connection.getBrokerAlias());
        assertEquals("oidc", connection.getProtocol());
        assertEquals(Set.of(), connection.getCapabilities());
        assertEquals(applicationTenant, connection.getApplicationTenantId());

        IdentityProviderRepresentation persistedBroker = applicationRealm.admin().identityProviders().get(alias).toRepresentation();
        assertEquals(manualConfig, persistedBroker.getConfig());
    }

    private FedSetupConfigurationProfile applicationProfile(String applicationTenant) {
        FedSetupConfigurationProfile profile = new FedSetupConfigurationProfile();
        profile.setApplicationTenantId(applicationTenant);
        profile.setCanonicalBaseUri(realmIssuer(applicationRealm));
        profile.setOidcClientId(APPLICATION_CLIENT);
        profile.setCapabilities(Set.of("oidc"));
        return profile;
    }

    private FedSetupConfigurationProfile samlApplicationProfile(String applicationTenant) {
        FedSetupConfigurationProfile profile = new FedSetupConfigurationProfile();
        profile.setApplicationTenantId(applicationTenant);
        profile.setCanonicalBaseUri(realmIssuer(applicationRealm));
        profile.setSamlClientId(APPLICATION_SAML_CLIENT);
        profile.setCapabilities(Set.of("saml"));
        return profile;
    }

    private DirectInstallationTrust outboundBackChannelTrust(String applicationTenant) {
        DirectInstallationTrust trust = new DirectInstallationTrust();
        trust.setApplicationTenantId(applicationTenant);
        trust.setCanonicalApplicationBaseUri(realmIssuer(applicationRealm));
        trust.setConfigurationEndpoint(resourceBase(applicationRealm) + "/connections");
        trust.setConnectionEndpointTemplate(resourceBase(applicationRealm) + "/connections/{connection_id}");
        trust.setInstallationTrustEndpoint(resourceBase(applicationRealm) + "/trust");
        trust.setIdpIssuer(realmIssuer(idpRealm));
        trust.setTrustProfileUri(FedSetupConstants.BACK_CHANNEL_TRUST_PROFILE_URI);
        trust.setInstallationRuntimeCimdUri(cimdUri(idpRealm));
        trust.setCapabilities(Set.of("oidc"));
        trust.setExtensionProfiles(Set.of(FedSetupConstants.FEATURE_PROFILE_URI));
        return trust;
    }

    private DirectInstallationTrust outboundFrontChannelTrust(String applicationTenant) {
        DirectInstallationTrust trust = outboundBackChannelTrust(applicationTenant);
        trust.setTrustProfileUri(FedSetupConstants.FRONT_CHANNEL_TRUST_PROFILE_URI);
        trust.setInstallationTrustEndpoint(null);
        trust.setInstallationAuthorizationEndpoint(resourceBase(applicationRealm) + "/front/authorize");
        trust.setInstallationTokenEndpoint(resourceBase(applicationRealm) + "/front/token");
        return trust;
    }

    private String realmIssuer(ManagedRealm realm) {
        return PUBLIC_BASE + "/realms/" + realm.getName();
    }

    private String resourceBase(ManagedRealm realm) {
        return realmIssuer(realm) + "/fedsetup";
    }

    private String cimdUri(ManagedRealm realm) {
        return resourceBase(realm) + "/cimd";
    }

    private AdminResponse put(String realm, String path, Object value) throws Exception {
        try (Client client = client()) {
            try (Response response = target(client, realm, path).request().put(json(value))) {
                return response(response);
            }
        }
    }

    private AdminResponse post(String realm, String path, Object value) throws Exception {
        try (Client client = client()) {
            try (Response response = target(client, realm, path).request().post(value == null ? Entity.text("") : json(value))) {
                return response(response);
            }
        }
    }

    private <T> T getPublic(String path, Class<T> type) throws Exception {
        try (Client client = client()) {
            try (Response response = client.target(keycloakUrls.getBase() + path).request().get()) {
                String body = response.readEntity(String.class);
                assertEquals(200, response.getStatus(), body);
                return read(body, type);
            }
        }
    }

    private void assertPublicStatus(String path, int expectedStatus) throws Exception {
        try (Client client = client()) {
            try (Response response = client.target(keycloakUrls.getBase() + path).request().get()) {
                assertEquals(expectedStatus, response.getStatus(), response.readEntity(String.class));
            }
        }
    }

    private <T> List<T> getList(String realm, String path, Class<T> type) throws Exception {
        try (Client client = client()) {
            try (Response response = target(client, realm, path).request().get()) {
                String body = response.readEntity(String.class);
                assertEquals(200, response.getStatus(), body);
                return JsonSerialization.mapper.readerForListOf(type).readValue(body);
            }
        }
    }

    private static DirectInstallationTrust trustForTenant(List<DirectInstallationTrust> trusts, String applicationTenant) {
        List<DirectInstallationTrust> matches = trusts.stream()
                .filter(trust -> applicationTenant.equals(trust.getApplicationTenantId()))
                .toList();
        assertEquals(1, matches.size(), "Expected exactly one trust for Application Tenant " + applicationTenant);
        return matches.get(0);
    }

    private static FedSetupConnection connectionForTenant(List<FedSetupConnection> connections, String applicationTenant) {
        List<FedSetupConnection> matches = connections.stream()
                .filter(connection -> applicationTenant.equals(connection.getApplicationTenantId()))
                .toList();
        assertEquals(1, matches.size(), "Expected exactly one connection for Application Tenant " + applicationTenant);
        return matches.get(0);
    }

    private Client client() {
        return Keycloak.getClientProvider().newRestEasyClient(null, certificates.getClientSSLContext(), false);
    }

    private WebTarget target(Client client, String realm, String path) {
        return client.target(keycloakUrls.getBase())
                .path("admin").path("realms").path(realm).path("fedsetup").path(path)
                .register(new BearerAuthFilter(adminClient.tokenManager()));
    }

    private static Entity<String> json(Object value) throws Exception {
        return Entity.entity(JsonSerialization.writeValueAsString(value), MediaType.APPLICATION_JSON_TYPE);
    }

    private static AdminResponse response(Response response) {
        return new AdminResponse(response.getStatus(), response.getHeaderString(FedSetupConstants.ETAG_HEADER), response.readEntity(String.class));
    }

    private static <T> T read(String json, Class<T> type) throws IOException {
        return JsonSerialization.readValue(json, type);
    }

    private BrowserResponse browserGet(String uri, HttpClientContext context) throws IOException {
        return browser(new HttpGet(browserUri(uri)), context);
    }

    private BrowserResponse browserPost(String uri, HttpClientContext context, List<? extends NameValuePair> parameters) throws IOException {
        HttpPost request = new HttpPost(browserUri(uri));
        request.setEntity(new UrlEncodedFormEntity(parameters, StandardCharsets.UTF_8));
        return browser(request, context);
    }

    private BrowserResponse browser(org.apache.http.client.methods.HttpUriRequest request, HttpClientContext context) throws IOException {
        HttpResponse response = browser.execute(request, context);
        try {
            Header location = response.getFirstHeader("Location");
            String body = response.getEntity() == null ? "" : EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
            return new BrowserResponse(response.getStatusLine().getStatusCode(), location == null ? null : location.getValue(), body);
        } finally {
            EntityUtils.consume(response.getEntity());
        }
    }

    private String browserUri(String uri) {
        if (uri.startsWith(PUBLIC_BASE)) {
            return keycloakUrls.getBase() + uri.substring(PUBLIC_BASE.length());
        }
        if (uri.startsWith("/")) {
            return keycloakUrls.getBase() + uri;
        }
        throw new AssertionError("Unexpected front-channel browser URI: " + uri);
    }

    private static String formAction(String html) {
        Matcher matcher = FORM_ACTION.matcher(html);
        assertTrue(matcher.find(), html);
        return matcher.group(1).replace("&amp;", "&");
    }

    private static String hiddenValue(String html, String name) {
        Matcher matcher = HIDDEN_INPUT.matcher(html);
        while (matcher.find()) {
            if (name.equals(matcher.group(1))) return matcher.group(2);
        }
        throw new AssertionError("Missing hidden input " + name + " in " + html);
    }

    @SuppressWarnings("unchecked")
    private static String activeRs256Jwk(Map<?, ?> keySet) throws IOException {
        Object keys = keySet.get("keys");
        assertTrue(keys instanceof List<?>, "JWKS response has no keys array");
        for (Object key : (List<?>) keys) {
            if (key instanceof Map<?, ?> jwk && "RS256".equals(jwk.get("alg"))) {
                return JsonSerialization.writeValueAsString((Map<String, Object>) jwk);
            }
        }
        throw new AssertionError("JWKS response has no RS256 signing key: " + keySet);
    }

    private static void assertRedirect(BrowserResponse response, String step) {
        assertTrue(Set.of(302, 303).contains(response.status()), step + " returned HTTP " + response.status() + ": " + response.body());
        assertNotNull(response.location(), step + " did not return a Location header");
    }

    private record AdminResponse(int status, String etag, String body) {
    }

    private record BrowserResponse(int status, String location, String body) {
    }

    public static class FedSetupServerConfig implements KeycloakServerConfig {
        @Override
        public KeycloakServerConfigBuilder configure(KeycloakServerConfigBuilder config) {
            return config.features(Profile.Feature.FED_SETUP_CONFIGURATION)
                    .features(Profile.Feature.SCIM_API)
                    .option("hostname", PUBLIC_BASE)
                    // The proxy and trust-manager setting are test-process
                    // configuration only. Runtime still receives an HTTPS URI
                    // at a public address and performs its normal SSRF checks.
                    .spiOption("connections-http-client", "default", "proxy-mappings",
                            "1\\.1\\.1\\.1;http://127.0.0.1:" + PROXY_PORT)
                    .spiOption("connections-http-client", "default", "disable-trust-manager", "true");
        }
    }

    public static class TlsConfig implements CertificatesConfig {
        @Override
        public CertificatesConfigBuilder configure(CertificatesConfigBuilder config) {
            return config.tlsEnabled(true);
        }
    }

    public static class ApplicationRealmConfig implements RealmConfig {
        @Override
        public RealmBuilder configure(RealmBuilder realm) {
            return realm.clients(ClientBuilder.create(APPLICATION_CLIENT).secret("application-client-secret"),
                            ClientBuilder.create(APPLICATION_SAML_CLIENT).protocol(SamlProtocol.LOGIN_PROTOCOL)
                                    .attribute(SamlProtocol.SAML_ASSERTION_CONSUMER_URL_POST_ATTRIBUTE, "https://application.example.test/saml/acs"),
                            ClientBuilder.create(UNAUTHORIZED_SCIM_CLIENT).secret("ordinary-service-secret").serviceAccountsEnabled())
                    .scimEnabled(true)
                    .users(UserBuilder.create(APPLICATION_ADMIN).email("application-admin@example.test")
                            .name("Application", "Administrator").password(APPLICATION_ADMIN_PASSWORD)
                            .clientRoles("realm-management", "realm-admin"));
        }
    }

    public static class IdpRealmConfig implements RealmConfig {
        @Override
        public RealmBuilder configure(RealmBuilder realm) {
            return realm.clients(ClientBuilder.create(IDP_CLIENT).secret("idp-client-secret"),
                    ClientBuilder.create(IDP_SAML_CLIENT).protocol(SamlProtocol.LOGIN_PROTOCOL)
                            .attribute(SamlProtocol.SAML_ASSERTION_CONSUMER_URL_POST_ATTRIBUTE, "https://application.example.test/saml/acs"));
        }
    }

    /** Minimal CONNECT proxy used only to make a public test origin reach the local TLS server. */
    private static final class ConnectProxy implements AutoCloseable {
        private final ServerSocket server;
        private final Map<String, InetSocketAddress> routes;
        private final ExecutorService workers = Executors.newCachedThreadPool();
        private volatile boolean running;

        private ConnectProxy(int port, Map<String, InetSocketAddress> routes) throws IOException {
            server = new ServerSocket();
            server.bind(new InetSocketAddress("127.0.0.1", port));
            this.routes = new LinkedHashMap<>(routes);
        }

        void start() {
            running = true;
            Thread acceptor = new Thread(this::accept, "fedsetup-test-connect-proxy");
            acceptor.setDaemon(true);
            acceptor.start();
        }

        private void accept() {
            while (running) {
                try {
                    Socket client = server.accept();
                    workers.execute(() -> connect(client));
                } catch (IOException e) {
                    if (running) throw new IllegalStateException("FedSetup test CONNECT proxy stopped unexpectedly", e);
                }
            }
        }

        private void connect(Socket client) {
            try (client) {
                InputStream input = new BufferedInputStream(client.getInputStream());
                String request = readHeaders(input);
                String[] firstLine = request.substring(0, request.indexOf("\r\n")).split(" ");
                if (firstLine.length != 3 || !"CONNECT".equals(firstLine[0])) {
                    throw new IOException("Only CONNECT is supported by the FedSetup test proxy");
                }
                String host = firstLine[1].substring(0, firstLine[1].lastIndexOf(':'));
                InetSocketAddress destination = routes.get(host);
                if (destination == null) throw new IOException("No test proxy route for " + host);
                try (Socket upstream = new Socket(destination.getHostString(), destination.getPort())) {
                    client.getOutputStream().write("HTTP/1.1 200 Connection Established\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
                    client.getOutputStream().flush();
                    workers.execute(() -> copy(input, output(upstream)));
                    copy(upstream.getInputStream(), client.getOutputStream());
                }
            } catch (IOException ignored) {
                // Closing either side of a CONNECT tunnel is expected after a
                // request completes. Assertions happen at the HTTP layer.
            }
        }

        private static OutputStream output(Socket socket) {
            try {
                return socket.getOutputStream();
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }

        private static String readHeaders(InputStream input) throws IOException {
            byte[] bytes = new byte[16 * 1024];
            int index = 0;
            while (index < bytes.length) {
                int next = input.read();
                if (next < 0) throw new IOException("Unexpected end of CONNECT request");
                bytes[index++] = (byte) next;
                if (index >= 4 && bytes[index - 4] == '\r' && bytes[index - 3] == '\n'
                        && bytes[index - 2] == '\r' && bytes[index - 1] == '\n') {
                    return new String(bytes, 0, index, StandardCharsets.US_ASCII);
                }
            }
            throw new IOException("CONNECT request headers are too large");
        }

        private static void copy(InputStream source, OutputStream destination) {
            try {
                source.transferTo(destination);
                destination.flush();
            } catch (IOException ignored) {
                // The other tunnel direction closed first.
            }
        }

        @Override
        public void close() {
            running = false;
            try {
                server.close();
            } catch (IOException ignored) {
            }
            workers.shutdownNow();
        }
    }
}
