/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup;

import java.lang.reflect.Proxy;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import jakarta.ws.rs.core.Response;

import org.keycloak.broker.saml.SAMLIdentityProviderConfig;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.fedsetup.representation.DirectInstallationTrust;
import org.keycloak.fedsetup.representation.FedSetupIdJagConfiguration;
import org.keycloak.fedsetup.representation.FedSetupIdJagResourceBinding;
import org.keycloak.fedsetup.representation.FedSetupInstallation;
import org.keycloak.fedsetup.representation.InstallationConfigurationRequest;
import org.keycloak.fedsetup.representation.InstallationConfigurationResponse;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.util.JsonSerialization;
import org.keycloak.util.KeyWrapperUtil;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FedSetupSecurityTest {

    private static final String SAML_CERTIFICATE_1 = "MIICmzCCAYMCBgGGc0gbfzANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZtYXN0ZXIwHhcNMjMwMjIxMDkyMDUwWhcNMzMwMjIxMDkyMjMwWjARMQ8wDQYDVQQDDAZtYXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCfc15pW/NOT3CM92q7BUB3pyTdA1h0WFG+JM2JjrNyZEbxsycYXS84QlaaEl/qT0wshIFQnv6bD1jy604V9W+7luK6Q/cOoQyRCiI70CVy4kB73sqT8Lgrfux6zWJeZ0lMO14sPq6eJLhWNBGxbGvJtUgBAdv5TIjf8yaHCV+yo4rc83T6Pd1sfTlRrURnokPD+hy+BbCEVj9350vYiyTRSvUD+e1wG1BIyZ/IA572p15rS69PP+qAuBBE8QF42bI56ZTsU+tXxwSX2nPqVbLD61tb1BFXfrHkArRiLe/Dte7xAmArynWs62ZI1q52REVWik1dzzy+VpJ7lef7vgtJAgMBAAEwDQYJKoZIhvcNAQELBQADggEBADB5DXugTWEYrw/ic/Jqz+aKXlz+QJvP5JEOVMnfKQLfHx+6760ubCwqJstA8HL6z8DWQUWWylwhfFv15nW/tgawbYLGHiq0NfB3/T6u3hswAPff9ZNvviL0L8CtPXpgPE5MzUEyPRIl/ExW/a7oNlo3rOPE6vA2xEG5h24f9xVdT5hGT5wRTm/e64ZT+umpWs2HnGjRcvdEKZhQPGfKrfdzNn1DVobbGSuy7P64lPWRJ/DxrhMwVkOyfZ+XoIGavS/yLQt01KjIrqtmUZOwHE5FRM/B58doGZn/zNpxq0tb7t9sxWIcW6wyZyieTAO7D9D84Qw8EBwKlbtsfS0oSZw=";
    private static final String SAML_CERTIFICATE_2 = "MIICmzCCAYMCBgGGc0gb+jANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZtYXN0ZXIwHhcNMjMwMjIxMDkyMDUxWhcNMzMwMjIxMDkyMjMxWjARMQ8wDQYDVQQDDAZtYXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDOgZKCSPgYFaBCLrhaX4jBjgTqdYemJPLyR3gAq3GhO/KVVj5i3lOJYLPE3TdyxowxpvnqJK5zIgLv954y7cbah5wbyfdcFf/qa/RvEDAVb1c3gs+7e5uEoiAWgvARQbcduuO8U/rerlgF3eN0WLjIjcz8yncLmMvd+AhjOAqs3AmKrlEADeABTRq454gXjrD8x3bZwRvC67ZOdK32WpfIG9u58WABDYHWavQ8aetcs1uuwbNl7Tmi0heEtgBd8q2y3BJmn31NXmRobLwNuILEN8sujMKf6iaISA50gh0TCUYSbzeeQ6DrqHBlOA8azpuwka4pQyr+R22MDdrItTc3AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAKuc82PlWzQbevzd/FvbutsEX5Tdf4Nojd+jOvcP6NiDtImWojzgN+SSAKTtmCz3ToBxjJbI4UjhovjWN4e4ygEWksBw6YYYR9ZGCJ7Z3EZzyREojvZeF/H0lQqB3BgnjI38HBpRgCpZm3H6+1UoJtMOW2sU8jorG/k1qvXrx2Y3bZvj/6wixVnzjiFzagb3cIUzv9c7ZWlexaR2Bg0k4kQ5TFwyzYCE136nl8xPqoDd8Nc4fQEPI7wLYMGglmbLFlGvdz3IJ7XRparYJRm4wlznQ43GL2x2KGBu8JipgbA7+u6F84oqf3vOC/PozWXzVCn08e6gqBY3YdZcs6sA3qY=";

    @Test
    void canonicalizesTrustedHttpsIdentifiers() {
        assertEquals("https://example.com/application", FedSetupUri.canonicalize("HTTPS://EXAMPLE.COM:443/application/"));
        assertEquals("https://example.com/", FedSetupUri.canonicalize("https://example.com"));
    }

    @Test
    void rejectsAmbiguousOrNonHttpsTrustedIdentifiers() {
        assertThrows(FedSetupValidationException.class, () -> FedSetupUri.canonicalize("http://example.com"));
        assertThrows(FedSetupValidationException.class, () -> FedSetupUri.canonicalize("https://example.com/path?key=value"));
        assertThrows(FedSetupValidationException.class, () -> FedSetupUri.canonicalize("https://user@example.com"));
    }

    @Test
    void comparesTrustedEndpointOriginsWithCanonicalHttpsPorts() {
        assertEquals(true, FedSetupUri.sameOrigin("https://issuer.example/realms/acme", "https://ISSUER.EXAMPLE:443/protocol/openid-connect/token"));
        assertEquals(false, FedSetupUri.sameOrigin("https://issuer.example", "https://other.example/protocol/openid-connect/token"));
    }

    @Test
    void rejectsIpv6UniqueLocalFetchAddresses() {
        FedSetupValidationException exception = assertThrows(FedSetupValidationException.class,
                () -> FedSetupUri.requirePublicAddress("https://[fc00::1]/metadata", "Metadata source"));
        assertTrue(exception.getMessage().contains("prohibited network address"));
    }

    @Test
    void retainsConfiguredSamlSloWhenRefreshedMetadataOmitsIt() {
        Map<String, String> broker = new HashMap<>();
        broker.put(SAMLIdentityProviderConfig.SINGLE_LOGOUT_SERVICE_URL, "https://issuer.example/saml/old-logout");
        broker.put(SAMLIdentityProviderConfig.POST_BINDING_LOGOUT, "true");

        FedSetupSamlMetadataRefresher.applyMetadata(broker,
                new FedSetupSamlMetadataRefresher.SAMLMetadata("https://issuer.example/saml/entity",
                        "https://issuer.example/saml/new-sso", null, SAML_CERTIFICATE_1, true, false, null), true);

        assertEquals("https://issuer.example/saml/old-logout", broker.get(SAMLIdentityProviderConfig.SINGLE_LOGOUT_SERVICE_URL));
        assertEquals("true", broker.get(SAMLIdentityProviderConfig.POST_BINDING_LOGOUT));
    }

    @Test
    void refreshParsesAllSamlMetadataSigningCertificatesAndPrefersPostBinding() {
        FedSetupSamlMetadataRefresher.SAMLMetadata parsed = FedSetupSamlMetadataRefresher.parseAndValidate(
                samlMetadata("https://issuer.example/saml/entity", "https://issuer.example/saml/redirect",
                        "https://issuer.example/saml/post", "https://issuer.example/saml/logout"), samlTrust(), samlConnection());

        assertEquals("https://issuer.example/saml/entity", parsed.entityId());
        assertEquals("https://issuer.example/saml/post", parsed.singleSignOnService());
        assertEquals("https://issuer.example/saml/logout", parsed.singleLogoutService());
        assertTrue(parsed.postBindingResponse());
        assertTrue(parsed.postBindingLogout());
        assertEquals("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", parsed.nameIdFormat());
        assertEquals(SAML_CERTIFICATE_1 + "," + SAML_CERTIFICATE_2, parsed.signingCertificates());
    }

    @Test
    void refreshRejectsSamlMetadataForAnotherEntityOrIssuerOrigin() {
        assertThrows(FedSetupValidationException.class, () -> FedSetupSamlMetadataRefresher.parseAndValidate(
                samlMetadata("https://issuer.example/other", "https://issuer.example/saml/redirect",
                        "https://issuer.example/saml/post", "https://issuer.example/saml/logout"), samlTrust(), samlConnection()));
        assertThrows(FedSetupValidationException.class, () -> FedSetupSamlMetadataRefresher.parseAndValidate(
                samlMetadata("https://issuer.example/saml/entity", "https://other.example/saml/redirect",
                        "https://other.example/saml/post", "https://other.example/saml/logout"), samlTrust(), samlConnection()));
    }

    @Test
    void resolvesOidcMetadataUsingTheRfc8414IssuerDiscoveryAlgorithm() {
        assertEquals("https://issuer.example/.well-known/oauth-authorization-server",
                FedSetupOidcMetadataResolver.discoveryUri("https://issuer.example"));
        assertEquals("https://issuer.example/.well-known/oauth-authorization-server/realms/acme",
                FedSetupOidcMetadataResolver.discoveryUri("https://issuer.example/realms/acme/"));
    }

    @Test
    void resolvesApplicationDiscoveryUsingTheRfc8414InsertionAlgorithm() {
        assertEquals("https://application.example/.well-known/fedsetup",
                FedSetupApplicationDiscoveryService.discoveryUri("https://application.example"));
        assertEquals("https://application.example/.well-known/fedsetup/realms/acme",
                FedSetupApplicationDiscoveryService.discoveryUri("https://application.example/realms/acme/"));
    }

    @Test
    void canonicalizesRegisteredRedirectUrisWithoutChangingTheirQuery() {
        assertEquals("https://example.com/callback?tenant=a", FedSetupUri.canonicalizeRedirectUri("HTTPS://EXAMPLE.COM:443/callback?tenant=a"));
        assertThrows(FedSetupValidationException.class, () -> FedSetupUri.canonicalizeRedirectUri("https://example.com/callback#fragment"));
    }

    @Test
    void canonicalizesOnlyTheSingleConnectionIdentifierTemplate() {
        assertEquals("https://app.example/connections/{connection_id}",
                FedSetupUri.canonicalizeConnectionEndpointTemplate("HTTPS://APP.EXAMPLE:443/connections/{connection_id}"));
        assertThrows(FedSetupValidationException.class,
                () -> FedSetupUri.canonicalizeConnectionEndpointTemplate("https://app.example/connections/{other}"));
        assertThrows(FedSetupValidationException.class,
                () -> FedSetupUri.canonicalizeConnectionEndpointTemplate("https://app.example/{connection_id}/{connection_id}"));
    }

    @Test
    void serializesTheCoreScimBootstrapCredentialOnlyInTheScimResponse() {
        InstallationConfigurationResponse response = new InstallationConfigurationResponse();
        response.setConnectionId("connection-1");
        InstallationConfigurationResponse.ScimResponse scim = new InstallationConfigurationResponse.ScimResponse();
        scim.setProvisioningEndpoint("https://app.example/scim/v2");
        scim.setTokenType("Bearer");
        scim.setAccessToken("secret-value");
        response.setScim(scim);

        String json = JsonSerialization.valueAsString(response);
        assertEquals(true, json.contains("\"access_token\":\"secret-value\""));
        assertEquals(false, json.contains("scimServiceClientId"));
    }

    @Test
    void serializesResponseTimestampsAsDraftDateTimeStrings() {
        InstallationConfigurationResponse response = new InstallationConfigurationResponse();
        response.setConnectionId("connection-1");
        response.setCreatedAt("2026-07-24T22:26:19Z");
        response.setUpdatedAt("2026-07-24T22:27:19Z");

        String json = JsonSerialization.valueAsString(response);
        assertEquals(true, json.contains("\"created_at\":\"2026-07-24T22:26:19Z\""));
        assertEquals(true, json.contains("\"updated_at\":\"2026-07-24T22:27:19Z\""));
    }

    @Test
    void serializesTheRevisedOidcConfigurationBody() {
        InstallationConfigurationRequest request = new InstallationConfigurationRequest();
        request.setIdpIssuer("https://issuer.example");
        request.setIdpDomain("issuer.example");
        InstallationConfigurationRequest.OidcConfiguration oidc = new InstallationConfigurationRequest.OidcConfiguration();
        oidc.setIssuer("https://issuer.example");
        oidc.setClientId("application-client");
        oidc.setClientSecret("client-secret");
        oidc.setTokenEndpointAuthMethod("client_secret_basic");
        request.setOidc(oidc);

        String json = JsonSerialization.valueAsString(request);
        assertEquals(true, json.contains("\"idp_issuer\""));
        assertEquals(true, json.contains("\"client_id\""));
        assertEquals(true, json.contains("\"client_secret\":\"client-secret\""));
        assertEquals(false, json.contains("\"applicationTenantId\""));
        assertEquals(false, json.contains("\"protocol\""));
    }

    @Test
    void enforcesTheDraftsOidcAndSamlObjectCardinality() {
        InstallationConfigurationRequest both = new InstallationConfigurationRequest();
        both.setOidc(new InstallationConfigurationRequest.OidcConfiguration());
        both.setSaml(new InstallationConfigurationRequest.SamlConfiguration());
        assertThrows(FedSetupValidationException.class, () -> FedSetupRealmResource.validateSsoObjectCardinality(both, true));

        InstallationConfigurationRequest none = new InstallationConfigurationRequest();
        assertThrows(FedSetupValidationException.class, () -> FedSetupRealmResource.validateSsoObjectCardinality(none, true));
        FedSetupRealmResource.validateSsoObjectCardinality(none, false);
    }

    @Test
    void permitsOnlyAWorkloadIdJagConnectionToOmitSso() {
        InstallationConfigurationRequest workload = new InstallationConfigurationRequest();
        FedSetupIdJagConfiguration idJag = new FedSetupIdJagConfiguration();
        idJag.setRequesterType("workload_principal");
        workload.setIdJag(idJag);
        FedSetupRealmResource.validateSsoObjectCardinality(workload, true);

        idJag.setRequesterType("app_instance");
        assertThrows(FedSetupValidationException.class, () -> FedSetupRealmResource.validateSsoObjectCardinality(workload, true));
    }

    @Test
    void requiresAZeroByteBodyForGetDeleteAndTrustRequests() {
        FedSetupRealmResource.requireNoBody(null, "GET request");
        FedSetupRealmResource.requireNoBody("", "DELETE request");
        assertThrows(FedSetupValidationException.class, () -> FedSetupRealmResource.requireNoBody(" ", "GET request"));
        assertThrows(FedSetupValidationException.class, () -> FedSetupRealmResource.requireNoBody("{}", "Trust Establishment Request"));
    }

    @Test
    void recordsOnlyRedactedProtocolAuditIdentifiers() {
        org.keycloak.fedsetup.representation.DirectInstallationTrust trust = new org.keycloak.fedsetup.representation.DirectInstallationTrust();
        trust.setId("trust-1");
        trust.setApplicationTenantId("application-tenant");
        trust.setIdpIssuer("https://issuer.example");
        org.keycloak.fedsetup.representation.FedSetupConnection connection = new org.keycloak.fedsetup.representation.FedSetupConnection();
        connection.setId("connection-1");
        connection.setApplicationTenantId("application-tenant");
        connection.setIdpIssuer("https://issuer.example");
        connection.getSso().put("client_secret", "must-not-appear");

        Map<String, String> details = FedSetupAudit.details("connection_credential_rotated", trust, connection);
        assertEquals("connection_credential_rotated", details.get("fedsetup_action"));
        assertEquals("trust-1", details.get("trust_id"));
        assertEquals("connection-1", details.get("connection_id"));
        assertEquals(false, details.containsValue("must-not-appear"));
    }

    @Test
    void treatsIdJagAsAnAuthorizedCoreCapabilityAndKeepsResponseIds() {
        InstallationConfigurationRequest request = new InstallationConfigurationRequest();
        FedSetupIdJagConfiguration idJag = new FedSetupIdJagConfiguration();
        idJag.setClientId("https://requester.example/client.json");
        idJag.setCimdUri("https://requester.example/client.json");
        idJag.setRequesterType("workload_principal");
        FedSetupIdJagConfiguration.ResourceConnection resource = new FedSetupIdJagConfiguration.ResourceConnection();
        resource.setResourceIssuer("https://application.example/realms/resource");
        resource.setResource("https://resource.example/api");
        resource.setScopes(java.util.Set.of("documents.read"));
        resource.setResourceConnectionId("rc_resource_1");
        idJag.setResourceConnections(List.of(resource));
        request.setIdJag(idJag);

        assertTrue(request.requestedCapabilities().contains("id_jag"));
        InstallationConfigurationResponse response = new InstallationConfigurationResponse();
        response.setConnectionId("connection-1");
        response.setIdJag(idJag);
        String json = JsonSerialization.valueAsString(response);
        assertTrue(json.contains("\"id_jag\""));
        assertTrue(json.contains("\"resource_connection_id\":\"rc_resource_1\""));
    }

    @Test
    void rejectsIdJagScopesOutsideTheApprovedResourceBinding() {
        FedSetupIdJagResourceBinding binding = new FedSetupIdJagResourceBinding();
        binding.setScopes(Set.of("documents.read"));

        FedSetupIdJagConnectionService.requireApprovedScopes(binding, Set.of("documents.read"));
        assertThrows(FedSetupValidationException.class,
                () -> FedSetupIdJagConnectionService.requireApprovedScopes(binding, Set.of("documents.write")));
    }

    @Test
    void requiresTheSignedConfigurationSendersEnvelopeOnCreateAndPatch() {
        InstallationConfigurationRequest request = new InstallationConfigurationRequest();
        assertThrows(FedSetupValidationException.class, () -> FedSetupRealmResource.validateRequestEnvelope(request));

        request.setIdpIssuer("https://issuer.example");
        request.setIdpDomain("issuer.example");
        FedSetupRealmResource.validateRequestEnvelope(request);
    }

    @Test
    void retainsTheWriteOnlyOidcCredentialWhenAPatchOmitsIt() {
        assertEquals("existing-secret", FedSetupRealmResource.credentialReferenceForPatch("existing-secret", "new-secret", false));
        assertEquals("existing-secret", FedSetupRealmResource.credentialReferenceForPatch("existing-secret", "new-secret", true));
        assertEquals("new-secret", FedSetupRealmResource.credentialReferenceForPatch(null, "new-secret", true));
        assertEquals(null, FedSetupRealmResource.credentialReferenceForPatch(null, null, false));
    }

    @Test
    void rejectsAnExplicitEmptyOidcSecretButPermitsOmission() {
        InstallationConfigurationRequest request = new InstallationConfigurationRequest();
        InstallationConfigurationRequest.OidcConfiguration oidc = new InstallationConfigurationRequest.OidcConfiguration();
        request.setOidc(oidc);
        FedSetupRealmResource.rejectExplicitEmptyOidcClientSecret(request);

        oidc.setClientSecret("");
        assertThrows(FedSetupValidationException.class, () -> FedSetupRealmResource.rejectExplicitEmptyOidcClientSecret(request));
        oidc.setClientSecret(null);
        FedSetupRealmResource.rejectExplicitEmptyOidcClientSecret(request);
    }

    @Test
    void serializesSamlMappingsAndMetadataWithoutFlatteningThemIntoSso() {
        InstallationConfigurationRequest request = new InstallationConfigurationRequest();
        request.setIdpIssuer("https://issuer.example");
        request.setIdpDomain("issuer.example");
        InstallationConfigurationRequest.SamlConfiguration saml = new InstallationConfigurationRequest.SamlConfiguration();
        saml.setIdpEntityId("https://issuer.example/saml/entity");
        saml.setIdpSsoUrl("https://issuer.example/protocol/saml");
        saml.setIdpCertificate("certificate");
        saml.setAttributeMapping(Map.of("email", "urn:oid:0.9.2342.19200300.100.1.3", "groups", "memberOf"));
        saml.setIdpMetadataUrl("https://issuer.example/saml/metadata");
        request.setSaml(saml);

        String json = JsonSerialization.valueAsString(request);
        assertEquals(true, json.contains("\"attribute_mapping\""));
        assertEquals(true, json.contains("\"idp_metadata_url\""));
        assertEquals(false, request.getSso().containsKey("attribute_mapping"));
        assertEquals(false, request.getSso().containsKey("idp_metadata_url"));
    }

    @Test
    void retainsExplicitScimFeatureSubsetOnTheInstallation() {
        FedSetupInstallation installation = new FedSetupInstallation();
        installation.setScimFeatures(java.util.Set.of("PUSH_NEW_USERS", "PUSH_PROFILE_UPDATES"));

        String json = JsonSerialization.valueAsString(installation);
        assertEquals(true, json.contains("\"scimFeatures\""));
        assertEquals(true, installation.getScimFeatures().contains("PUSH_NEW_USERS"));
        assertEquals(false, installation.getScimFeatures().contains("PUSH_GROUPS"));
    }

    @Test
    void persistsAdministratorApprovedOutboundSamlAttributeMapping() {
        FedSetupInstallation installation = new FedSetupInstallation();
        installation.setProtocol("saml");
        installation.setSamlAttributeMapping(Map.of("email", "mail", "groups", "memberOf"));

        String json = JsonSerialization.valueAsString(installation);
        assertEquals(true, json.contains("\"samlAttributeMapping\""));
        assertEquals("mail", installation.getSamlAttributeMapping().get("email"));
        assertEquals("memberOf", installation.getSamlAttributeMapping().get("groups"));
    }

    @Test
    void detectsOutboundSamlMappingChangesWithoutDependingOnJsonMemberOrder() {
        InstallationConfigurationRequest first = samlRequest(Map.of("email", "mail", "groups", "memberOf"));
        Map<String, String> reordered = new java.util.LinkedHashMap<>();
        reordered.put("groups", "memberOf");
        reordered.put("email", "mail");
        InstallationConfigurationRequest sameMappingDifferentOrder = samlRequest(reordered);
        InstallationConfigurationRequest changed = samlRequest(Map.of("email", "mail", "groups", "groups"));

        assertEquals(OutboundInstallationDispatcher.ssoState(first), OutboundInstallationDispatcher.ssoState(sameMappingDifferentOrder));
        assertEquals(false, OutboundInstallationDispatcher.ssoState(first).equals(OutboundInstallationDispatcher.ssoState(changed)));
    }

    @Test
    void hashesExactUtf8RequestBody() {
        assertEquals("43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777",
                InstallationAuthorizationValidator.sha256("{\"a\":1,\"b\":2}"));
        assertEquals("3fb75453225c732a76b7899ea2096dda1455189c89817239732182f73fe5a09f",
                InstallationAuthorizationValidator.sha256("{\"b\":2,\"a\":1}"));
    }

    @Test
    void signsPlatformControlProofBoundToNonceAndCertificationEndpoint() throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        KeyWrapper key = rsaKey(pair);

        String proof = FedSetupPlatformControlProof.sign(key, "HTTPS://PLATFORM.EXAMPLE:443/fedsetup/cimd/",
                "HTTPS://CATALOG.EXAMPLE:443/platform/certifications", "challenge-nonce",
                "proof-jti", Time.currentTime(), Time.currentTime() + 60);

        JsonWebToken token = FedSetupPlatformControlProof.verify(proof, "https://platform.example/fedsetup/cimd",
                "https://catalog.example/platform/certifications", "challenge-nonce",
                platformControlProofJwk(pair), Set.of(Algorithm.RS256));
        assertEquals("https://platform.example/fedsetup/cimd", token.getIssuer());
        assertEquals(true, token.hasAudience("https://catalog.example/platform/certifications"));
        assertEquals("challenge-nonce", token.getOtherClaims().get("nonce"));
        assertEquals("proof-jti", token.getId());
    }

    @Test
    void rejectsInvalidPlatformControlProofInputs() throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        KeyWrapper key = rsaKey(pair);
        long now = Time.currentTime();

        assertThrows(FedSetupValidationException.class, () -> FedSetupPlatformControlProof.sign(key,
                "https://platform.example/cimd", "https://catalog.example/platform/certifications?unexpected=true",
                "nonce", "jti", now, now + 60));
        assertThrows(FedSetupValidationException.class, () -> FedSetupPlatformControlProof.sign(key,
                "https://platform.example/cimd", "https://catalog.example/platform/certifications",
                "", "jti", now, now + 60));
        assertThrows(FedSetupValidationException.class, () -> FedSetupPlatformControlProof.sign(key,
                "https://platform.example/cimd", "https://catalog.example/platform/certifications",
                "nonce", "jti", now, now + FedSetupConstants.MAX_AUTHORIZATION_LIFESPAN_SECONDS + 1));

        key.setAlgorithm("HS256");
        assertThrows(FedSetupValidationException.class, () -> FedSetupPlatformControlProof.sign(key,
                "https://platform.example/cimd", "https://catalog.example/platform/certifications",
                "nonce", "jti", now, now + 60));
    }

    @Test
    void rejectsPlatformControlProofVerificationMismatches() throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        KeyWrapper key = rsaKey(pair);
        String proof = FedSetupPlatformControlProof.sign(key, "https://platform.example/cimd",
                "https://catalog.example/platform/certifications", "nonce", "jti",
                Time.currentTime(), Time.currentTime() + 60);
        JWK jwk = platformControlProofJwk(pair);

        assertThrows(FedSetupValidationException.class, () -> FedSetupPlatformControlProof.verify(proof,
                "https://platform.example/cimd", "https://catalog.example/platform/certifications",
                "different-nonce", jwk, Set.of(Algorithm.RS256)));
        assertThrows(FedSetupValidationException.class, () -> FedSetupPlatformControlProof.verify(proof,
                "https://platform.example/cimd", "https://catalog.example/platform/certifications",
                "nonce", jwk, Set.of("HS256")));
    }

    @Test
    void rejectsExpiredReplayedAndMalformedInstallationAuthorizations() throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        DirectInstallationTrust trust = installationAuthorizationTrust(pair);
        KeycloakSession session = installationAuthorizationSession();
        String body = "{\"connection\":\"test\"}";
        String authorization = signedInstallationAuthorization(pair, "authorization-1", Time.currentTime(),
                Time.currentTime() + 60, body);

        InstallationAuthorizationValidator.validate(session, trust, "Bearer " + authorization, "POST",
                "https://application.example/connections", body, "application-tenant", Set.of("scim"), Set.of());
        assertThrows(FedSetupValidationException.class,
                () -> InstallationAuthorizationValidator.validate(session, trust, "Bearer " + authorization, "POST",
                        "https://application.example/connections", body, "application-tenant", Set.of("scim"), Set.of()));

        String expired = signedInstallationAuthorization(pair, "authorization-expired", Time.currentTime() - 120,
                Time.currentTime() - 60, body);
        assertThrows(FedSetupValidationException.class,
                () -> InstallationAuthorizationValidator.validate(session, trust, "Bearer " + expired, "POST",
                        "https://application.example/connections", body, "application-tenant", Set.of("scim"), Set.of()));
        assertThrows(FedSetupValidationException.class,
                () -> InstallationAuthorizationValidator.validate(session, trust, "Bearer malformed", "POST",
                        "https://application.example/connections", body, "application-tenant", Set.of("scim"), Set.of()));
    }

    @Test
    void derivesOutboundOidcScopesFromThePreCreatedClient() {
        ClientModel client = (ClientModel) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[] { ClientModel.class },
                (proxy, method, arguments) -> switch (method.getName()) {
                    case "getClientScopes" -> {
                        Map<String, org.keycloak.models.ClientScopeModel> scopes = new HashMap<>();
                        scopes.put("groups", null);
                        yield scopes;
                    }
                    default -> throw new UnsupportedOperationException(method.getName());
                });

        assertEquals(java.util.Set.of("openid", "profile", "email", "groups"), OutboundInstallationDispatcher.effectiveOidcScopes(client));
    }

    @Test
    void doesNotRelabelSymmetricClientSecretJwtAsPrivateKeyJwt() {
        ClientModel client = (ClientModel) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[] { ClientModel.class },
                (proxy, method, arguments) -> switch (method.getName()) {
                    case "isPublicClient" -> false;
                    case "getClientAuthenticatorType" -> "client-secret-jwt";
                    default -> throw new UnsupportedOperationException(method.getName());
                });

        assertThrows(FedSetupValidationException.class, () -> OutboundInstallationDispatcher.clientAuthenticationMethod(client));
    }

    @Test
    void outboxRetriesOnlyDueAdministratorApprovedFailures() {
        FedSetupInstallation installation = new FedSetupInstallation();
        installation.setStatus("PENDING_REVIEW");
        installation.setNextAttemptAt(0);
        assertEquals(false, FedSetupInstallationOutboxTask.isDue(installation, 100));

        installation.setStatus(FedSetupInstallationOutboxTask.RETRY_PENDING);
        installation.setNextAttemptAt(101);
        assertEquals(false, FedSetupInstallationOutboxTask.isDue(installation, 100));

        installation.setNextAttemptAt(100);
        assertEquals(true, FedSetupInstallationOutboxTask.isDue(installation, 100));

        installation.setStatus(FedSetupInstallationOutboxTask.DELETE_RETRY_PENDING);
        assertEquals(true, FedSetupInstallationOutboxTask.isDue(installation, 100));
    }

    @Test
    void scopesIdempotencyToTheImmutableApplicationAndIdpBinding() {
        Map<String, String> attributes = new HashMap<>();
        RealmModel realm = (RealmModel) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[] { RealmModel.class },
                (proxy, method, arguments) -> switch (method.getName()) {
                    case "getAttribute" -> attributes.get(arguments[0]);
                    case "setAttribute" -> attributes.put((String) arguments[0], (String) arguments[1]);
                    case "removeAttribute" -> attributes.remove(arguments[0]);
                    default -> throw new UnsupportedOperationException(method.getName());
                });
        RealmFedSetupStore store = new RealmFedSetupStore(realm);
        store.putIdempotencyResult("same-key", "application-a", "https://idp-a.example", "connection-a", "request-hash");

        assertEquals("connection-a", store.getIdempotencyResult("same-key", "application-a", "https://idp-a.example", "request-hash"));
        assertEquals(null, store.getIdempotencyResult("same-key", "application-b", "https://idp-b.example", "request-hash"));
        assertThrows(FedSetupValidationException.class,
                () -> store.getIdempotencyResult("same-key", "application-a", "https://idp-a.example", "different-request-hash"));
    }

    @Test
    void locatesOutboundFrontChannelTransactionsByTheirOpaqueState() {
        Map<String, String> attributes = new HashMap<>();
        RealmModel realm = (RealmModel) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[] { RealmModel.class },
                (proxy, method, arguments) -> switch (method.getName()) {
                    case "getAttribute" -> attributes.get(arguments[0]);
                    case "setAttribute" -> attributes.put((String) arguments[0], (String) arguments[1]);
                    case "removeAttribute" -> attributes.remove(arguments[0]);
                    default -> throw new UnsupportedOperationException(method.getName());
                });
        RealmFedSetupStore store = new RealmFedSetupStore(realm);
        org.keycloak.fedsetup.representation.FedSetupFrontChannelTransaction transaction =
                new org.keycloak.fedsetup.representation.FedSetupFrontChannelTransaction();
        transaction.setState("unpredictable-oauth-state");
        transaction.setTrustId("outbound-trust");
        store.createFrontChannelTransaction(transaction);

        assertEquals(transaction.getId(), store.findFrontChannelTransactionByState("unpredictable-oauth-state").getId());
        assertEquals(null, store.findFrontChannelTransactionByState("different-state"));
    }

    @Test
    void preservesProtocolDefinedTrustAndConcurrencyErrorCodes() {
        assertEquals("untrusted_issuer", FedSetupRealmResource.protocolErrorCode(Response.Status.BAD_REQUEST,
                "Trust Establishment Request exceeds the pre-authorization"));
        assertEquals("untrusted_issuer", FedSetupRealmResource.protocolErrorCode(Response.Status.BAD_REQUEST,
                "No Direct Installation Trust exists for this Application Tenant and installation runtime"));
        assertEquals("invalid_credential", FedSetupRealmResource.protocolErrorCode(Response.Status.BAD_REQUEST,
                "Installation Authorization has already been used"));
        assertEquals("invalid_credential", FedSetupRealmResource.protocolErrorCode(Response.Status.BAD_REQUEST,
                "Invalid Installation Authorization"));
        assertEquals("conflict", FedSetupRealmResource.protocolErrorCode(Response.Status.CONFLICT, "any conflict"));
        assertEquals("precondition_failed", FedSetupRealmResource.protocolErrorCode(Response.Status.PRECONDITION_FAILED, "ETag mismatch"));
    }

    private static org.keycloak.fedsetup.representation.DirectInstallationTrust samlTrust() {
        org.keycloak.fedsetup.representation.DirectInstallationTrust trust = new org.keycloak.fedsetup.representation.DirectInstallationTrust();
        trust.setIdpIssuer("https://issuer.example");
        return trust;
    }

    private static org.keycloak.fedsetup.representation.FedSetupConnection samlConnection() {
        org.keycloak.fedsetup.representation.FedSetupConnection connection = new org.keycloak.fedsetup.representation.FedSetupConnection();
        connection.setSso(Map.of("entity_id", "https://issuer.example/saml/entity",
                "single_sign_on_service", "https://issuer.example/saml/old",
                "single_logout_service", "https://issuer.example/saml/old-logout"));
        return connection;
    }

    private static String samlMetadata(String entityId, String redirectSso, String postSso, String slo) {
        return "<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" "
                + "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"" + entityId + "\">"
                + "<IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">"
                + "<KeyDescriptor use=\"signing\"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>" + SAML_CERTIFICATE_1
                + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>"
                + "<KeyDescriptor use=\"signing\"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>" + SAML_CERTIFICATE_2
                + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>"
                + "<SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"" + redirectSso + "\"/>"
                + "<SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"" + postSso + "\"/>"
                + "<SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"" + slo + "\"/>"
                + "<NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>"
                + "</IDPSSODescriptor></EntityDescriptor>";
    }

    private static InstallationConfigurationRequest samlRequest(Map<String, String> mapping) {
        InstallationConfigurationRequest request = new InstallationConfigurationRequest();
        InstallationConfigurationRequest.SamlConfiguration saml = new InstallationConfigurationRequest.SamlConfiguration();
        saml.setIdpEntityId("https://issuer.example/saml/entity");
        saml.setIdpSsoUrl("https://issuer.example/protocol/saml");
        saml.setIdpCertificate("certificate");
        saml.setAttributeMapping(mapping);
        request.setSaml(saml);
        return request;
    }

    private static DirectInstallationTrust installationAuthorizationTrust(KeyPair pair) {
        DirectInstallationTrust trust = new DirectInstallationTrust();
        trust.setActive(true);
        trust.setApplicationTenantId("application-tenant");
        trust.setIdpIssuer("https://issuer.example");
        trust.setCapabilities(Set.of("scim"));
        trust.setSigningKeyJwk(JsonSerialization.valueAsString(JWKBuilder.create().kid("fedsetup-test-key")
                .algorithm(Algorithm.RS256).rsa(pair.getPublic())));
        return trust;
    }

    private static String signedInstallationAuthorization(KeyPair pair, String id, long issuedAt, long expiresAt, String body) {
        KeyWrapper key = rsaKey(pair);
        org.keycloak.representations.JsonWebToken token = new org.keycloak.representations.JsonWebToken()
                .issuer("https://issuer.example").id(id).iat(issuedAt).exp(expiresAt);
        token.setOtherClaims("application_tenant_id", "application-tenant");
        token.setOtherClaims("method", "POST");
        token.setOtherClaims("uri", "https://application.example/connections");
        token.setOtherClaims("request_hash", InstallationAuthorizationValidator.sha256(body));
        token.setOtherClaims("capabilities", List.of("scim"));
        token.setOtherClaims("extension_profiles", List.of());
        return new JWSBuilder().type("JWT").kid(key.getKid()).jsonContent(token)
                .sign(KeyWrapperUtil.createSignatureSignerContext(key));
    }

    private static KeyWrapper rsaKey(KeyPair pair) {
        KeyWrapper key = new KeyWrapper();
        key.setKid("fedsetup-test-key");
        key.setType(KeyType.RSA);
        key.setAlgorithm(Algorithm.RS256);
        key.setPrivateKey(pair.getPrivate());
        key.setPublicKey(pair.getPublic());
        return key;
    }

    private static JWK platformControlProofJwk(KeyPair pair) {
        return JWKBuilder.create().kid("fedsetup-test-key").algorithm(Algorithm.RS256).rsa(pair.getPublic());
    }

    private static KeycloakSession installationAuthorizationSession() {
        Set<String> consumed = new HashSet<>();
        RealmModel realm = (RealmModel) Proxy.newProxyInstance(FedSetupSecurityTest.class.getClassLoader(),
                new Class<?>[] { RealmModel.class }, (proxy, method, arguments) -> switch (method.getName()) {
                    case "getId" -> "realm";
                    default -> throw new UnsupportedOperationException(method.getName());
                });
        KeycloakContext context = (KeycloakContext) Proxy.newProxyInstance(FedSetupSecurityTest.class.getClassLoader(),
                new Class<?>[] { KeycloakContext.class }, (proxy, method, arguments) -> switch (method.getName()) {
                    case "getRealm" -> realm;
                    default -> throw new UnsupportedOperationException(method.getName());
                });
        SingleUseObjectProvider singleUseObjects = (SingleUseObjectProvider) Proxy.newProxyInstance(
                FedSetupSecurityTest.class.getClassLoader(), new Class<?>[] { SingleUseObjectProvider.class },
                (proxy, method, arguments) -> switch (method.getName()) {
                    case "putIfAbsent" -> consumed.add((String) arguments[0]);
                    default -> throw new UnsupportedOperationException(method.getName());
                });
        return (KeycloakSession) Proxy.newProxyInstance(FedSetupSecurityTest.class.getClassLoader(),
                new Class<?>[] { KeycloakSession.class }, (proxy, method, arguments) -> switch (method.getName()) {
                    case "getContext" -> context;
                    case "singleUseObjects" -> singleUseObjects;
                    default -> throw new UnsupportedOperationException(method.getName());
                });
    }
}
