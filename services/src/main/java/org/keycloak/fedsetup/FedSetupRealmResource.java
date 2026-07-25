/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.PATCH;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;

import org.keycloak.common.util.Time;
import org.keycloak.common.util.PemUtils;
import org.keycloak.broker.saml.mappers.UserAttributeMapper;
import org.keycloak.fedsetup.representation.FedSetupConfigurationProfile;
import org.keycloak.fedsetup.representation.DirectInstallationTrust;
import org.keycloak.fedsetup.representation.FedSetupConnection;
import org.keycloak.fedsetup.representation.FedSetupCredentialReference;
import org.keycloak.fedsetup.representation.FedSetupFrontChannelTransaction;
import org.keycloak.fedsetup.representation.InstallationConfigurationRequest;
import org.keycloak.fedsetup.representation.InstallationConfigurationResponse;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.AdminRoles;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.oidc.OIDCClientRepresentation;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.urls.UrlType;
import org.keycloak.util.JsonSerialization;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Application-facing Express Configuration receiver.
 *
 * <p>Every mutable request requires an authorization that has been validated
 * against a realm-local {@link DirectInstallationTrust}. The receiver never
 * fetches a request-supplied JWKS or stores an incoming secret.</p>
 */
public class FedSetupRealmResource implements RealmResourceProvider {

    private static final Pattern BROKER_ALIAS = Pattern.compile("[A-Za-z0-9_-]{1,255}");
    private static final Pattern VAULT_REFERENCE = Pattern.compile("\\$\\{vault\\.[A-Za-z0-9_.-]+}");
    private static final Set<String> OIDC_SSO_FIELDS = Set.of("issuer", "authorization_endpoint", "token_endpoint",
            "userinfo_endpoint", "logout_endpoint", "client_id", "client_secret", "default_scope", "client_auth_method");
    private static final Set<String> SAML_SSO_FIELDS = Set.of("entity_id", "single_sign_on_service", "single_logout_service",
            "name_id_format", "signing_certificate");
    private static final Set<String> SAML_ATTRIBUTE_FIELDS = Set.of("email", "given_name", "family_name", "display_name", "groups");
    private static final Map<String, String> SAML_USER_ATTRIBUTES = Map.of(
            "email", "email", "given_name", "firstName", "family_name", "lastName", "display_name", "displayName", "groups", "groups");
    private static final String SAML_MAPPER_PREFIX = "FedSetup SAML attribute: ";
    private static final SecureRandom RANDOM = new SecureRandom();

    private final KeycloakSession session;
    private final RealmModel realm;
    private final RealmFedSetupStore store;

    public FedSetupRealmResource(KeycloakSession session) {
        this.session = session;
        this.realm = session.getContext().getRealm();
        this.store = new RealmFedSetupStore(realm);
    }

    /** Public Client ID Metadata Document for this realm's installation runtime. */
    @GET
    @Path("cimd")
    @Produces(MediaType.APPLICATION_JSON)
    public Response cimd() {
        String issuer = Urls.realmIssuer(session.getContext().getUri(UrlType.FRONTEND).getBaseUri(), realm.getName());
        OIDCClientRepresentation result = new OIDCClientRepresentation();
        result.setClientId(FedSetupUrls.cimd(session.getContext().getUri(UrlType.FRONTEND), realm));
        result.setJwksUri(issuer + "/protocol/openid-connect/certs");
        result.setTokenEndpointAuthMethod("private_key_jwt");
        result.setTokenEndpointAuthSigningAlg("RS256");
        result.setRedirectUris(List.of(FedSetupUrls.frontCallback(session.getContext().getUri(UrlType.FRONTEND), realm)));
        return Response.ok(result).type(MediaType.APPLICATION_JSON).header("Cache-Control", "public, max-age=300").build();
    }

    /** Section 5.1: pre-authorized, no-body Trust Establishment Request. */
    @POST
    @Path("trust")
    @Produces(MediaType.APPLICATION_JSON)
    public Response establishBackChannelTrust(@HeaderParam("Authorization") String authorization,
                                              @HeaderParam(FedSetupConstants.IDEMPOTENCY_HEADER) String idempotencyKey,
                                              String body) {
        try {
            requireNoBody(body, "Trust Establishment Request");
            DirectInstallationTrust trust = BackChannelTrustService.establish(session, realm, store, authorization, idempotencyKey, requestUri());
            FedSetupAudit.success(session, realm, org.keycloak.events.admin.OperationType.CREATE,
                    "trust_established_back_channel", trust, null);
            return Response.status(Response.Status.CREATED).type(MediaType.APPLICATION_JSON)
                    .entity(trustConfirmation(trust)).build();
        } catch (FedSetupValidationException e) {
            return trustError(e);
        }
    }

    /** Section 5.2 authorization endpoint. The browser is sent through this realm's normal login flow. */
    @GET
    @Path("front/authorize")
    public Response startFrontChannelTrust(@QueryParam("response_type") String responseType,
                                           @QueryParam("client_id") String clientId,
                                           @QueryParam("idp_issuer") String idpIssuer,
                                           @QueryParam("redirect_uri") String redirectUri,
                                           @QueryParam("application_tenant_id") String applicationTenantId,
                                           @QueryParam("capabilities") String capabilityTerms,
                                           @QueryParam("provider_delegation_profiles") String providerProfileTerms,
                                           @QueryParam("federation_extension_profiles") String federationProfileTerms,
                                           @QueryParam("scope") String scope,
                                           @QueryParam("audience") String audience,
                                           @QueryParam("state") String state) {
        try {
            if (!"code".equals(responseType) || blank(clientId) || blank(idpIssuer) || blank(redirectUri)
                    || blank(applicationTenantId) || blank(state) || (blank(scope) && blank(audience))) {
                throw new FedSetupValidationException("response_type, client_id, idp_issuer, redirect_uri, application_tenant_id, state, and scope or audience are required");
            }
            FedSetupConfigurationProfile profile = requireApplicationProfile(applicationTenantId);
            String cimdUri = FedSetupUri.canonicalize(clientId);
            String canonicalIssuer = FedSetupUri.canonicalize(idpIssuer);
            String canonicalRedirectUri = FedSetupUri.canonicalizeRedirectUri(redirectUri);
            OIDCClientRepresentation metadata = FedSetupCimdResolver.metadata(session, cimdUri);
            if (!"private_key_jwt".equals(metadata.getTokenEndpointAuthMethod())
                    || !FedSetupConstants.INSTALLATION_SIGNING_ALGORITHM.equals(metadata.getTokenEndpointAuthSigningAlg())
                    || metadata.getRedirectUris() == null || metadata.getRedirectUris().stream()
                    .map(FedSetupUri::canonicalizeRedirectUri).noneMatch(canonicalRedirectUri::equals)) {
                throw new FedSetupValidationException("redirect_uri or client authentication method is not registered by the CIMD document");
            }

            Set<String> capabilities = terms(capabilityTerms);
            Set<String> providerProfiles = terms(providerProfileTerms);
            Set<String> federationProfiles = terms(federationProfileTerms);
            if (!providerProfiles.isEmpty()) {
                throw new FedSetupValidationException("This Keycloak preview does not implement a Provider Delegation Profile");
            }
            if (!profile.getCapabilities().containsAll(capabilities) || !profile.getExtensionProfiles().containsAll(federationProfiles)) {
                throw new FedSetupValidationException("Requested capabilities or federation extension profiles are not supported by this Application Tenant");
            }
            FedSetupFrontChannelTransaction transaction = new FedSetupFrontChannelTransaction();
            transaction.setApplicationTenantId(applicationTenantId);
            transaction.setIdpIssuer(canonicalIssuer);
            transaction.setCimdUri(cimdUri);
            transaction.setRedirectUri(canonicalRedirectUri);
            transaction.setState(state);
            transaction.setCapabilities(capabilities);
            transaction.setProviderDelegationProfiles(providerProfiles);
            transaction.setFederationExtensionProfiles(federationProfiles);
            transaction.setConsentNonce(randomValue());
            transaction.setExpiresAt(Time.currentTime() + FedSetupConstants.MAX_AUTHORIZATION_LIFESPAN_SECONDS);
            transaction = store.createFrontChannelTransaction(transaction);

            ClientModel client = frontChannelLoginClient();
            URI login = UriBuilder.fromUri(Urls.realmIssuer(session.getContext().getUri(UrlType.FRONTEND).getBaseUri(), realm.getName())
                            + "/protocol/openid-connect/auth")
                    .queryParam("client_id", client.getClientId())
                    .queryParam("response_type", "code")
                    .queryParam("redirect_uri", FedSetupUrls.frontLoginCallback(session.getContext().getUri(UrlType.FRONTEND), realm))
                    .queryParam("scope", "openid")
                    .queryParam("state", transaction.getId()).build();
            return Response.seeOther(login).header("Cache-Control", "no-store").build();
        } catch (FedSetupValidationException e) {
            return trustError(e);
        }
    }

    /**
     * Receives the IdP-side browser callback defined by the profile.  The
     * callback state is an opaque IdP value, never a Keycloak record ID.
     */
    @GET
    @Path("front/callback")
    @Produces(MediaType.TEXT_HTML)
    public Response frontChannelCallback(@QueryParam("code") String code, @QueryParam("state") String transactionId) {
        try {
            if (blank(code) || blank(transactionId)) throw new FedSetupValidationException("Authorization response is missing code or state");
            FedSetupFrontChannelTransaction transaction = store.findFrontChannelTransactionByState(transactionId);
            if (transaction == null || transaction.getTrustId() == null || transaction.getExpiresAt() <= Time.currentTime() || transaction.isConsumed()) {
                throw new FedSetupValidationException("Front-channel authorization transaction is expired or invalid");
            }
            return outboundFrontChannelCallback(transaction, code);
        } catch (FedSetupValidationException e) {
            return Response.status(Response.Status.BAD_REQUEST).type(MediaType.TEXT_HTML).entity(errorPage(e.getMessage())).build();
        }
    }

    /** Receives Keycloak's internal administrator-login callback before consent is rendered. */
    @GET
    @Path("front/login-callback")
    @Produces(MediaType.TEXT_HTML)
    public Response frontChannelLoginCallback(@QueryParam("code") String code, @QueryParam("state") String transactionId) {
        try {
            if (blank(code) || blank(transactionId)) throw new FedSetupValidationException("Authorization response is missing code or state");
            FedSetupFrontChannelTransaction transaction = store.getFrontChannelTransaction(transactionId);
            if (transaction == null || transaction.getTrustId() != null || transaction.getExpiresAt() <= Time.currentTime() || transaction.isConsumed()) {
                throw new FedSetupValidationException("Front-channel authorization transaction is expired or invalid");
            }
            requireApplicationRealmAdministrator();
            return Response.ok(consentPage(transaction)).type(MediaType.TEXT_HTML)
                    .header("Cache-Control", "no-store").header("Pragma", "no-cache")
                    .header("X-Frame-Options", "DENY")
                    .header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'").build();
        } catch (FedSetupValidationException e) {
            return Response.status(Response.Status.BAD_REQUEST).type(MediaType.TEXT_HTML).entity(errorPage(e.getMessage())).build();
        }
    }

    /** Explicit consent action. A transaction-specific nonce prevents cross-site approval. */
    @POST
    @Path("front/approve")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response approveFrontChannelTrust(@FormParam("transaction") String transactionId,
                                             @FormParam("consent_nonce") String consentNonce) {
        try {
            FedSetupFrontChannelTransaction transaction = store.getFrontChannelTransaction(transactionId);
            if (transaction == null || transaction.getExpiresAt() <= Time.currentTime() || transaction.isConsumed() || transaction.isConsented()) {
                throw new FedSetupValidationException("Front-channel authorization transaction is expired or invalid");
            }
            requireApplicationRealmAdministrator();
            if (!constantTimeEquals(transaction.getConsentNonce(), consentNonce)) {
                throw new FedSetupValidationException("Front-channel consent nonce is invalid");
            }
            String code = randomValue();
            transaction.setAuthorizationCodeHash(InstallationAuthorizationValidator.sha256Base64Url(code));
            transaction.setConsented(true);
            store.updateFrontChannelTransaction(transaction, transaction.getVersion());
            URI redirect = UriBuilder.fromUri(transaction.getRedirectUri()).queryParam("code", code)
                    .queryParam("state", transaction.getState()).build();
            return Response.seeOther(redirect).header("Cache-Control", "no-store").build();
        } catch (FedSetupValidationException e) {
            return Response.status(Response.Status.BAD_REQUEST).type(MediaType.TEXT_HTML).entity(errorPage(e.getMessage())).build();
        }
    }

    /** Section 5.2 code exchange. It is intentionally a trust confirmation, never an OAuth token response. */
    @POST
    @Path("front/token")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response redeemFrontChannelTrust(@FormParam("grant_type") String grantType,
                                            @FormParam("code") String code,
                                            @FormParam("client_assertion_type") String clientAssertionType,
                                            @FormParam("client_assertion") String clientAssertion) {
        try {
            if (!"authorization_code".equals(grantType)
                    || !"urn:ietf:params:oauth:client-assertion-type:jwt-bearer".equals(clientAssertionType)) {
                throw new FedSetupValidationException("grant_type and client_assertion_type are invalid");
            }
            DirectInstallationTrust trust = FrontChannelTrustService.redeem(session, realm, store, code, clientAssertion, requestUri());
            FedSetupAudit.success(session, realm, org.keycloak.events.admin.OperationType.CREATE,
                    "trust_established_front_channel", trust, null);
            return Response.ok(trustConfirmation(trust)).type(MediaType.APPLICATION_JSON).header("Cache-Control", "no-store").build();
        } catch (FedSetupValidationException e) {
            return trustError(e);
        }
    }

    @POST
    @Path("connections")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response createConnection(@HeaderParam("Authorization") String authorization,
                                     @HeaderParam(FedSetupConstants.IDEMPOTENCY_HEADER) String idempotencyKey,
                                     String body) {
        try {
            InstallationConfigurationRequest request = parseRequest(body);
            validateSsoObjectCardinality(request, true);
            validateRequestEnvelope(request);
            String applicationTenantId = unverifiedApplicationTenantId(authorization);
            RequestAuthorization requestAuthorization = authorizeForIdempotency(authorization, "POST", body, request, applicationTenantId);
            validateExtensions(request, requestAuthorization.authorization().extensionProfiles());
            if (idempotencyKey == null || idempotencyKey.isBlank()) {
                throw new FedSetupValidationException("Idempotency-Key is required");
            }
            String existingId = store.getIdempotencyResult(idempotencyKey, requestAuthorization.trust().getApplicationTenantId(),
                    requestAuthorization.trust().getIdpIssuer(), requestAuthorization.authorization().requestHash());
            if (existingId != null) {
                // Section 7.1 requires the original successful POST result,
                // including its creation status and any first-create SCIM
                // bootstrap credential, for an idempotent retry.
                return response(store.requireConnection(existingId), Response.Status.CREATED, true);
            }
            if (store.findConnectionByTrust(requestAuthorization.trust().getId()) != null) {
                throw new FedSetupValidationException("A FedSetup Connection already exists for this Direct Installation Trust");
            }

            // Section 6.2 permits the one idempotent replay above.  Every
            // new create consumes its authorization before materializing any
            // Connection state, so a JWT cannot authorize a second create.
            InstallationAuthorizationValidator.consume(session, requestAuthorization.authorization());

            FedSetupConnection connection = toConnection(request, requestAuthorization.trust(), true,
                    requestAuthorization.authorization().extensionProfiles());
            storeOidcCredential(connection, request);
            if (isSsoConnection(connection)) {
                materializeBroker(connection, requestAuthorization.trust());
            }
            FedSetupConnection created = store.createConnection(connection);
            createScimServiceAndBootstrapCredential(created, requestAuthorization.trust());
            if (created.getScimServiceClientId() != null) {
                created = store.updateConnection(created, created.getVersion());
            }
            if (created.getIdJag() != null) {
                FedSetupIdJagConnectionService.materialize(session, realm, created, requestAuthorization.trust(), null);
                created = store.updateConnection(created, created.getVersion());
            }
            store.putIdempotencyResult(idempotencyKey, created.getApplicationTenantId(), created.getIdpIssuer(), created.getId(),
                    requestAuthorization.authorization().requestHash());
            FedSetupAudit.success(session, realm, org.keycloak.events.admin.OperationType.CREATE,
                    "connection_created", requestAuthorization.trust(), created);
            if (created.getCredentialReferenceId() != null || created.getScimBootstrapCredentialReferenceId() != null) {
                FedSetupAudit.success(session, realm, org.keycloak.events.admin.OperationType.ACTION,
                        "connection_credential_issued", requestAuthorization.trust(), created);
            }
            if (created.getIdJag() != null) {
                FedSetupAudit.success(session, realm, org.keycloak.events.admin.OperationType.ACTION,
                        "id_jag_materialized", requestAuthorization.trust(), created);
            }
            return response(created, Response.Status.CREATED, true);
        } catch (FedSetupValidationException e) {
            return error(Response.Status.BAD_REQUEST, e.getMessage());
        }
    }

    @GET
    @Path("connections/{connectionId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getConnection(@PathParam("connectionId") String connectionId,
                                  @QueryParam("application_tenant_id") String applicationTenantId,
                                  @HeaderParam("Authorization") String authorization,
                                  String body) {
        try {
            requireNoBody(body, "GET request");
            FedSetupConnection connection = store.requireConnection(connectionId);
            if (applicationTenantId != null && !connection.getApplicationTenantId().equals(applicationTenantId)) {
                throw new NotFoundException();
            }
            DirectInstallationTrust trust = store.requireTrust(connection.getTrustId());
            InstallationAuthorizationValidator.validate(session, trust, authorization, "GET", requestUri(), "", connection.getApplicationTenantId(),
                    Set.of(), Set.of());
            return response(connection, Response.Status.OK);
        } catch (NotFoundException e) {
            throw e;
        } catch (FedSetupValidationException e) {
            return error(Response.Status.BAD_REQUEST, e.getMessage());
        }
    }

    @PATCH
    @Path("connections/{connectionId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateConnection(@PathParam("connectionId") String connectionId,
                                     @HeaderParam("Authorization") String authorization,
                                     @HeaderParam(FedSetupConstants.IF_MATCH_HEADER) String ifMatch,
                                     String body) {
        try {
            FedSetupConnection current = store.requireConnection(connectionId);
            InstallationConfigurationRequest request = parseRequest(body);
            validateSsoObjectCardinality(request, false);
            validateRequestEnvelope(request);
            if (request.getApplicationTenantId() != null && !current.getApplicationTenantId().equals(request.getApplicationTenantId())) {
                throw new NotFoundException();
            }
            RequestAuthorization requestAuthorization = authorize(authorization, "PATCH", body, request, current.getApplicationTenantId());
            validateExtensions(request, requestAuthorization.authorization().extensionProfiles());
            if (!current.getTrustId().equals(requestAuthorization.trust().getId())) {
                throw new FedSetupValidationException("Connection is not bound to this Direct Installation Trust");
            }
            requireEtag(ifMatch, current.getVersion());
            boolean replacesSso = request.getProtocol() != null;
            if ((replacesSso && !current.getProtocol().equals(request.getProtocol()))
                    || (request.getBrokerAlias() != null && !Objects.equals(current.getBrokerAlias(), request.getBrokerAlias()))) {
                throw new FedSetupValidationException("A FedSetup Connection cannot change protocol or broker alias");
            }
            if (request.getCredentialVaultReference() != null) {
                throw new FedSetupValidationException("An inbound Configuration PATCH cannot supply a Keycloak Vault reference");
            }
            boolean rotatesOidcSecret = oidcClientSecret(request) != null;
            boolean removeScim = request.getRemove().contains("scim");
            boolean removeIdJag = request.getRemove().contains("id_jag");
            boolean replacesIdJag = request.getIdJag() != null;
            if (removeScim && request.getScim() != null) {
                throw new FedSetupValidationException("A request cannot supply and remove scim in the same PATCH");
            }
            if (removeIdJag && replacesIdJag) {
                throw new FedSetupValidationException("A request cannot supply and remove id_jag in the same PATCH");
            }
            boolean addsScim = request.getScim() != null && !current.getCapabilities().contains("scim");
            mergePatchWithCurrentConnection(request, current, replacesSso, removeScim, removeIdJag);
            Set<String> extensionProfiles = new java.util.LinkedHashSet<>(current.getExtensionProfiles());
            extensionProfiles.addAll(requestAuthorization.authorization().extensionProfiles());
            FedSetupConnection updated = toConnection(request, requestAuthorization.trust(), replacesSso, extensionProfiles, current);
            updated.setId(current.getId());
            updated.setBrokerAlias(current.getBrokerAlias());
            // client_secret is write-only: an omitted value retains the
            // existing encrypted record, while a supplied value rotates it.
            // A Connection that previously used private_key_jwt/none needs a
            // new record the first time a secret is supplied.
            updated.setCredentialReferenceId(credentialReferenceForPatch(current.getCredentialReferenceId(),
                    updated.getCredentialReferenceId(), rotatesOidcSecret));
            updated.setScimBootstrapCredentialReferenceId(current.getScimBootstrapCredentialReferenceId());
            if (!replacesSso) {
                updated.setSamlAttributeMapping(current.getSamlAttributeMapping());
                updated.setSamlMetadataUrl(current.getSamlMetadataUrl());
            }
            if (!replacesIdJag && !removeIdJag) {
                updated.setIdJag(current.getIdJag());
                updated.setIdJagIdentityProviderAlias(current.getIdJagIdentityProviderAlias());
            } else if (removeIdJag) {
                FedSetupIdJagConnectionService.deactivate(realm, current);
                updated.setIdJag(null);
                updated.setIdJagIdentityProviderAlias(null);
            }
            if (request.getScim() == null && !removeScim) {
                updated.setScimFeatures(current.getScimFeatures());
                updated.setScimBaseUri(current.getScimBaseUri());
                updated.setScimTokenEndpoint(current.getScimTokenEndpoint());
                updated.setScimServiceClientId(current.getScimServiceClientId());
            } else if (removeScim) {
                FedSetupScimConnectionService.deactivate(realm, current);
                store.deleteCredentialReference(current.getScimBootstrapCredentialReferenceId());
                updated.setScimFeatures(Set.of());
                updated.setScimBaseUri(null);
                updated.setScimTokenEndpoint(null);
                updated.setScimServiceClientId(null);
                updated.setScimBootstrapCredentialReferenceId(null);
            } else if (!addsScim) {
                updated.setScimBaseUri(current.getScimBaseUri());
                updated.setScimTokenEndpoint(current.getScimTokenEndpoint());
                updated.setScimServiceClientId(current.getScimServiceClientId());
            }
            if (rotatesOidcSecret) {
                storeOidcCredential(updated, request);
            }
            if (isSsoConnection(updated)) {
                materializeBroker(updated, requestAuthorization.trust());
            }
            if (replacesIdJag) {
                FedSetupIdJagConnectionService.materialize(session, realm, updated, requestAuthorization.trust(), current);
            }
            FedSetupConnection persisted = store.updateConnection(updated, current.getVersion());
            if (addsScim) {
                createScimServiceAndBootstrapCredential(persisted, requestAuthorization.trust());
                persisted = store.updateConnection(persisted, persisted.getVersion());
            }
            FedSetupAudit.success(session, realm, org.keycloak.events.admin.OperationType.UPDATE,
                    "connection_updated", requestAuthorization.trust(), persisted);
            if (rotatesOidcSecret) {
                FedSetupAudit.success(session, realm, org.keycloak.events.admin.OperationType.ACTION,
                        "connection_credential_rotated", requestAuthorization.trust(), persisted);
            }
            if (removeScim) {
                FedSetupAudit.success(session, realm, org.keycloak.events.admin.OperationType.ACTION,
                        "scim_credential_revoked", requestAuthorization.trust(), persisted);
            } else if (addsScim) {
                FedSetupAudit.success(session, realm, org.keycloak.events.admin.OperationType.ACTION,
                        "scim_credential_issued", requestAuthorization.trust(), persisted);
            }
            if (removeIdJag) {
                FedSetupAudit.success(session, realm, org.keycloak.events.admin.OperationType.ACTION,
                        "id_jag_deactivated", requestAuthorization.trust(), persisted);
            } else if (replacesIdJag) {
                FedSetupAudit.success(session, realm, org.keycloak.events.admin.OperationType.ACTION,
                        "id_jag_materialized", requestAuthorization.trust(), persisted);
            }
            return response(persisted, Response.Status.OK, addsScim);
        } catch (NotFoundException e) {
            throw e;
        } catch (FedSetupValidationException e) {
            return error(e.getMessage().startsWith("ETag") ? Response.Status.PRECONDITION_FAILED : Response.Status.BAD_REQUEST, e.getMessage());
        }
    }

    @DELETE
    @Path("connections/{connectionId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response deactivateConnection(@PathParam("connectionId") String connectionId,
                                         @QueryParam("application_tenant_id") String applicationTenantId,
                                         @HeaderParam("Authorization") String authorization,
                                         String body) {
        try {
            requireNoBody(body, "DELETE request");
            FedSetupConnection connection = store.requireConnection(connectionId);
            if (applicationTenantId != null && !connection.getApplicationTenantId().equals(applicationTenantId)) {
                throw new NotFoundException();
            }
            DirectInstallationTrust trust = store.requireTrust(connection.getTrustId());
            InstallationAuthorizationValidator.validate(session, trust, authorization, "DELETE", requestUri(), "", connection.getApplicationTenantId(),
                    Set.of(), Set.of());
            if (!blank(connection.getBrokerAlias())) {
                IdentityProviderModel provider = realm.getIdentityProviderByAlias(connection.getBrokerAlias());
                if (provider != null) {
                    provider.setEnabled(false);
                    realm.updateIdentityProvider(provider);
                }
                removeFedSetupSamlMappers(connection.getBrokerAlias());
            }
            FedSetupIdJagConnectionService.deactivate(realm, connection);
            FedSetupScimConnectionService.deactivate(realm, connection);
            store.deleteCredentialReference(connection.getScimBootstrapCredentialReferenceId());
            store.deleteCredentialReference(connection.getCredentialReferenceId());
            connection.setScimBootstrapCredentialReferenceId(null);
            connection.setCredentialReferenceId(null);
            connection.setStatus("DEACTIVATED");
            FedSetupConnection updated = store.updateConnection(connection, connection.getVersion());
            FedSetupAudit.success(session, realm, org.keycloak.events.admin.OperationType.DELETE,
                    "connection_deactivated", trust, updated);
            FedSetupAudit.success(session, realm, org.keycloak.events.admin.OperationType.ACTION,
                    "connection_credentials_revoked", trust, updated);
            return Response.noContent().header(FedSetupConstants.ETAG_HEADER, etag(updated.getVersion())).build();
        } catch (NotFoundException e) {
            throw e;
        } catch (FedSetupValidationException e) {
            return error(e.getMessage().startsWith("ETag") ? Response.Status.PRECONDITION_FAILED : Response.Status.BAD_REQUEST, e.getMessage());
        }
    }

    private FedSetupConfigurationProfile requireApplicationProfile(String applicationTenantId) {
        FedSetupConfigurationProfile profile = store.getApplicationProfile();
        if (profile == null || !Objects.equals(profile.getApplicationTenantId(), applicationTenantId)) {
            throw new FedSetupValidationException("No Application integration profile matches application_tenant_id");
        }
        return profile;
    }

    private ClientModel frontChannelLoginClient() {
        ClientModel client = realm.getClientByClientId(FedSetupConstants.FRONT_CHANNEL_INTERNAL_CLIENT);
        String callback = FedSetupUrls.frontLoginCallback(session.getContext().getUri(UrlType.FRONTEND), realm);
        if (client == null) {
            client = realm.addClient(UUID.randomUUID().toString(), FedSetupConstants.FRONT_CHANNEL_INTERNAL_CLIENT);
            client.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
            client.setEnabled(true);
            client.setPublicClient(true);
            client.setStandardFlowEnabled(true);
            client.setImplicitFlowEnabled(false);
            client.setDirectAccessGrantsEnabled(false);
            client.setServiceAccountsEnabled(false);
            client.setRedirectUris(Set.of(callback));
        } else if (!client.getRedirectUris().equals(Set.of(callback)) || !client.isStandardFlowEnabled() || !client.isPublicClient()) {
            throw new FedSetupValidationException("The reserved FedSetup front-channel login client has an unsafe configuration");
        }
        return client;
    }

    private void requireApplicationRealmAdministrator() {
        AuthenticationManager.AuthResult authenticated = AuthenticationManager.authenticateIdentityCookie(session, realm, true);
        if (authenticated == null || authenticated.user() == null) {
            throw new FedSetupValidationException("Application Tenant administrator authentication is required");
        }
        ClientModel management = realm.getClientByClientId(Constants.REALM_MANAGEMENT_CLIENT_ID);
        RoleModel realmAdmin = management == null ? null : management.getRole(AdminRoles.REALM_ADMIN);
        UserModel user = authenticated.user();
        if (realmAdmin == null || !user.hasRole(realmAdmin)) {
            throw new FedSetupValidationException("The authenticated user is not an Application Tenant administrator");
        }
    }

    private Response outboundFrontChannelCallback(FedSetupFrontChannelTransaction transaction, String code) {
        try {
            DirectInstallationTrust trust = OutboundTrustDispatcher.redeemFrontChannelCode(session, realm, store, transaction, code);
            return Response.ok(successPage("Direct Installation Trust established for " + trust.getApplicationTenantId() + "."))
                    .type(MediaType.TEXT_HTML).header("Cache-Control", "no-store").build();
        } catch (FedSetupValidationException e) {
            return Response.status(Response.Status.BAD_REQUEST).type(MediaType.TEXT_HTML).entity(errorPage(e.getMessage())).build();
        }
    }

    private Map<String, Object> trustConfirmation(DirectInstallationTrust trust) {
        return Map.of(
                "application_tenant_id", trust.getApplicationTenantId(),
                "idp_issuer", trust.getIdpIssuer(),
                "capabilities", trust.getCapabilities(),
                "provider_delegation_profiles", trust.getProviderDelegationProfiles(),
                "federation_extension_profiles", trust.getExtensionProfiles());
    }

    private Response trustError(FedSetupValidationException error) {
        String message = error.getMessage() == null ? "Trust request was rejected" : error.getMessage();
        return protocolError(Response.Status.BAD_REQUEST, message);
    }

    private static Set<String> terms(String raw) {
        if (raw == null || raw.isBlank()) return Set.of();
        Set<String> result = new java.util.LinkedHashSet<>();
        for (String value : raw.split(",", -1)) {
            String term = value.trim();
            if (term.isEmpty()) throw new FedSetupValidationException("Requested capability or profile contains an empty value");
            result.add(term);
        }
        return result;
    }

    private static String randomValue() {
        byte[] value = new byte[32];
        RANDOM.nextBytes(value);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private static boolean constantTimeEquals(String first, String second) {
        if (first == null || second == null) return false;
        return java.security.MessageDigest.isEqual(first.getBytes(StandardCharsets.US_ASCII), second.getBytes(StandardCharsets.US_ASCII));
    }

    private String consentPage(FedSetupFrontChannelTransaction transaction) {
        String action = FedSetupUrls.frontApprove(session.getContext().getUri(UrlType.FRONTEND), realm);
        return "<!doctype html><html><head><meta charset=\"utf-8\"><title>Approve Direct Installation Trust</title>"
                + "<style>body{font-family:sans-serif;max-width:48rem;margin:3rem auto}code{word-break:break-all}</style></head><body>"
                + "<h1>Approve Direct Installation Trust</h1><p>An IdP Tenant requests a trust limited to this Application Tenant.</p>"
                + "<dl><dt>Application Tenant</dt><dd>" + html(transaction.getApplicationTenantId()) + "</dd>"
                + "<dt>IdP issuer</dt><dd><code>" + html(transaction.getIdpIssuer()) + "</code></dd>"
                + "<dt>Installation runtime CIMD URI</dt><dd><code>" + html(transaction.getCimdUri()) + "</code></dd>"
                + "<dt>Capabilities</dt><dd>" + html(String.join(", ", transaction.getCapabilities())) + "</dd>"
                + "</dl><form method=\"post\" action=\"" + html(action) + "\">"
                + "<input type=\"hidden\" name=\"transaction\" value=\"" + html(transaction.getId()) + "\">"
                + "<input type=\"hidden\" name=\"consent_nonce\" value=\"" + html(transaction.getConsentNonce()) + "\">"
                + "<button type=\"submit\">Approve trust</button></form></body></html>";
    }

    private static String successPage(String message) {
        return "<!doctype html><html><head><meta charset=\"utf-8\"><title>FedSetup complete</title></head><body><h1>FedSetup complete</h1><p>"
                + html(message) + "</p></body></html>";
    }

    private static String errorPage(String message) {
        return "<!doctype html><html><head><meta charset=\"utf-8\"><title>FedSetup failed</title></head><body><h1>FedSetup failed</h1><p>"
                + html(message) + "</p></body></html>";
    }

    private static String html(String value) {
        if (value == null) return "";
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }

    /** GET, DELETE, and the back-channel trust request bind a zero-byte body. */
    static void requireNoBody(String body, String requestType) {
        if (body != null && !body.isEmpty()) {
            throw new FedSetupValidationException(requestType + " must not contain a body");
        }
    }

    private RequestAuthorization authorize(String authorization, String method, String body, InstallationConfigurationRequest request,
                                           String applicationTenantId) {
        if (applicationTenantId == null || applicationTenantId.isBlank()) {
            throw new FedSetupValidationException("Installation Authorization is missing application_tenant_id");
        }
        String issuer = unverifiedIssuer(authorization);
        DirectInstallationTrust trust = store.findTrustByCimdUri(applicationTenantId, issuer);
        if (trust == null) {
            // Existing preview records use the IdP issuer as the JWT issuer and
            // retain the legacy pinned-JWK validation path.
            trust = store.findTrust(applicationTenantId, issuer);
        }
        if (trust == null) {
            throw new FedSetupValidationException("No Direct Installation Trust exists for this Application Tenant and installation runtime");
        }
        InstallationAuthorizationValidator.ValidatedAuthorization validated = InstallationAuthorizationValidator.validate(session, trust, authorization,
                method, requestUri(), body, applicationTenantId, request.requestedCapabilities(), request.getExtensionProfiles());
        return new RequestAuthorization(trust, validated);
    }

    /**
     * Verifies the POST before using its tenant binding for idempotency, but
     * deliberately delays replay consumption until no cached success exists.
     */
    private RequestAuthorization authorizeForIdempotency(String authorization, String method, String body, InstallationConfigurationRequest request,
                                                         String applicationTenantId) {
        if (applicationTenantId == null || applicationTenantId.isBlank()) {
            throw new FedSetupValidationException("Installation Authorization is missing application_tenant_id");
        }
        String issuer = unverifiedIssuer(authorization);
        DirectInstallationTrust trust = store.findTrustByCimdUri(applicationTenantId, issuer);
        if (trust == null) {
            trust = store.findTrust(applicationTenantId, issuer);
        }
        if (trust == null) {
            throw new FedSetupValidationException("No Direct Installation Trust exists for this Application Tenant and installation runtime");
        }
        InstallationAuthorizationValidator.ValidatedAuthorization validated = InstallationAuthorizationValidator.validateForIdempotency(session, trust,
                authorization, method, requestUri(), body, applicationTenantId, request.requestedCapabilities(), request.getExtensionProfiles());
        return new RequestAuthorization(trust, validated);
    }

    private InstallationConfigurationRequest parseRequest(String body) {
        if (body == null || body.isBlank()) {
            throw new FedSetupValidationException("A JSON configuration request is required");
        }
        try {
            JsonNode document = JsonSerialization.mapper.readTree(body);
            if (document == null || !document.isObject()) {
                throw new FedSetupValidationException("Configuration request must be a JSON object");
            }
            if (document.has("connection_id")) {
                throw new FedSetupValidationException("connection_id must not appear in a Configuration Request body");
            }
            return JsonSerialization.readValue(body, InstallationConfigurationRequest.class);
        } catch (FedSetupValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new FedSetupValidationException("Invalid JSON configuration request", e);
        }
    }

    /** Enforces Section 7.1 before PATCH merges omitted capability objects. */
    static void validateSsoObjectCardinality(InstallationConfigurationRequest request, boolean creation) {
        boolean oidc = request.getOidc() != null;
        boolean saml = request.getSaml() != null;
        if (oidc && saml) {
            throw new FedSetupValidationException("Configuration request must not contain both oidc and saml");
        }
        if (creation && !oidc && !saml
                && (request.getIdJag() == null || !"workload_principal".equals(request.getIdJag().getRequesterType()))) {
            throw new FedSetupValidationException("A Connection creation request must contain exactly one of oidc or saml, unless it creates a workload_principal id_jag client");
        }
    }

    /** Validates required, sender-identifying fields before PATCH can merge omitted capability objects. */
    static void validateRequestEnvelope(InstallationConfigurationRequest request) {
        if (request.getIdpIssuer() == null || request.getIdpIssuer().isBlank()
                || request.getIdpDomain() == null || request.getIdpDomain().isBlank()) {
            throw new FedSetupValidationException("idp_issuer and idp_domain are required");
        }
    }

    /** Section 7.1 ignores unauthorized extension keys but rejects authorized, unsupported ones. */
    private static void validateExtensions(InstallationConfigurationRequest request, Set<String> authorizedProfiles) {
        for (String profile : request.getExtensions().keySet()) {
            if (authorizedProfiles.contains(profile)) {
                throw new FedSetupValidationException("Configuration contains an authorized extension that this Keycloak preview does not implement");
            }
        }
    }

    private String unverifiedIssuer(String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            throw new FedSetupValidationException("A Bearer Installation Authorization is required");
        }
        try {
            return new JWSInput(authorization.substring("Bearer ".length())).readJsonContent(org.keycloak.representations.JsonWebToken.class).getIssuer();
        } catch (Exception e) {
            throw new FedSetupValidationException("Invalid Installation Authorization", e);
        }
    }

    private String unverifiedApplicationTenantId(String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            throw new FedSetupValidationException("A Bearer Installation Authorization is required");
        }
        try {
            Object value = new JWSInput(authorization.substring("Bearer ".length())).readJsonContent(org.keycloak.representations.JsonWebToken.class)
                    .getOtherClaims().get("application_tenant_id");
            if (!(value instanceof String tenant) || tenant.isBlank()) {
                throw new FedSetupValidationException("Installation Authorization is missing application_tenant_id");
            }
            return tenant;
        } catch (FedSetupValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new FedSetupValidationException("Invalid Installation Authorization", e);
        }
    }

    private FedSetupConnection toConnection(InstallationConfigurationRequest request, DirectInstallationTrust trust) {
        return toConnection(request, trust, true, request.getExtensionProfiles());
    }

    private FedSetupConnection toConnection(InstallationConfigurationRequest request, DirectInstallationTrust trust,
                                            boolean requiresNewSsoCredential, Set<String> authorizedExtensionProfiles) {
        return toConnection(request, trust, requiresNewSsoCredential, authorizedExtensionProfiles, null);
    }

    private FedSetupConnection toConnection(InstallationConfigurationRequest request, DirectInstallationTrust trust,
                                            boolean requiresNewSsoCredential, Set<String> authorizedExtensionProfiles,
                                            FedSetupConnection previous) {
        validateRequest(request, trust, requiresNewSsoCredential);
        FedSetupConnection connection = new FedSetupConnection();
        connection.setId(UUID.randomUUID().toString());
        connection.setTrustId(trust.getId());
        connection.setApplicationTenantId(trust.getApplicationTenantId());
        connection.setIdpIssuer(trust.getIdpIssuer());
        connection.setIdpDomain(request.getIdpDomain());
        connection.setProtocol(request.getProtocol() == null ? "id_jag" : request.getProtocol());
        connection.setBrokerAlias(isSsoConnection(connection) ? alias(request, connection.getId()) : null);
        connection.setStatus("ACTIVE");
        Map<String, String> sso = new LinkedHashMap<>(request.getSso());
        // The body may legitimately contain the core OIDC client_secret, but
        // Connection state and broker configuration retain only an encrypted
        // credential record and an opaque reference.
        sso.remove("client_secret");
        connection.setSso(sso);
        if (request.getSaml() != null) {
            connection.setSamlAttributeMapping(request.getSaml().getAttributeMapping());
            connection.setSamlMetadataUrl(request.getSaml().getIdpMetadataUrl());
        }
        connection.setCapabilities(request.requestedCapabilities());
        connection.setExtensionProfiles(authorizedExtensionProfiles);
        if (request.getScim() != null) connection.setScimFeatures(request.getScim().getFeatures());
        if (request.getIdJag() != null) {
            connection.setIdJag(FedSetupIdJagConnectionService.validate(session, realm, store.getApplicationProfile(), trust,
                    connection, request.getIdJag(), previous == null ? null : previous.getIdJag()));
        }
        if (oidcClientSecret(request) != null || request.getCredentialVaultReference() != null) {
            connection.setCredentialReferenceId(UUID.randomUUID().toString());
        }
        return connection;
    }

    /** Applies Section 9's replace-present, retain-omitted PATCH semantics. */
    private void mergePatchWithCurrentConnection(InstallationConfigurationRequest request, FedSetupConnection current,
                                                 boolean replacesSso, boolean removeScim, boolean removeIdJag) {
        if (!replacesSso) {
            if (isSsoConnection(current)) {
                request.setProtocol(current.getProtocol());
                request.setSso(current.getSso());
            } else {
                request.setProtocol(null);
                request.setSso(Map.of());
                if (request.getIdJag() == null && !removeIdJag) {
                    // A Connection without SSO is valid only while its
                    // workload-principal ID-JAG capability remains present.
                    // This internal merge preserves it for validation; it
                    // does not turn an omitted PATCH object into a replacement.
                    request.setIdJag(current.getIdJag());
                }
            }
            // This synthesized object is internal PATCH context, not an
            // additional caller-supplied SSO object.  It preserves the fact
            // that the retained SAML keys come from the Connection's already
            // approved metadata source rather than its original static trust
            // certificate.
            if ("saml".equals(current.getProtocol()) && !blank(current.getSamlMetadataUrl())) {
                InstallationConfigurationRequest.SamlConfiguration retained = new InstallationConfigurationRequest.SamlConfiguration();
                retained.setIdpMetadataUrl(current.getSamlMetadataUrl());
                request.setSaml(retained);
            }
        }
        Set<String> capabilities = new java.util.LinkedHashSet<>(current.getCapabilities());
        if (request.getScim() != null) capabilities.add("scim");
        if (removeScim) capabilities.remove("scim");
        if (request.getIdJag() != null) capabilities.add("id_jag");
        if (removeIdJag) capabilities.remove("id_jag");
        request.setCapabilities(capabilities);
        request.setExtensionProfiles(current.getExtensionProfiles());
    }

    private void validateRequest(InstallationConfigurationRequest request, DirectInstallationTrust trust,
                                 boolean requiresNewSsoCredential) {
        if (request.getProviderDelegation() != null
                || request.getRemove().stream().anyMatch(value -> !Set.of("scim", "id_jag").contains(value))) {
            throw new FedSetupValidationException("Provider Delegation and unsupported capability removals are not implemented by this Keycloak preview");
        }
        if (request.getRemove().contains("scim") && request.getScim() != null) {
            throw new FedSetupValidationException("A request cannot supply and remove scim in the same operation");
        }
        if (request.getScim() != null) {
            Set<String> supported = Set.of("PUSH_NEW_USERS", "PUSH_USER_DEACTIVATION", "REACTIVATE_USERS", "PUSH_PROFILE_UPDATES", "PUSH_GROUPS");
            if (request.getScim().getFeatures().isEmpty() || !supported.containsAll(request.getScim().getFeatures())) {
                throw new FedSetupValidationException("Requested SCIM feature is not supported by this Keycloak preview");
            }
        }
        if (request.getRemove().contains("id_jag") && request.getIdJag() != null) {
            throw new FedSetupValidationException("A request cannot supply and remove id_jag in the same operation");
        }
        if (request.getProtocol() == null) {
            if (request.getIdJag() == null || !"workload_principal".equals(request.getIdJag().getRequesterType())) {
                throw new FedSetupValidationException("Only a workload_principal id_jag configuration may omit OIDC or SAML SSO");
            }
        } else if (!Set.of("oidc", "saml").contains(request.getProtocol())) {
            throw new FedSetupValidationException("Only oidc and saml SSO protocols are supported");
        }
        if (!trust.getIdpIssuer().equals(FedSetupUri.canonicalize(request.getIdpIssuer()))) {
            throw new FedSetupValidationException("idp_issuer does not match Direct Installation Trust");
        }
        if (request.getIdpDomain() == null || request.getIdpDomain().isBlank()) {
            throw new FedSetupValidationException("idp_domain is required");
        }
        Set<String> allowed = "oidc".equals(request.getProtocol()) ? OIDC_SSO_FIELDS
                : "saml".equals(request.getProtocol()) ? SAML_SSO_FIELDS : Set.of();
        if (!allowed.containsAll(request.getSso().keySet())) {
            throw new FedSetupValidationException("Configuration contains an unsupported SSO field");
        }
        if (request.getCredentialVaultReference() != null && !VAULT_REFERENCE.matcher(request.getCredentialVaultReference()).matches()) {
            throw new FedSetupValidationException("Credentials must be a Keycloak Vault reference");
        }
        if ("oidc".equals(request.getProtocol())) {
            if (!trust.getIdpIssuer().equals(FedSetupUri.canonicalize(required(request.getSso(), "issuer")))) {
                throw new FedSetupValidationException("OIDC issuer does not match Direct Installation Trust");
            }
            required(request.getSso(), "client_id");
            if (trust.getInstallationRuntimeCimdUri() == null) {
                required(request.getSso(), "authorization_endpoint");
                required(request.getSso(), "token_endpoint");
                validateIssuerBoundEndpoint(request.getSso(), "authorization_endpoint", trust.getIdpIssuer());
                validateIssuerBoundEndpoint(request.getSso(), "token_endpoint", trust.getIdpIssuer());
                validateIssuerBoundEndpoint(request.getSso(), "userinfo_endpoint", trust.getIdpIssuer());
                validateIssuerBoundEndpoint(request.getSso(), "logout_endpoint", trust.getIdpIssuer());
            } else {
                // Runtime endpoints and signing keys come only from the issuer
                // already bound into this trust, never from a push body.
                FedSetupOidcMetadataResolver.resolve(session, trust.getIdpIssuer());
            }
            if (trust.getInstallationRuntimeCimdUri() == null && trust.getRuntimeJwksUri() == null) {
                throw new FedSetupValidationException("Direct Installation Trust has no approved OIDC runtime JWKS URI");
            }
            String authenticationMethod = request.getSso().getOrDefault("client_auth_method", "client_secret_basic");
            if (!Set.of("client_secret_basic", "client_secret_post", "private_key_jwt", "none").contains(authenticationMethod)) {
                throw new FedSetupValidationException("OIDC token_endpoint_auth_method is not supported");
            }
            rejectExplicitEmptyOidcClientSecret(request);
            String clientSecret = oidcClientSecret(request);
            if (("private_key_jwt".equals(authenticationMethod) || "none".equals(authenticationMethod)) && clientSecret != null) {
                throw new FedSetupValidationException("OIDC client_secret must be omitted for private_key_jwt or none");
            }
            if (("client_secret_basic".equals(authenticationMethod) || "client_secret_post".equals(authenticationMethod))
                    && requiresNewSsoCredential && clientSecret == null && request.getCredentialVaultReference() == null) {
                throw new FedSetupValidationException("OIDC client_secret is required for the selected token endpoint authentication method");
            }
            if (clientSecret != null && request.getCredentialVaultReference() != null) {
                throw new FedSetupValidationException("OIDC client_secret and a credential Vault reference cannot both be supplied");
            }
        } else if ("saml".equals(request.getProtocol())) {
            required(request.getSso(), "entity_id");
            required(request.getSso(), "single_sign_on_service");
            validateIssuerBoundEndpoint(request.getSso(), "single_sign_on_service", trust.getIdpIssuer());
            validateIssuerBoundEndpoint(request.getSso(), "single_logout_service", trust.getIdpIssuer());
            validateSamlCertificate(required(request.getSso(), "signing_certificate"));
            InstallationConfigurationRequest.SamlConfiguration saml = request.getSaml();
            if (saml != null) {
                validateSamlAttributeMapping(saml.getAttributeMapping());
                if (!blank(saml.getIdpMetadataUrl())) {
                    saml.setIdpMetadataUrl(validateSamlMetadataUrl(saml.getIdpMetadataUrl(), trust.getIdpIssuer()));
                }
            }
            FedSetupConfigurationProfile profile = store.getApplicationProfile();
            boolean sloSupported = profile != null && profile.isSamlSpInitiatedSloSupported();
            if (sloSupported) {
                required(request.getSso(), "single_logout_service");
            } else if (saml != null && request.getSso().containsKey("single_logout_service")) {
                throw new FedSetupValidationException("SAML Single Logout is not enabled by this Application realm policy");
            }
            if (trust.getInstallationRuntimeCimdUri() == null && (trust.getRuntimeSigningCertificate() == null || trust.getRuntimeSigningCertificate().isBlank())) {
                throw new FedSetupValidationException("Direct Installation Trust has no approved SAML signing certificate");
            }
            String suppliedCertificate = request.getSso().get("signing_certificate");
            // A stored, issuer-bound metadata URL is an approved dynamic key
            // source.  Without one, the original trust-pinned certificate
            // remains the only permitted SAML signing key.
            boolean usesTrustedMetadata = saml != null && !blank(saml.getIdpMetadataUrl());
            if (trust.getInstallationRuntimeCimdUri() == null && !usesTrustedMetadata && suppliedCertificate != null
                    && !trust.getRuntimeSigningCertificate().equals(suppliedCertificate)) {
                throw new FedSetupValidationException("SAML signing certificate does not match Direct Installation Trust");
            }
        }
    }

    private static boolean isSsoConnection(FedSetupConnection connection) {
        return connection != null && Set.of("oidc", "saml").contains(connection.getProtocol());
    }

    private void materializeBroker(FedSetupConnection connection, DirectInstallationTrust trust) {
        IdentityProviderModel provider = realm.getIdentityProviderByAlias(connection.getBrokerAlias());
        if (provider != null && store.getConnections().stream().noneMatch(existing -> existing.getId().equals(connection.getId())
                && existing.getBrokerAlias().equals(connection.getBrokerAlias()))) {
            throw new FedSetupValidationException("Identity broker alias is already in use");
        }
        if (provider == null) {
            provider = new IdentityProviderModel();
            provider.setAlias(connection.getBrokerAlias());
        }
        provider.setEnabled("ACTIVE".equals(connection.getStatus()));
        provider.setDisplayName("FedSetup " + trust.getIdpIssuer());
        provider.setProviderId("oidc".equals(connection.getProtocol())
                ? FedSetupOIDCIdentityProviderFactory.PROVIDER_ID : connection.getProtocol());
        provider.setConfig("oidc".equals(connection.getProtocol()) ? oidcBrokerConfig(connection, trust) : samlBrokerConfig(connection, trust));
        if (realm.getIdentityProviderByAlias(connection.getBrokerAlias()) == null) {
            realm.addIdentityProvider(provider);
        } else {
            realm.updateIdentityProvider(provider);
        }
        if ("saml".equals(connection.getProtocol())) {
            materializeSamlMappers(connection);
        }
    }

    private Map<String, String> oidcBrokerConfig(FedSetupConnection connection, DirectInstallationTrust trust) {
        Map<String, String> config = new LinkedHashMap<>();
        Map<String, String> sso = connection.getSso();
        FedSetupOidcMetadataResolver.RuntimeMetadata discovered = trust.getInstallationRuntimeCimdUri() == null ? null
                : FedSetupOidcMetadataResolver.resolve(session, trust.getIdpIssuer());
        config.put("issuer", trust.getIdpIssuer());
        config.put("authorizationUrl", discovered == null ? FedSetupUri.canonicalize(sso.get("authorization_endpoint")) : discovered.authorizationEndpoint());
        config.put("tokenUrl", discovered == null ? FedSetupUri.canonicalize(sso.get("token_endpoint")) : discovered.tokenEndpoint());
        config.put("clientId", sso.get("client_id"));
        config.put("jwksUrl", discovered == null ? trust.getRuntimeJwksUri() : discovered.jwksUri());
        config.put("useJwksUrl", "true");
        config.put("validateSignature", "true");
        if (discovered == null) {
            optionalUri(sso, "userinfo_endpoint", config, "userInfoUrl");
            optionalUri(sso, "logout_endpoint", config, "logoutUrl");
        } else {
            if (discovered.userinfoEndpoint() != null) config.put("userInfoUrl", discovered.userinfoEndpoint());
            if (discovered.logoutEndpoint() != null) config.put("logoutUrl", discovered.logoutEndpoint());
        }
        optional(sso, "default_scope", config, "defaultScope");
        optional(sso, "client_auth_method", config, "clientAuthMethod");
        if (connection.getCredentialReferenceId() != null) {
            FedSetupCredentialReference credential = store.getCredentialReference(connection.getCredentialReferenceId());
            String reference = credential == null ? null : credential.getVaultReference();
            if (reference == null && credential != null && credential.getEncryptedSecret() != null) {
                reference = FedSetupCredentialResolver.reference(credential.getId());
            }
            if (reference != null) {
                config.put("clientSecret", reference);
            }
        }
        return config;
    }

    private Map<String, String> samlBrokerConfig(FedSetupConnection connection, DirectInstallationTrust trust) {
        Map<String, String> config = new LinkedHashMap<>();
        Map<String, String> sso = connection.getSso();
        config.put("idpEntityId", sso.get("entity_id"));
        config.put("singleSignOnServiceUrl", FedSetupUri.canonicalize(sso.get("single_sign_on_service")));
        config.put("signingCertificate", trust.getInstallationRuntimeCimdUri() == null ? trust.getRuntimeSigningCertificate()
                : required(sso, "signing_certificate"));
        config.put("validateSignature", "true");
        optionalUri(sso, "single_logout_service", config, "singleLogoutServiceUrl");
        optional(sso, "name_id_format", config, "nameIDPolicyFormat");
        return config;
    }

    /** Replaces only FedSetup-owned SAML attribute mappers for this broker. */
    private void materializeSamlMappers(FedSetupConnection connection) {
        removeFedSetupSamlMappers(connection.getBrokerAlias());
        for (Map.Entry<String, String> mapping : connection.getSamlAttributeMapping().entrySet()) {
            IdentityProviderMapperModel mapper = new IdentityProviderMapperModel();
            mapper.setName(SAML_MAPPER_PREFIX + mapping.getKey());
            mapper.setIdentityProviderAlias(connection.getBrokerAlias());
            mapper.setIdentityProviderMapper(UserAttributeMapper.PROVIDER_ID);
            Map<String, String> config = new LinkedHashMap<>();
            config.put(UserAttributeMapper.ATTRIBUTE_NAME, mapping.getValue());
            config.put(UserAttributeMapper.USER_ATTRIBUTE, SAML_USER_ATTRIBUTES.get(mapping.getKey()));
            mapper.setConfig(config);
            realm.addIdentityProviderMapper(mapper);
        }
    }

    private void removeFedSetupSamlMappers(String brokerAlias) {
        realm.getIdentityProviderMappersByAliasStream(brokerAlias)
                .filter(mapper -> mapper.getName() != null && mapper.getName().startsWith(SAML_MAPPER_PREFIX))
                .toList().forEach(realm::removeIdentityProviderMapper);
    }

    private void validateSamlAttributeMapping(Map<String, String> mapping) {
        if (mapping == null || mapping.isEmpty()) return;
        if (!SAML_ATTRIBUTE_FIELDS.containsAll(mapping.keySet())
                || mapping.entrySet().stream().anyMatch(entry -> blank(entry.getKey()) || blank(entry.getValue()))) {
            throw new FedSetupValidationException("SAML attribute_mapping contains an unsupported or blank field");
        }
    }

    private String validateSamlMetadataUrl(String value, String issuer) {
        String metadata = FedSetupUri.canonicalize(value);
        if (!FedSetupUri.sameOrigin(metadata, issuer)) {
            throw new FedSetupValidationException("SAML idp_metadata_url must use the Direct Installation Trust issuer origin");
        }
        return metadata;
    }

    /** Canonicalizes a pushed runtime endpoint and binds it to the trusted IdP origin. */
    private void validateIssuerBoundEndpoint(Map<String, String> values, String key, String issuer) {
        String value = values.get(key);
        if (blank(value)) return;
        String canonical = FedSetupUri.canonicalize(value);
        if (!FedSetupUri.sameOrigin(canonical, issuer)) {
            throw new FedSetupValidationException(key + " must use the Direct Installation Trust issuer origin");
        }
        values.put(key, canonical);
    }

    private void validateSamlCertificate(String value) {
        for (String certificate : value.split(",")) {
            try {
                PemUtils.decodeCertificate(certificate);
            } catch (RuntimeException e) {
                throw new FedSetupValidationException("saml.idp_certificate is missing or could not be parsed", e);
            }
        }
    }

    private void optionalUri(Map<String, String> source, String sourceKey, Map<String, String> target, String targetKey) {
        if (source.get(sourceKey) != null) {
            target.put(targetKey, FedSetupUri.canonicalize(source.get(sourceKey)));
        }
    }

    private void optional(Map<String, String> source, String sourceKey, Map<String, String> target, String targetKey) {
        if (source.get(sourceKey) != null && !source.get(sourceKey).isBlank()) {
            target.put(targetKey, source.get(sourceKey));
        }
    }

    private String required(Map<String, String> values, String name) {
        String value = values.get(name);
        if (value == null || value.isBlank()) {
            throw new FedSetupValidationException(name + " is required");
        }
        return value;
    }

    private String alias(InstallationConfigurationRequest request, String connectionId) {
        String alias = request.getBrokerAlias() == null ? "fedsetup-" + connectionId.substring(0, 8) : request.getBrokerAlias();
        if (!BROKER_ALIAS.matcher(alias).matches()) {
            throw new FedSetupValidationException("Invalid identity broker alias");
        }
        return alias;
    }

    private void requireEtag(String header, long version) {
        if (header == null || !header.equals(etag(version))) {
            throw new FedSetupValidationException("ETag does not match the current resource version");
        }
    }

    private Response response(FedSetupConnection connection, Response.Status status) {
        return response(connection, status, false);
    }

    private Response response(FedSetupConnection connection, Response.Status status, boolean includeScimAccessToken) {
        Response.ResponseBuilder result = Response.status(status).type(MediaType.APPLICATION_JSON)
                .header(FedSetupConstants.ETAG_HEADER, etag(connection.getVersion()))
                .entity(configurationResponse(connection, includeScimAccessToken));
        if (includeScimAccessToken && connection.getScimBootstrapCredentialReferenceId() != null) {
            result.header("Cache-Control", "no-store").header("Pragma", "no-cache");
        }
        return result.build();
    }

    private InstallationConfigurationResponse configurationResponse(FedSetupConnection connection, boolean includeScimAccessToken) {
        InstallationConfigurationResponse response = new InstallationConfigurationResponse();
        response.setConnectionId(connection.getId());
        response.setConnectionName("FedSetup " + connection.getIdpIssuer());
        response.setIdpDomain(connection.getIdpDomain());
        response.setCreatedAt(dateTime(connection.getCreatedAt()));
        response.setUpdatedAt(dateTime(connection.getUpdatedAt()));
        if (connection.getScimBaseUri() != null) {
            InstallationConfigurationResponse.ScimResponse scim = new InstallationConfigurationResponse.ScimResponse();
            scim.setProvisioningEndpoint(connection.getScimBaseUri());
            scim.setTokenType("Bearer");
            scim.setFeatures(connection.getScimFeatures());
            if (includeScimAccessToken && connection.getScimBootstrapCredentialReferenceId() != null) {
                FedSetupCredentialReference credential = store.getCredentialReference(connection.getScimBootstrapCredentialReferenceId());
                if (credential == null) throw new FedSetupValidationException("SCIM bootstrap credential is unavailable");
                scim.setAccessToken(FedSetupSecretCipher.open(session, realm, credential.getId(), credential.getEncryptedSecret()));
            }
            response.setScim(scim);
            if (connection.getExtensionProfiles().contains(FedSetupConstants.SCIM_CREDENTIAL_PROFILE_URI)
                    && connection.getScimTokenEndpoint() != null && connection.getScimServiceClientId() != null) {
                response.setExtensions(Map.of(FedSetupConstants.SCIM_CREDENTIAL_PROFILE_URI, Map.of(
                        "token_endpoint", connection.getScimTokenEndpoint(), "client_id", connection.getScimServiceClientId())));
            }
        }
        if (connection.getIdJag() != null) {
            response.setIdJag(connection.getIdJag());
        }
        return response;
    }

    private void createScimServiceAndBootstrapCredential(FedSetupConnection connection, DirectInstallationTrust trust) {
        FedSetupScimConnectionService.create(session, realm, connection, trust);
        if (connection.getScimServiceClientId() == null || connection.getScimBootstrapCredentialReferenceId() != null) return;
        FedSetupCredentialReference credential = new FedSetupCredentialReference();
        credential.setId(UUID.randomUUID().toString());
        credential.setConnectionId(connection.getId());
        credential.setType("scim-bootstrap-bearer");
        connection.setScimBootstrapCredentialReferenceId(credential.getId());
        credential.setEncryptedSecret(FedSetupSecretCipher.seal(session, realm, credential.getId(),
                FedSetupScimConnectionService.issueBootstrapAccessToken(session, realm, connection)));
        store.createCredentialReference(credential);
    }

    /** Stores or rotates an incoming core OIDC client_secret without exposing it in Connection or broker state. */
    private void storeOidcCredential(FedSetupConnection connection, InstallationConfigurationRequest request) {
        if (connection.getCredentialReferenceId() == null) return;
        FedSetupCredentialReference credential = store.getCredentialReference(connection.getCredentialReferenceId());
        boolean created = credential == null;
        if (credential == null) {
            credential = new FedSetupCredentialReference();
            credential.setId(connection.getCredentialReferenceId());
        }
        credential.setConnectionId(connection.getId());
        credential.setType("oidc-client-secret");
        String secret = oidcClientSecret(request);
        if (secret == null) {
            credential.setVaultReference(request.getCredentialVaultReference());
            credential.setEncryptedSecret(null);
        } else {
            credential.setVaultReference(null);
            credential.setEncryptedSecret(FedSetupSecretCipher.seal(session, realm, credential.getId(), secret));
        }
        if (created) {
            store.createCredentialReference(credential);
        } else {
            store.replaceCredentialReference(credential);
        }
    }

    private static String oidcClientSecret(InstallationConfigurationRequest request) {
        if (request.getOidc() != null && request.getOidc().getClientSecret() != null && !request.getOidc().getClientSecret().isBlank()) {
            return request.getOidc().getClientSecret();
        }
        String legacy = request.getSso().get("client_secret");
        return legacy == null || legacy.isBlank() ? null : legacy;
    }

    /** Section 9 distinguishes omitted/null write-only secrets from an invalid empty replacement. */
    static void rejectExplicitEmptyOidcClientSecret(InstallationConfigurationRequest request) {
        String coreSecret = request.getOidc() == null ? null : request.getOidc().getClientSecret();
        String legacySecret = request.getSso().get("client_secret");
        if ((coreSecret != null && coreSecret.isBlank()) || (legacySecret != null && legacySecret.isBlank())) {
            throw new FedSetupValidationException("OIDC client_secret must not be an empty string");
        }
    }

    /** Implements the write-only secret exception to Section 9's replace-present rule. */
    static String credentialReferenceForPatch(String currentReference, String newReference, boolean suppliedSecret) {
        return currentReference == null && suppliedSecret ? newReference : currentReference;
    }

    private FedSetupConnection redacted(FedSetupConnection connection) {
        FedSetupConnection result = JsonSerialization.valueFromString(JsonSerialization.valueAsString(connection), FedSetupConnection.class);
        result.getSso().remove("client_secret");
        result.getSso().remove("client_secret_vault_reference");
        result.setCredentialReferenceId(null);
        result.setScimBootstrapCredentialReferenceId(null);
        return result;
    }

    private Response error(Response.Status status, String message) {
        return protocolError(status, message);
    }

    private Response protocolError(Response.Status status, String message) {
        String code = protocolErrorCode(status, message);
        Response.Status responseStatus = "untrusted_issuer".equals(code) && status == Response.Status.BAD_REQUEST
                ? Response.Status.FORBIDDEN : status;
        return Response.status(responseStatus).type(MediaType.APPLICATION_JSON)
                .entity(Map.of("error", code, "error_description", message)).build();
    }

    /** Maps the draft's distinct protocol failures without exposing internal exception types. */
    static String protocolErrorCode(Response.Status status, String message) {
        if (status == Response.Status.PRECONDITION_FAILED) return "precondition_failed";
        if (status == Response.Status.CONFLICT) return "conflict";
        String value = message == null ? "" : message;
        if (value.contains("unsupported protocol")) return "unsupported_protocol";
        if (value.contains("Idempotency-Key") && value.contains("different")
                || value.contains("cannot change protocol or broker alias")
                || value.contains("A FedSetup Connection already exists")) return "conflict";
        if (value.contains("pre-authorization") || value.contains("active consent")
                || value.contains("No Direct Installation Trust exists")
                || value.contains("Direct Installation Trust is not active")
                || value.contains("Connection is not bound to this Direct Installation Trust")
                || value.contains("No Application integration profile")) return "untrusted_issuer";
        if (value.contains("Installation Authorization") || value.contains("Trust Establishment Request")
                || value.contains("client_assertion") || value.contains("Authorization code")) return "invalid_credential";
        return "invalid_request";
    }

    private String requestUri() {
        return session.getContext().getUri().getRequestUri().toString();
    }

    private String etag(long version) {
        return "\"" + version + "\"";
    }

    private static String dateTime(long epochSeconds) {
        return epochSeconds <= 0 ? null : Instant.ofEpochSecond(epochSeconds).toString();
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {
    }

    private record RequestAuthorization(DirectInstallationTrust trust, InstallationAuthorizationValidator.ValidatedAuthorization authorization) {
    }
}
