/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup;

import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.keycloak.common.Profile;
import org.keycloak.common.util.Time;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.fedsetup.representation.FedSetupConfigurationProfile;
import org.keycloak.fedsetup.representation.DirectInstallationTrust;
import org.keycloak.fedsetup.representation.DirectInstallationTrustApprovalRequest;
import org.keycloak.fedsetup.representation.DirectInstallationTrustConsentResult;
import org.keycloak.fedsetup.representation.DirectInstallationTrustInvitationRequest;
import org.keycloak.fedsetup.representation.FedSetupConnection;
import org.keycloak.fedsetup.representation.FedSetupInstallation;
import org.keycloak.fedsetup.representation.FedSetupScimProvisioningTask;
import org.keycloak.fedsetup.representation.FedSetupTrustPreAuthorization;
import org.keycloak.fedsetup.representation.ManualConnectionAdoption;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.RealmModel;
import org.keycloak.services.Urls;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;
import org.keycloak.urls.UrlType;

/** Admin REST surface for realm-scoped FedSetup profiles, trusts, connections, and IdP installations. */
public class FedSetupAdminResource {

    private static final Set<String> SUPPORTED_CAPABILITIES = Set.of("oidc", "saml", "scim", "id_jag");
    private static final Set<String> SUPPORTED_SCIM_FEATURES = Set.of("PUSH_NEW_USERS", "PUSH_USER_DEACTIVATION", "REACTIVATE_USERS",
            "PUSH_PROFILE_UPDATES", "PUSH_GROUPS");
    /** Portable profile fields supported by the Express Configuration SAML mapping. */
    private static final Set<String> SUPPORTED_SAML_ATTRIBUTE_FIELDS = Set.of("email", "given_name", "family_name", "display_name", "groups");

    private final KeycloakSession session;
    private final RealmModel realm;
    private final AdminPermissionEvaluator auth;
    private final AdminEventBuilder adminEvent;
    private final RealmFedSetupStore store;

    public FedSetupAdminResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth, AdminEventBuilder adminEvent) {
        this.session = session;
        this.realm = realm;
        this.auth = auth;
        this.adminEvent = adminEvent;
        this.store = new RealmFedSetupStore(realm);
    }

    /** Stable local handoff values for the IETF Direct Installation Trust profiles. */
    @GET
    @Path("runtime")
    @Produces(MediaType.APPLICATION_JSON)
    public Map<String, String> getInstallationRuntime() {
        auth.realm().requireViewRealm();
        return Map.of("idp_issuer", realmIssuer(),
                "cimd_uri", FedSetupUrls.cimd(session.getContext().getUri(UrlType.FRONTEND), realm),
                "front_channel_callback", FedSetupUrls.frontCallback(session.getContext().getUri(UrlType.FRONTEND), realm));
    }

    /** Validates external Application discovery before an IdP administrator creates an outbound trust. */
    @GET
    @Path("application-discovery")
    @Produces(MediaType.APPLICATION_JSON)
    public org.keycloak.fedsetup.representation.FedSetupDiscoveryRepresentation discoverApplication(
            @QueryParam("application_base_uri") String applicationBaseUri) {
        auth.realm().requireManageRealm();
        return FedSetupApplicationDiscoveryService.discover(session, applicationBaseUri);
    }

    @GET
    @Path("application-profile")
    @Produces(MediaType.APPLICATION_JSON)
    public FedSetupConfigurationProfile getApplicationProfile() {
        auth.realm().requireViewRealm();
        FedSetupConfigurationProfile profile = store.getApplicationProfile();
        if (profile == null) {
            throw new NotFoundException();
        }
        return profile;
    }

    @PUT
    @Path("application-profile")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public FedSetupConfigurationProfile putApplicationProfile(FedSetupConfigurationProfile profile) {
        auth.realm().requireManageRealm();
        validateProfile(profile);
        store.setApplicationProfile(profile);
        audit(OperationType.UPDATE, profile);
        return profile;
    }

    @GET
    @Path("trusts")
    @Produces(MediaType.APPLICATION_JSON)
    public List<DirectInstallationTrust> getTrusts() {
        auth.realm().requireViewRealm();
        return store.getTrusts().stream().map(this::redact).toList();
    }

    @POST
    @Path("trusts")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response createTrust(DirectInstallationTrust trust) {
        auth.realm().requireManageRealm();
        validateTrust(trust, false);
        DirectInstallationTrust created = store.createTrust(trust);
        DirectInstallationTrust redacted = redact(created);
        audit(OperationType.CREATE, redacted);
        return Response.status(Response.Status.CREATED).type(MediaType.APPLICATION_JSON).header(FedSetupConstants.ETAG_HEADER, etag(created.getVersion()))
                .entity(redacted).build();
    }

    /**
     * Starts the two-administrator Direct Installation Trust consent exchange.
     * The returned artifact is deliberately returned only at creation time and
     * is not available from a list or read API.
     */
    @POST
    @Path("trust-invitations")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response createTrustInvitation(DirectInstallationTrustInvitationRequest request) {
        auth.realm().requireManageRealm();
        DirectInstallationTrustConsentResult result = new DirectInstallationTrustConsentService(session, realm, store).invite(request);
        audit(OperationType.CREATE, Map.of("resource", "direct-installation-trust-invitation"));
        return Response.status(Response.Status.CREATED).entity(result).build();
    }

    /** IdP Tenant Admin action: approve an Application Tenant's signed invitation. */
    @POST
    @Path("trust-invitations/approve")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response approveTrustInvitation(DirectInstallationTrustApprovalRequest request) {
        auth.realm().requireManageRealm();
        DirectInstallationTrustConsentResult result = new DirectInstallationTrustConsentService(session, realm, store).approve(request);
        DirectInstallationTrust redacted = redact(result.getTrust());
        audit(OperationType.CREATE, redacted);
        result.setTrust(redacted);
        return Response.status(Response.Status.CREATED).entity(result).build();
    }

    /** Application Tenant Admin action: consume the IdP's signed approval exactly once. */
    @POST
    @Path("trust-invitations/consume")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response consumeTrustInvitation(DirectInstallationTrustApprovalRequest request) {
        auth.realm().requireManageRealm();
        DirectInstallationTrust created = new DirectInstallationTrustConsentService(session, realm, store).consume(request);
        DirectInstallationTrust redacted = redact(created);
        audit(OperationType.CREATE, redacted);
        return Response.status(Response.Status.CREATED).type(MediaType.APPLICATION_JSON)
                .header(FedSetupConstants.ETAG_HEADER, etag(created.getVersion())).entity(redacted).build();
    }

    @GET
    @Path("trust-pre-authorizations")
    @Produces(MediaType.APPLICATION_JSON)
    public List<FedSetupTrustPreAuthorization> getTrustPreAuthorizations() {
        auth.realm().requireViewRealm();
        return store.getTrustPreAuthorizations();
    }

    /** Creates the exact Application-admin approval required before a back-channel CIMD fetch. */
    @POST
    @Path("trust-pre-authorizations")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response createTrustPreAuthorization(FedSetupTrustPreAuthorization entry) {
        auth.realm().requireManageRealm();
        validateTrustPreAuthorization(entry);
        FedSetupTrustPreAuthorization created = store.createTrustPreAuthorization(entry);
        audit(OperationType.CREATE, created);
        return Response.status(Response.Status.CREATED).type(MediaType.APPLICATION_JSON)
                .header(FedSetupConstants.ETAG_HEADER, etag(created.getVersion())).entity(created).build();
    }

    @DELETE
    @Path("trust-pre-authorizations/{preAuthorizationId}")
    public Response cancelTrustPreAuthorization(@PathParam("preAuthorizationId") String preAuthorizationId,
                                                @HeaderParam(FedSetupConstants.IF_MATCH_HEADER) String ifMatch) {
        auth.realm().requireManageRealm();
        FedSetupTrustPreAuthorization entry = store.getTrustPreAuthorization(preAuthorizationId);
        if (entry == null) throw new NotFoundException();
        if (!etag(entry.getVersion()).equals(ifMatch)) {
            return error(Response.Status.PRECONDITION_FAILED, "ETag does not match the current resource version");
        }
        entry.setConsumed(true);
        FedSetupTrustPreAuthorization updated = store.updateTrustPreAuthorization(entry, entry.getVersion());
        audit(OperationType.DELETE, updated);
        return Response.noContent().header(FedSetupConstants.ETAG_HEADER, etag(updated.getVersion())).build();
    }

    @GET
    @Path("trusts/{trustId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getTrust(@PathParam("trustId") String trustId) {
        auth.realm().requireViewRealm();
        DirectInstallationTrust trust = store.requireTrust(trustId);
        return Response.ok(redact(trust)).type(MediaType.APPLICATION_JSON).header(FedSetupConstants.ETAG_HEADER, etag(trust.getVersion())).build();
    }

    /** Sends the Section 5.1 Trust Establishment Request after the Application admin's OOB pre-authorization. */
    @POST
    @Path("trusts/{trustId}/establish")
    @Produces(MediaType.APPLICATION_JSON)
    public Response establishBackChannelTrust(@PathParam("trustId") String trustId) {
        auth.realm().requireManageRealm();
        DirectInstallationTrust trust = store.requireTrust(trustId);
        DirectInstallationTrust established = OutboundTrustDispatcher.establishBackChannel(session, realm, store, trust);
        audit(OperationType.UPDATE, redact(established));
        return Response.ok(Map.of("application_tenant_id", established.getApplicationTenantId(), "idp_issuer", established.getIdpIssuer(),
                "status", "ESTABLISHED")).build();
    }

    /** Starts the administrator's browser at the Section 5.2 authorization endpoint. */
    @POST
    @Path("trusts/{trustId}/front-channel")
    @Produces(MediaType.APPLICATION_JSON)
    public Response startFrontChannelTrust(@PathParam("trustId") String trustId) {
        auth.realm().requireManageRealm();
        DirectInstallationTrust trust = store.requireTrust(trustId);
        String authorizationUri = OutboundTrustDispatcher.startFrontChannel(session, realm, store, trust);
        audit(OperationType.UPDATE, Map.of("trust_id", trustId, "profile", FedSetupConstants.FRONT_CHANNEL_TRUST_PROFILE_URI));
        return Response.ok(Map.of("authorization_uri", authorizationUri)).build();
    }

    /**
     * Local incident response for a dynamic signing-key source.  The broker is
     * disabled before its key cache is reloaded and stays disabled if the
     * approved source cannot be fetched, preventing continued acceptance of a
     * key removed during an emergency rollover.
     */
    @POST
    @Path("trusts/{trustId}/signing-keys/purge")
    public Response purgeSigningKeys(@PathParam("trustId") String trustId) {
        auth.realm().requireManageRealm();
        DirectInstallationTrust trust = store.requireTrust(trustId);
        if (blank(trust.getInstallationRuntimeCimdUri()) && blank(trust.getRuntimeJwksUri())) {
            return error(Response.Status.CONFLICT, "The Direct Installation Trust does not use a dynamic signing-key source");
        }
        FedSetupConnection connection = store.findConnectionByTrust(trustId);
        IdentityProviderModel broker = connection == null ? null : realm.getIdentityProviderByAlias(connection.getBrokerAlias());
        boolean enabled = broker != null && broker.isEnabled();
        if (broker != null) {
            broker.setEnabled(false);
            realm.updateIdentityProvider(broker);
        }
        try {
            if (!blank(trust.getInstallationRuntimeCimdUri())) {
                // FedSetup's CIMD verifier intentionally has no retained key
                // cache, so this proves a fresh retrieval before re-enabling.
                FedSetupCimdResolver.metadata(session, trust.getInstallationRuntimeCimdUri());
            }
            if (connection != null && "oidc".equals(connection.getProtocol())) {
                FedSetupOidcMetadataResolver.resolve(session, trust.getIdpIssuer());
                if (broker != null) {
                    OIDCIdentityProviderConfig configuration = new OIDCIdentityProviderConfig(broker);
                    // The stored provider remains disabled while the loader
                    // runs; enable only this in-memory configuration so the
                    // standard cache-reload implementation executes.
                    configuration.setEnabled(true);
                    if (!new OIDCIdentityProvider(session, configuration).reloadKeys()) {
                        throw new FedSetupValidationException("Unable to reload the approved OIDC signing-key source");
                    }
                }
            }
            if (broker != null) {
                broker.setEnabled(enabled);
                realm.updateIdentityProvider(broker);
            }
            audit(OperationType.UPDATE, Map.of("trust_id", trustId, "operation", "purge-signing-keys"));
            return Response.noContent().build();
        } catch (FedSetupValidationException e) {
            audit(OperationType.UPDATE, Map.of("trust_id", trustId, "operation", "purge-signing-keys-failed"));
            return error(Response.Status.BAD_REQUEST, e.getMessage());
        }
    }

    @PUT
    @Path("trusts/{trustId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateTrust(@PathParam("trustId") String trustId, @HeaderParam(FedSetupConstants.IF_MATCH_HEADER) String ifMatch,
                                DirectInstallationTrust trust) {
        auth.realm().requireManageRealm();
        DirectInstallationTrust current = store.requireTrust(trustId);
        if (!Objects.equals(trustId, trust.getId())) {
            return error(Response.Status.BAD_REQUEST, "Trust identifier cannot change");
        }
        if (!etag(current.getVersion()).equals(ifMatch)) {
            return error(Response.Status.PRECONDITION_FAILED, "ETag does not match the current resource version");
        }
        if (blank(trust.getReceiverCredentialVaultReference())) {
            trust.setReceiverCredentialVaultReference(current.getReceiverCredentialVaultReference());
        }
        validateTrust(trust, true);
        if ((!Objects.equals(current.getApplicationTenantId(), trust.getApplicationTenantId())
                || !Objects.equals(current.getIdpIssuer(), trust.getIdpIssuer())
                || !Objects.equals(current.getCanonicalApplicationBaseUri(), trust.getCanonicalApplicationBaseUri()))
                && (store.findConnectionByTrust(trustId) != null || store.getInstallations().stream()
                .anyMatch(installation -> trustId.equals(installation.getTrustId())))) {
            return error(Response.Status.CONFLICT, "A trust bound to a Connection or Installation cannot change its tenant, issuer, or Application URI");
        }
        if (store.getTrusts().stream().anyMatch(existing -> !trustId.equals(existing.getId())
                && trust.getApplicationTenantId().equals(existing.getApplicationTenantId())
                && trust.getIdpIssuer().equals(existing.getIdpIssuer()))) {
            return error(Response.Status.CONFLICT, "A Direct Installation Trust already exists for this Application Tenant and IdP issuer");
        }
        DirectInstallationTrust updated = store.updateTrust(trust, current.getVersion());
        DirectInstallationTrust redacted = redact(updated);
        audit(OperationType.UPDATE, redacted);
        return Response.ok(redacted).type(MediaType.APPLICATION_JSON).header(FedSetupConstants.ETAG_HEADER, etag(updated.getVersion())).build();
    }

    @GET
    @Path("connections")
    @Produces(MediaType.APPLICATION_JSON)
    public List<FedSetupConnection> getConnections() {
        auth.realm().requireViewRealm();
        return store.getConnections().stream().map(this::redact).toList();
    }

    /** Binds an existing, manually configured broker to the approved tenant trust without changing its configuration. */
    @POST
    @Path("connections/adopt")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response adoptManualConnection(ManualConnectionAdoption adoption) {
        auth.realm().requireManageRealm();
        if (adoption == null || blank(adoption.getTrustId()) || blank(adoption.getBrokerAlias())) {
            throw new FedSetupValidationException("trustId and brokerAlias are required");
        }
        DirectInstallationTrust trust = store.requireTrust(adoption.getTrustId());
        if (!trust.isActive()) throw new FedSetupValidationException("Direct Installation Trust is not active");
        if (store.findConnectionByTrust(trust.getId()) != null || store.getConnections().stream()
                .anyMatch(connection -> adoption.getBrokerAlias().equals(connection.getBrokerAlias()))) {
            throw new FedSetupValidationException("Broker or Direct Installation Trust is already bound to a FedSetup Connection");
        }
        IdentityProviderModel broker = realm.getIdentityProviderByAlias(adoption.getBrokerAlias());
        if (broker == null || !Set.of("oidc", "saml").contains(broker.getProviderId())) {
            throw new FedSetupValidationException("A pre-existing OIDC or SAML identity broker is required");
        }
        Map<String, String> sso = adoptedSso(broker, trust);
        FedSetupConnection connection = new FedSetupConnection();
        connection.setTrustId(trust.getId());
        connection.setApplicationTenantId(trust.getApplicationTenantId());
        connection.setIdpIssuer(trust.getIdpIssuer());
        connection.setProtocol(broker.getProviderId());
        connection.setBrokerAlias(broker.getAlias());
        connection.setStatus(broker.isEnabled() ? "ACTIVE" : "DEACTIVATED");
        connection.setSso(sso);
        // Adoption establishes immutable ownership of the pre-existing SSO
        // configuration.  It does not configure every capability merely
        // because the Direct Installation Trust would permit it.
        connection.setCapabilities(Set.of());
        connection.setExtensionProfiles(Set.of());
        FedSetupConnection created = store.createConnection(connection);
        FedSetupScimConnectionService.create(session, realm, created, trust);
        if (created.getScimServiceClientId() != null) {
            created = store.updateConnection(created, created.getVersion());
        }
        FedSetupConnection redacted = redact(created);
        audit(OperationType.CREATE, redacted);
        return Response.status(Response.Status.CREATED).entity(redacted).header(FedSetupConstants.ETAG_HEADER, etag(created.getVersion())).build();
    }

    @GET
    @Path("installations")
    @Produces(MediaType.APPLICATION_JSON)
    public List<FedSetupInstallation> getInstallations() {
        auth.realm().requireViewRealm();
        return store.getInstallations().stream().map(this::redact).toList();
    }

    @GET
    @Path("scim-provisioning-tasks")
    @Produces(MediaType.APPLICATION_JSON)
    public List<FedSetupScimProvisioningTask> getScimProvisioningTasks() {
        auth.realm().requireViewRealm();
        return store.getScimTasks();
    }

    /** Queues the current realm users and groups for an administrator-requested SCIM reconciliation. */
    @POST
    @Path("installations/{installationId}/scim/reconcile")
    @Produces(MediaType.APPLICATION_JSON)
    public Response reconcileScimInstallation(@PathParam("installationId") String installationId) {
        auth.realm().requireManageRealm();
        FedSetupInstallation installation = store.requireInstallation(installationId);
        if (!"ACTIVE".equals(installation.getStatus()) || !installation.getCapabilities().contains("scim")
                || installation.getScimEndpoint() == null || (installation.getScimCredentialReferenceId() == null
                && (installation.getScimTokenEndpoint() == null || installation.getScimServiceClientId() == null))) {
            return error(Response.Status.CONFLICT, "An active SCIM-enabled Installation is required for reconciliation");
        }
        if (!store.requireTrust(installation.getTrustId()).isActive()) {
            return error(Response.Status.CONFLICT, "An active Direct Installation Trust is required for reconciliation");
        }
        int users = 0;
        for (org.keycloak.models.UserModel user : session.users().searchForUserStream(realm, Map.of()).toList()) {
            enqueueScimReconciliation(installation, "USER", user.getId());
            users++;
        }
        int groups = 0;
        for (org.keycloak.models.GroupModel group : realm.getGroupsStream().toList()) {
            enqueueScimReconciliation(installation, "GROUP", group.getId());
            groups++;
        }
        Map<String, Integer> result = Map.of("users", users, "groups", groups);
        audit(OperationType.UPDATE, result);
        return Response.accepted(result).build();
    }

    /**
     * Creates the IdP-side, administrator-reviewed desired state. A dispatcher
     * can only send this record after a compatible trust profile is approved.
     */
    @POST
    @Path("installations")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response createInstallation(FedSetupInstallation installation) {
        auth.realm().requireManageRealm();
        validateInstallation(installation);
        clearServerManagedInstallationState(installation);
        installation.setStatus("PENDING_REVIEW");
        installation.setIdempotencyKey(UUID.randomUUID().toString());
        FedSetupInstallation created = store.createInstallation(installation);
        FedSetupInstallation redacted = redact(created);
        audit(OperationType.CREATE, redacted);
        return Response.status(Response.Status.CREATED).type(MediaType.APPLICATION_JSON).header(FedSetupConstants.ETAG_HEADER, etag(created.getVersion()))
                .entity(redacted).build();
    }

    /** Material changes remain in PENDING_REVIEW until an administrator explicitly dispatches them. */
    @PUT
    @Path("installations/{installationId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateInstallation(@PathParam("installationId") String installationId,
                                       @HeaderParam(FedSetupConstants.IF_MATCH_HEADER) String ifMatch,
                                       FedSetupInstallation installation) {
        auth.realm().requireManageRealm();
        FedSetupInstallation current = store.requireInstallation(installationId);
        if (!Objects.equals(installationId, installation.getId())) return error(Response.Status.BAD_REQUEST, "Installation identifier cannot change");
        if (!etag(current.getVersion()).equals(ifMatch)) return error(Response.Status.PRECONDITION_FAILED, "ETag does not match the current resource version");
        if (!Objects.equals(current.getTrustId(), installation.getTrustId()) || !Objects.equals(current.getApplicationTenantId(), installation.getApplicationTenantId())) {
            return error(Response.Status.BAD_REQUEST, "Installation trust and Application Tenant cannot change");
        }
        validateInstallation(installation);
        installation.setRemoteConnectionId(current.getRemoteConnectionId());
        installation.setRemoteEtag(current.getRemoteEtag());
        installation.setDesiredSso(Map.of());
        installation.setAppliedSso(current.getAppliedSso());
        installation.setScimEndpoint(current.getScimEndpoint());
        installation.setScimTokenEndpoint(current.getScimTokenEndpoint());
        installation.setScimServiceClientId(current.getScimServiceClientId());
        installation.setScimCredentialReferenceId(current.getScimCredentialReferenceId());
        installation.setIdempotencyKey(current.getIdempotencyKey());
        installation.setStatus("PENDING_REVIEW");
        installation.setLastError(null);
        installation.setDispatchAttempts(0);
        installation.setNextAttemptAt(0);
        FedSetupInstallation updated = store.updateInstallation(installation, current.getVersion());
        FedSetupInstallation redacted = redact(updated);
        audit(OperationType.UPDATE, redacted);
        return Response.ok(redacted).header(FedSetupConstants.ETAG_HEADER, etag(updated.getVersion())).build();
    }

    @POST
    @Path("installations/{installationId}/dispatch")
    @Produces(MediaType.APPLICATION_JSON)
    public Response dispatchInstallation(@PathParam("installationId") String installationId) {
        auth.realm().requireManageRealm();
        FedSetupInstallation installation = store.requireInstallation(installationId);
        if ("DEACTIVATED".equals(installation.getStatus())) return error(Response.Status.CONFLICT, "A deactivated Installation cannot be dispatched");
        FedSetupInstallation updated = new OutboundInstallationDispatcher(session, realm, store).dispatch(installation);
        FedSetupInstallation redacted = redact(updated);
        audit(OperationType.UPDATE, redacted);
        Response.Status status = "ACTIVE".equals(updated.getStatus()) ? Response.Status.OK : Response.Status.ACCEPTED;
        return Response.status(status).entity(redacted).header(FedSetupConstants.ETAG_HEADER, etag(updated.getVersion())).build();
    }

    @DELETE
    @Path("installations/{installationId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response deleteInstallation(@PathParam("installationId") String installationId) {
        auth.realm().requireManageRealm();
        FedSetupInstallation updated = new OutboundInstallationDispatcher(session, realm, store)
                .delete(store.requireInstallation(installationId));
        FedSetupInstallation redacted = redact(updated);
        audit(OperationType.DELETE, redacted);
        Response.Status status = "DEACTIVATED".equals(updated.getStatus()) ? Response.Status.OK : Response.Status.ACCEPTED;
        return Response.status(status).entity(redacted).header(FedSetupConstants.ETAG_HEADER, etag(updated.getVersion())).build();
    }

    private void validateProfile(FedSetupConfigurationProfile profile) {
        if (profile == null || blank(profile.getApplicationTenantId())) {
            throw new FedSetupValidationException("applicationTenantId is required");
        }
        profile.setCanonicalBaseUri(FedSetupUri.canonicalize(profile.getCanonicalBaseUri()));
        String realmApplicationBaseUri = FedSetupUri.canonicalize(Urls.realmIssuer(
                session.getContext().getUri(UrlType.FRONTEND).getBaseUri(), realm.getName()));
        if (!realmApplicationBaseUri.equals(profile.getCanonicalBaseUri())) {
            throw new FedSetupValidationException("Keycloak serves this realm's FedSetup discovery only at its canonical realm URI; canonicalBaseUri must match it");
        }
        validateUriIfPresent(profile.getOidcDocumentationUri(), profile::setOidcDocumentationUri);
        validateClient(profile.getOidcClientId(), "openid-connect");
        validateClient(profile.getSamlClientId(), "saml");
        if (blank(profile.getOidcClientId()) && blank(profile.getSamlClientId())) {
            throw new FedSetupValidationException("An Application integration profile requires a pre-created OIDC or SAML client");
        }
        if (profile.isSamlSpInitiatedSloSupported() && blank(profile.getSamlClientId())) {
            throw new FedSetupValidationException("SP-initiated SAML SLO requires a pre-created SAML client");
        }
        profile.getExtensionProfiles().add(FedSetupConstants.FEATURE_PROFILE_URI);
        if (profile.getCapabilities().contains("scim")) {
            profile.getExtensionProfiles().add(FedSetupConstants.SCIM_CREDENTIAL_PROFILE_URI);
        }
        validateTerms(profile.getCapabilities(), "capability");
        validateTerms(profile.getExtensionProfiles(), "extension profile");
        if (!SUPPORTED_CAPABILITIES.containsAll(profile.getCapabilities())) {
            throw new FedSetupValidationException("Provider Commands or an unknown capability is not supported");
        }
        if (profile.getCapabilities().contains("scim") && (!Profile.isFeatureEnabled(Profile.Feature.SCIM_API) || !realm.isScimApiEnabled())) {
            throw new FedSetupValidationException("The realm's native SCIM API must be enabled before advertising scim");
        }
        validateIdJagResourceBindings(profile);
    }

    private void validateTrust(DirectInstallationTrust trust, boolean updating) {
        if (trust == null || blank(trust.getApplicationTenantId()) || blank(trust.getIdpIssuer())) {
            throw new FedSetupValidationException("applicationTenantId and idpIssuer are required");
        }
        boolean cimdTrust = !blank(trust.getInstallationRuntimeCimdUri());
        if (!cimdTrust && blank(trust.getSigningKeyJwk())) {
            throw new FedSetupValidationException("A legacy signingKeyJwk or a CIMD installation runtime is required");
        }
        trust.setCanonicalApplicationBaseUri(FedSetupUri.canonicalize(trust.getCanonicalApplicationBaseUri()));
        trust.setIdpIssuer(FedSetupUri.canonicalize(trust.getIdpIssuer()));
        if (cimdTrust) {
            trust.setInstallationRuntimeCimdUri(FedSetupUri.canonicalize(trust.getInstallationRuntimeCimdUri()));
            if (!Set.of(FedSetupConstants.BACK_CHANNEL_TRUST_PROFILE_URI, FedSetupConstants.FRONT_CHANNEL_TRUST_PROFILE_URI)
                    .contains(trust.getTrustProfileUri())) {
                throw new FedSetupValidationException("CIMD Direct Installation Trust requires a supported IETF trust profile URI");
            }
        }
        if (trust.getConfigurationEndpoint() != null) {
            trust.setConfigurationEndpoint(FedSetupUri.canonicalize(trust.getConfigurationEndpoint()));
        }
        if (trust.getConnectionEndpointTemplate() != null) {
            trust.setConnectionEndpointTemplate(FedSetupUri.canonicalizeConnectionEndpointTemplate(trust.getConnectionEndpointTemplate()));
        }
        if (trust.getInstallationTrustEndpoint() != null) {
            trust.setInstallationTrustEndpoint(FedSetupUri.canonicalize(trust.getInstallationTrustEndpoint()));
        }
        if (trust.getInstallationAuthorizationEndpoint() != null) {
            trust.setInstallationAuthorizationEndpoint(FedSetupUri.canonicalize(trust.getInstallationAuthorizationEndpoint()));
        }
        if (trust.getInstallationTokenEndpoint() != null) {
            trust.setInstallationTokenEndpoint(FedSetupUri.canonicalize(trust.getInstallationTokenEndpoint()));
        }
        if (trust.getRuntimeJwksUri() != null) {
            trust.setRuntimeJwksUri(FedSetupUri.canonicalize(trust.getRuntimeJwksUri()));
        }
        if (trust.getReceiverCredentialVaultReference() != null
                && !trust.getReceiverCredentialVaultReference().matches("\\$\\{vault\\.[A-Za-z0-9_.-]+}")) {
            throw new FedSetupValidationException("Receiver credentials must be a Keycloak Vault reference");
        }
        if (!cimdTrust) validatePinnedJwk(trust.getSigningKeyJwk());
        validateTerms(trust.getCapabilities(), "capability");
        validateTerms(trust.getProviderDelegationProfiles(), "provider delegation profile");
        validateTerms(trust.getExtensionProfiles(), "extension profile");
        if (!trust.getProviderDelegationProfiles().isEmpty()) {
            throw new FedSetupValidationException("This Keycloak preview does not implement a Provider Delegation Profile");
        }
        if (!SUPPORTED_CAPABILITIES.containsAll(trust.getCapabilities())) {
            throw new FedSetupValidationException("Provider Commands or an unknown capability is not supported");
        }
        if (trust.getCapabilities().contains("id_jag") && !Profile.isFeatureEnabled(Profile.Feature.IDENTITY_ASSERTION_JWT)) {
            throw new FedSetupValidationException("The Identity Assertion JWT preview feature must be enabled before approving id_jag");
        }
        if (!cimdTrust && !trust.getExtensionProfiles().contains(FedSetupConstants.FEATURE_PROFILE_URI)) {
            throw new FedSetupValidationException("The Keycloak Direct Installation Trust profile must be explicitly approved");
        }
        boolean outboundTrust = realmIssuer().equals(trust.getIdpIssuer());
        if (outboundTrust) {
            if (trust.getCapabilities().contains("id_jag")) {
                throw new FedSetupValidationException("This Keycloak preview receives ID-JAG assertions but does not issue them");
            }
            if (cimdTrust) {
                if (!trust.getInstallationRuntimeCimdUri().equals(FedSetupUrls.cimd(session.getContext().getUri(UrlType.FRONTEND), realm))) {
                    throw new FedSetupValidationException("Outbound Direct Installation Trust must use this realm's CIMD installation runtime");
                }
            } else {
                validateOutboundSigningKey(trust.getSigningKeyJwk());
            }
            if (blank(trust.getConfigurationEndpoint()) || !sameOrigin(trust.getCanonicalApplicationBaseUri(), trust.getConfigurationEndpoint())) {
                throw new FedSetupValidationException("Outbound Direct Installation Trust must pin a configuration endpoint on the approved Application origin");
            }
            if (cimdTrust && FedSetupConstants.BACK_CHANNEL_TRUST_PROFILE_URI.equals(trust.getTrustProfileUri())) {
                if (blank(trust.getInstallationTrustEndpoint()) || !sameOrigin(trust.getCanonicalApplicationBaseUri(), trust.getInstallationTrustEndpoint())) {
                    throw new FedSetupValidationException("Back-channel Direct Installation Trust must pin an installation trust endpoint on the approved Application origin");
                }
            }
            if (cimdTrust && FedSetupConstants.FRONT_CHANNEL_TRUST_PROFILE_URI.equals(trust.getTrustProfileUri())) {
                if (blank(trust.getInstallationAuthorizationEndpoint()) || blank(trust.getInstallationTokenEndpoint())
                        || !sameOrigin(trust.getCanonicalApplicationBaseUri(), trust.getInstallationAuthorizationEndpoint())
                        || !sameOrigin(trust.getCanonicalApplicationBaseUri(), trust.getInstallationTokenEndpoint())) {
                    throw new FedSetupValidationException("Front-channel Direct Installation Trust must pin authorization and token endpoints on the approved Application origin");
                }
            }
            if (cimdTrust) {
                org.keycloak.fedsetup.representation.FedSetupDiscoveryRepresentation discovery =
                        FedSetupApplicationDiscoveryService.discover(session, trust.getCanonicalApplicationBaseUri());
                if (!trust.getConfigurationEndpoint().equals(FedSetupUri.canonicalize(discovery.getConfigurationEndpoint()))
                        || !discovery.getDirectInstallationTrustProfilesSupported().contains(trust.getTrustProfileUri())) {
                    throw new FedSetupValidationException("Outbound Direct Installation Trust does not match the discovered Application configuration endpoint or profile support");
                }
                String discoveredTemplate = FedSetupUri.canonicalizeConnectionEndpointTemplate(discovery.getConnectionEndpointTemplate());
                if (trust.getConnectionEndpointTemplate() != null && !trust.getConnectionEndpointTemplate().equals(discoveredTemplate)) {
                    throw new FedSetupValidationException("Outbound Direct Installation Trust does not match the discovered connection endpoint template");
                }
                trust.setConnectionEndpointTemplate(discoveredTemplate);
                if (FedSetupConstants.BACK_CHANNEL_TRUST_PROFILE_URI.equals(trust.getTrustProfileUri())
                        && !trust.getInstallationTrustEndpoint().equals(FedSetupUri.canonicalize(discovery.getInstallationTrustEndpoint()))) {
                    throw new FedSetupValidationException("Outbound Direct Installation Trust does not match the discovered installation trust endpoint");
                }
                if (FedSetupConstants.FRONT_CHANNEL_TRUST_PROFILE_URI.equals(trust.getTrustProfileUri())
                        && (!trust.getInstallationAuthorizationEndpoint().equals(FedSetupUri.canonicalize(discovery.getInstallationAuthorizationEndpoint()))
                        || !trust.getInstallationTokenEndpoint().equals(FedSetupUri.canonicalize(discovery.getInstallationTokenEndpoint())))) {
                    throw new FedSetupValidationException("Outbound Direct Installation Trust does not match the discovered front-channel endpoints");
                }
                trust.setSamlSpInitiatedSloSupported(Boolean.TRUE.equals(discovery.getSamlSpInitiatedSloSupported()));
            }
        }
        if (!outboundTrust) {
            FedSetupConfigurationProfile profile = store.getApplicationProfile();
            if (profile == null || !profile.getApplicationTenantId().equals(trust.getApplicationTenantId())) {
                throw new FedSetupValidationException("A matching Application integration profile is required before creating an inbound trust");
            }
            if (!profile.getCanonicalBaseUri().equals(trust.getCanonicalApplicationBaseUri())) {
                throw new FedSetupValidationException("Inbound trust must use the Application integration profile's canonical Base URI");
            }
            if (!profile.getCapabilities().containsAll(trust.getCapabilities())
                    || !profile.getExtensionProfiles().containsAll(trust.getExtensionProfiles())) {
                throw new FedSetupValidationException("Trust grants capabilities or extension profiles not supported by the Application profile");
            }
        }
        if (trust.getExpiresAt() > 0 && trust.getExpiresAt() <= Time.currentTime()) {
            throw new FedSetupValidationException("Trust expiry must be in the future");
        }
    }

    private void validateTrustPreAuthorization(FedSetupTrustPreAuthorization entry) {
        if (entry == null || blank(entry.getApplicationTenantId()) || blank(entry.getIdpIssuer()) || blank(entry.getCimdUri())) {
            throw new FedSetupValidationException("applicationTenantId, idpIssuer, and cimdUri are required");
        }
        FedSetupConfigurationProfile profile = store.getApplicationProfile();
        if (profile == null || !entry.getApplicationTenantId().equals(profile.getApplicationTenantId())) {
            throw new FedSetupValidationException("A matching Application integration profile is required before pre-authorizing trust");
        }
        entry.setIdpIssuer(FedSetupUri.canonicalize(entry.getIdpIssuer()));
        entry.setCimdUri(FedSetupUri.canonicalize(entry.getCimdUri()));
        validateTerms(entry.getCapabilities(), "capability");
        validateTerms(entry.getProviderDelegationProfiles(), "provider delegation profile");
        validateTerms(entry.getFederationExtensionProfiles(), "federation extension profile");
        if (!entry.getProviderDelegationProfiles().isEmpty()) {
            throw new FedSetupValidationException("This Keycloak preview does not implement a Provider Delegation Profile");
        }
        if (!profile.getCapabilities().containsAll(entry.getCapabilities())
                || !profile.getExtensionProfiles().containsAll(entry.getFederationExtensionProfiles())) {
            throw new FedSetupValidationException("Pre-authorization exceeds the Application integration profile");
        }
        long now = Time.currentTime();
        if (entry.getExpiresAt() == 0) entry.setExpiresAt(now + FedSetupConstants.MAX_AUTHORIZATION_LIFESPAN_SECONDS);
        if (entry.getExpiresAt() <= now || entry.getExpiresAt() - now > FedSetupConstants.MAX_AUTHORIZATION_LIFESPAN_SECONDS) {
            throw new FedSetupValidationException("Trust pre-authorization expiry must be in the next five minutes");
        }
        entry.setConsumed(false);
    }

    private void validateInstallation(FedSetupInstallation installation) {
        if (installation == null || blank(installation.getApplicationTenantId()) || blank(installation.getTrustId())
                || blank(installation.getClientId()) || !Set.of("oidc", "saml").contains(installation.getProtocol())) {
            throw new FedSetupValidationException("applicationTenantId, trustId, clientId, and a supported protocol are required");
        }
        DirectInstallationTrust trust = store.requireTrust(installation.getTrustId());
        if (!trust.isActive() || !installation.getApplicationTenantId().equals(trust.getApplicationTenantId())) {
            throw new FedSetupValidationException("Installation must use an active Direct Installation Trust for the same Application Tenant");
        }
        if (!Urls.realmIssuer(session.getContext().getUri(UrlType.FRONTEND).getBaseUri(), realm.getName()).equals(trust.getIdpIssuer())) {
            throw new FedSetupValidationException("Installation must use a Direct Installation Trust approved for this realm issuer");
        }
        installation.setCanonicalApplicationBaseUri(FedSetupUri.canonicalize(installation.getCanonicalApplicationBaseUri()));
        installation.setConfigurationEndpoint(FedSetupUri.canonicalize(installation.getConfigurationEndpoint()));
        if (!installation.getCanonicalApplicationBaseUri().equals(trust.getCanonicalApplicationBaseUri())
                || !installation.getConfigurationEndpoint().equals(trust.getConfigurationEndpoint())) {
            throw new FedSetupValidationException("Installation must use the Application URI and configuration endpoint approved by Direct Installation Trust");
        }
        if (!sameOrigin(installation.getCanonicalApplicationBaseUri(), installation.getConfigurationEndpoint())) {
            throw new FedSetupValidationException("Installation configuration endpoint must use the approved Application origin");
        }
        validateClient(installation.getClientId(), "oidc".equals(installation.getProtocol()) ? "openid-connect" : "saml");
        if (!"saml".equals(installation.getProtocol()) && !installation.getSamlAttributeMapping().isEmpty()) {
            throw new FedSetupValidationException("SAML attribute mapping is only valid for a SAML Installation");
        }
        if (!SUPPORTED_SAML_ATTRIBUTE_FIELDS.containsAll(installation.getSamlAttributeMapping().keySet())
                || installation.getSamlAttributeMapping().entrySet().stream()
                .anyMatch(entry -> blank(entry.getKey()) || blank(entry.getValue()))) {
            throw new FedSetupValidationException("SAML attribute mapping contains an unsupported or blank field");
        }
        if (!trust.getCapabilities().containsAll(installation.getCapabilities())
                || !trust.getExtensionProfiles().containsAll(installation.getExtensionProfiles())) {
            throw new FedSetupValidationException("Installation requests capabilities or extension profiles not approved by Direct Installation Trust");
        }
        if (installation.getCapabilities().contains("id_jag")) {
            throw new FedSetupValidationException("This Keycloak preview receives ID-JAG assertions but does not issue them");
        }
        if (installation.getCapabilities().contains("scim")) {
            if (installation.getScimFeatures().isEmpty() || !SUPPORTED_SCIM_FEATURES.containsAll(installation.getScimFeatures())) {
                throw new FedSetupValidationException("A SCIM-enabled Installation must select a supported SCIM feature subset");
            }
        } else if (!installation.getScimFeatures().isEmpty()) {
            throw new FedSetupValidationException("SCIM features require the scim capability");
        }
    }

    private void clearServerManagedInstallationState(FedSetupInstallation installation) {
        installation.setRemoteConnectionId(null);
        installation.setRemoteEtag(null);
        installation.setDesiredSso(Map.of());
        installation.setAppliedSso(Map.of());
        installation.setScimEndpoint(null);
        installation.setScimTokenEndpoint(null);
        installation.setScimServiceClientId(null);
        installation.setScimCredentialReferenceId(null);
        installation.setLastError(null);
        installation.setDispatchAttempts(0);
        installation.setNextAttemptAt(0);
    }

    private void enqueueScimReconciliation(FedSetupInstallation installation, String resourceType, String resourceId) {
        org.keycloak.fedsetup.representation.FedSetupScimProvisioningTask task = new org.keycloak.fedsetup.representation.FedSetupScimProvisioningTask();
        task.setInstallationId(installation.getId());
        task.setResourceType(resourceType);
        task.setResourceId(resourceId);
        task.setOperation("UPSERT");
        store.enqueueScimTask(task);
    }

    private Map<String, String> adoptedSso(IdentityProviderModel broker, DirectInstallationTrust trust) {
        Map<String, String> config = broker.getConfig();
        Map<String, String> result = new java.util.LinkedHashMap<>();
        if ("oidc".equals(broker.getProviderId())) {
            String issuer = config.get("issuer");
            if (blank(issuer) || !trust.getIdpIssuer().equals(FedSetupUri.canonicalize(issuer))
                    || !Objects.equals(trust.getRuntimeJwksUri(), config.get("jwksUrl"))) {
                throw new FedSetupValidationException("OIDC broker issuer or JWKS URI does not match Direct Installation Trust");
            }
            copyIfPresent(config, result, "authorizationUrl", "authorization_endpoint");
            copyIfPresent(config, result, "tokenUrl", "token_endpoint");
            copyIfPresent(config, result, "userInfoUrl", "userinfo_endpoint");
            copyIfPresent(config, result, "logoutUrl", "logout_endpoint");
            copyIfPresent(config, result, "clientId", "client_id");
            if (blank(result.get("authorization_endpoint")) || blank(result.get("token_endpoint")) || blank(result.get("client_id"))) {
                throw new FedSetupValidationException("OIDC broker is missing required endpoint or client configuration");
            }
            result.put("issuer", trust.getIdpIssuer());
        } else {
            if (blank(trust.getRuntimeSigningCertificate())
                    || !Objects.equals(trust.getRuntimeSigningCertificate(), config.get("signingCertificate"))) {
                throw new FedSetupValidationException("SAML broker signing certificate does not match Direct Installation Trust");
            }
            copyIfPresent(config, result, "idpEntityId", "entity_id");
            copyIfPresent(config, result, "singleSignOnServiceUrl", "single_sign_on_service");
            copyIfPresent(config, result, "singleLogoutServiceUrl", "single_logout_service");
            copyIfPresent(config, result, "nameIDPolicyFormat", "name_id_format");
            if (blank(result.get("entity_id")) || blank(result.get("single_sign_on_service"))) {
                throw new FedSetupValidationException("SAML broker is missing required entity or SSO configuration");
            }
        }
        return result;
    }

    private void copyIfPresent(Map<String, String> source, Map<String, String> target, String sourceName, String targetName) {
        String value = source.get(sourceName);
        if (!blank(value)) target.put(targetName, value);
    }

    private void validatePinnedJwk(String rawJwk) {
        try {
            JWK jwk = JWKParser.create().parse(rawJwk).getJwk();
            if (blank(jwk.getKeyId()) || blank(jwk.getAlgorithm()) || !Set.of("RS256", "RS384", "RS512", "ES256", "ES384", "ES512").contains(jwk.getAlgorithm())) {
                throw new FedSetupValidationException("Pinned signing JWK requires kid and a supported asymmetric signing algorithm");
            }
            JWKParser.create(jwk).toPublicKey();
        } catch (FedSetupValidationException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new FedSetupValidationException("Invalid pinned signing JWK", e);
        }
    }

    private void validateOutboundSigningKey(String rawJwk) {
        try {
            PublicKey configuredKey = JWKParser.create(JWKParser.create().parse(rawJwk).getJwk()).toPublicKey();
            KeyWrapper activeKey = session.keys().getActiveKey(realm, KeyUse.SIG, Algorithm.RS256);
            if (activeKey == null || !(activeKey.getPublicKey() instanceof PublicKey activePublicKey)
                    || !MessageDigest.isEqual(configuredKey.getEncoded(), activePublicKey.getEncoded())) {
                throw new FedSetupValidationException("Outbound Direct Installation Trust must pin this realm's active RS256 signing key");
            }
        } catch (FedSetupValidationException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new FedSetupValidationException("Unable to validate the realm signing key", e);
        }
    }

    private void validateClient(String clientId, String protocol) {
        if (blank(clientId)) {
            return;
        }
        ClientModel client = realm.getClientByClientId(clientId);
        if (client == null || !protocol.equals(client.getProtocol())) {
            throw new FedSetupValidationException("A pre-created " + protocol + " client is required");
        }
    }

    /** Validates the administrator-controlled bridge from a FedSetup resource URI to a local resource server. */
    private void validateIdJagResourceBindings(FedSetupConfigurationProfile profile) {
        if (profile.getIdJagResourceBindings().isEmpty()) {
            if (profile.getCapabilities().contains("id_jag")) {
                throw new FedSetupValidationException("Advertising id_jag requires at least one Application-admin resource binding");
            }
            return;
        }
        if (!profile.getCapabilities().contains("id_jag")) {
            throw new FedSetupValidationException("ID-JAG resource bindings require the id_jag capability");
        }
        if (!Profile.isFeatureEnabled(Profile.Feature.IDENTITY_ASSERTION_JWT)) {
            throw new FedSetupValidationException("The Identity Assertion JWT preview feature must be enabled before advertising id_jag");
        }
        Set<String> resources = new java.util.LinkedHashSet<>();
        for (org.keycloak.fedsetup.representation.FedSetupIdJagResourceBinding binding : profile.getIdJagResourceBindings()) {
            if (binding == null || blank(binding.getResource()) || blank(binding.getClientId()) || binding.getScopes().isEmpty()) {
                throw new FedSetupValidationException("Each ID-JAG resource binding requires resource, client_id, and at least one scope");
            }
            binding.setResource(FedSetupUri.canonicalize(binding.getResource()));
            if (!resources.add(binding.getResource())) {
                throw new FedSetupValidationException("An ID-JAG resource URI may appear in only one Application-admin binding");
            }
            ClientModel client = realm.getClientByClientId(binding.getClientId());
            if (client == null || !client.isEnabled() || !"openid-connect".equals(client.getProtocol())) {
                throw new FedSetupValidationException("Each ID-JAG resource binding must select an enabled pre-created OIDC resource client");
            }
            validateTerms(binding.getScopes(), "ID-JAG resource scope");
            for (String scope : binding.getScopes()) {
                if (org.keycloak.models.utils.KeycloakModelUtils.getClientScopeByName(realm, scope) == null) {
                    throw new FedSetupValidationException("Each ID-JAG resource scope must name an existing realm client scope");
                }
            }
        }
    }

    private void validateTerms(Set<String> values, String label) {
        if (values == null || values.stream().anyMatch(this::blank)) {
            throw new FedSetupValidationException("Each " + label + " must be non-empty");
        }
    }

    private void validateUriIfPresent(String uri, java.util.function.Consumer<String> setter) {
        if (uri != null) {
            setter.accept(FedSetupUri.canonicalize(uri));
        }
    }

    private boolean blank(String value) {
        return value == null || value.isBlank();
    }

    private String stringValue(Object value) {
        return value instanceof String string ? string : null;
    }

    private boolean sameOrigin(String first, String second) {
        java.net.URI left = java.net.URI.create(first);
        java.net.URI right = java.net.URI.create(second);
        return left.getScheme().equals(right.getScheme()) && left.getHost().equals(right.getHost())
                && (left.getPort() == -1 ? 443 : left.getPort()) == (right.getPort() == -1 ? 443 : right.getPort());
    }

    private String realmIssuer() {
        return Urls.realmIssuer(session.getContext().getUri(UrlType.FRONTEND).getBaseUri(), realm.getName());
    }

    private DirectInstallationTrust redact(DirectInstallationTrust source) {
        DirectInstallationTrust result = org.keycloak.util.JsonSerialization.valueFromString(
                org.keycloak.util.JsonSerialization.valueAsString(source), DirectInstallationTrust.class);
        result.setReceiverCredentialVaultReference(null);
        return result;
    }

    private FedSetupConnection redact(FedSetupConnection source) {
        FedSetupConnection result = org.keycloak.util.JsonSerialization.valueFromString(
                org.keycloak.util.JsonSerialization.valueAsString(source), FedSetupConnection.class);
        result.getSso().remove("client_secret");
        result.getSso().remove("client_secret_vault_reference");
        result.setCredentialReferenceId(null);
        result.setScimBootstrapCredentialReferenceId(null);
        return result;
    }

    private FedSetupInstallation redact(FedSetupInstallation source) {
        FedSetupInstallation result = org.keycloak.util.JsonSerialization.valueFromString(
                org.keycloak.util.JsonSerialization.valueAsString(source), FedSetupInstallation.class);
        result.setScimCredentialReferenceId(null);
        result.getDesiredSso().remove("client_secret");
        result.getAppliedSso().remove("client_secret");
        redactSsoSecretFingerprint(result.getDesiredSso());
        redactSsoSecretFingerprint(result.getAppliedSso());
        return result;
    }

    private void redactSsoSecretFingerprint(Map<String, String> sso) {
        if (sso != null) sso.remove("client_secret_sha256");
    }

    private String etag(long version) {
        return "\"" + version + "\"";
    }

    private Response error(Response.Status status, String message) {
        return Response.status(status).type(MediaType.APPLICATION_JSON).entity(Map.of("error", "invalid_request", "error_description", message)).build();
    }

    private void audit(OperationType operation, Object representation) {
        adminEvent.operation(operation).resource(ResourceType.CUSTOM).resourcePath(session.getContext().getUri()).representation(representation).success();
    }
}
