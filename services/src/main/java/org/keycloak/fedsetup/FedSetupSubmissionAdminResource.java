/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup;

import java.util.List;
import java.util.Map;
import java.util.Objects;

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
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.fedsetup.representation.CatalogDiscovery;
import org.keycloak.fedsetup.representation.CatalogSubmission;
import org.keycloak.fedsetup.representation.CatalogTarget;
import org.keycloak.fedsetup.representation.FedSetupSubmissionProfile;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;

/** Administrator REST surface for realm-scoped Listing and Catalog Submission state. */
public final class FedSetupSubmissionAdminResource {

    private final KeycloakSession session;
    private final RealmModel realm;
    private final AdminPermissionEvaluator auth;
    private final AdminEventBuilder adminEvent;
    private final RealmFedSetupSubmissionStore store;

    public FedSetupSubmissionAdminResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth,
                                           AdminEventBuilder adminEvent) {
        this.session = session;
        this.realm = realm;
        this.auth = auth;
        this.adminEvent = adminEvent;
        this.store = new RealmFedSetupSubmissionStore(realm);
    }

    @GET
    @Path("listing-profile")
    @Produces(MediaType.APPLICATION_JSON)
    public FedSetupSubmissionProfile getListingProfile() {
        auth.realm().requireViewRealm();
        FedSetupSubmissionProfile profile = store.getListingProfile();
        if (profile == null) throw new NotFoundException();
        return profile;
    }

    @PUT
    @Path("listing-profile")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public FedSetupSubmissionProfile putListingProfile(FedSetupSubmissionProfile profile) {
        auth.realm().requireManageRealm();
        validateListingProfile(profile);
        store.setListingProfile(profile);
        audit(OperationType.UPDATE, profile);
        return profile;
    }

    @GET
    @Path("listing-profile/manifest")
    @Produces(MediaType.APPLICATION_JSON)
    public Map<String, Object> getManifest() {
        auth.realm().requireViewRealm();
        FedSetupSubmissionProfile profile = store.getListingProfile();
        if (profile == null) throw new NotFoundException();
        return SubmissionManifestGenerator.generate(session, realm, profile);
    }

    @GET
    @Path("catalog-targets")
    @Produces(MediaType.APPLICATION_JSON)
    public List<CatalogTarget> getCatalogTargets() {
        auth.realm().requireViewRealm();
        return store.getCatalogTargets().stream().map(this::redact).toList();
    }

    @GET
    @Path("catalog-targets/{targetId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getCatalogTarget(@PathParam("targetId") String targetId) {
        auth.realm().requireViewRealm();
        CatalogTarget target = store.requireCatalogTarget(targetId);
        return Response.ok(redact(target)).header(FedSetupSubmissionConstants.ETAG_HEADER, etag(target.getVersion())).build();
    }

    @POST
    @Path("catalog-targets")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response createCatalogTarget(CatalogTarget target) {
        auth.realm().requireManageRealm();
        validateCatalogTarget(target);
        target.setDiscovery(null);
        CatalogTarget created = store.createCatalogTarget(target);
        CatalogTarget redacted = redact(created);
        audit(OperationType.CREATE, redacted);
        return Response.status(Response.Status.CREATED).type(MediaType.APPLICATION_JSON)
                .header(FedSetupSubmissionConstants.ETAG_HEADER, etag(created.getVersion())).entity(redacted).build();
    }

    @PUT
    @Path("catalog-targets/{targetId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateCatalogTarget(@PathParam("targetId") String targetId,
                                        @HeaderParam(FedSetupSubmissionConstants.IF_MATCH_HEADER) String ifMatch,
                                        CatalogTarget target) {
        auth.realm().requireManageRealm();
        CatalogTarget current = store.requireCatalogTarget(targetId);
        if (!Objects.equals(targetId, target.getId())) return error(Response.Status.BAD_REQUEST, "Catalog target identifier cannot change");
        if (!etag(current.getVersion()).equals(ifMatch)) return error(Response.Status.PRECONDITION_FAILED, "ETag does not match the current resource version");
        if (blank(target.getCredentialVaultReference())) target.setCredentialVaultReference(current.getCredentialVaultReference());
        validateCatalogTarget(target);
        if (!Objects.equals(current.getDiscoveryUri(), target.getDiscoveryUri())
                || !Objects.equals(current.getAuthenticationMethod(), target.getAuthenticationMethod())) target.setDiscovery(null);
        CatalogTarget updated = store.updateCatalogTarget(target, current.getVersion());
        audit(OperationType.UPDATE, redact(updated));
        return Response.ok(redact(updated)).header(FedSetupSubmissionConstants.ETAG_HEADER, etag(updated.getVersion())).build();
    }

    @POST
    @Path("catalog-targets/{targetId}/discover")
    @Produces(MediaType.APPLICATION_JSON)
    public Response discoverCatalogTarget(@PathParam("targetId") String targetId) {
        auth.realm().requireManageRealm();
        CatalogTarget target = store.requireCatalogTarget(targetId);
        CatalogDiscovery discovery = new CatalogSubmissionService(session, realm, store).discover(target);
        CatalogTarget updated = store.updateCatalogTarget(target, target.getVersion());
        audit(OperationType.UPDATE, redact(updated));
        return Response.ok(discovery).header(FedSetupSubmissionConstants.ETAG_HEADER, etag(updated.getVersion())).build();
    }

    @GET
    @Path("catalog-submissions")
    @Produces(MediaType.APPLICATION_JSON)
    public List<CatalogSubmission> getCatalogSubmissions() {
        auth.realm().requireViewRealm();
        return store.getCatalogSubmissions();
    }

    @POST
    @Path("catalog-targets/{targetId}/submissions")
    @Produces(MediaType.APPLICATION_JSON)
    public Response submitToCatalog(@PathParam("targetId") String targetId) {
        auth.realm().requireManageRealm();
        FedSetupSubmissionProfile profile = requireListingProfile();
        CatalogSubmission created = new CatalogSubmissionService(session, realm, store)
                .submit(store.requireCatalogTarget(targetId), profile);
        audit(OperationType.CREATE, created);
        return Response.status(Response.Status.CREATED).entity(created)
                .header(FedSetupSubmissionConstants.ETAG_HEADER, etag(created.getVersion())).build();
    }

    @POST
    @Path("catalog-submissions/{submissionId}/poll")
    @Produces(MediaType.APPLICATION_JSON)
    public Response pollCatalogSubmission(@PathParam("submissionId") String submissionId) {
        auth.realm().requireManageRealm();
        CatalogSubmission updated = new CatalogSubmissionService(session, realm, store).poll(store.requireCatalogSubmission(submissionId));
        audit(OperationType.UPDATE, updated);
        return Response.ok(updated).header(FedSetupSubmissionConstants.ETAG_HEADER, etag(updated.getVersion())).build();
    }

    @PUT
    @Path("catalog-submissions/{submissionId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateCatalogSubmission(@PathParam("submissionId") String submissionId) {
        auth.realm().requireManageRealm();
        CatalogSubmission updated = new CatalogSubmissionService(session, realm, store)
                .update(store.requireCatalogSubmission(submissionId), requireListingProfile());
        audit(OperationType.UPDATE, updated);
        return Response.ok(updated).header(FedSetupSubmissionConstants.ETAG_HEADER, etag(updated.getVersion())).build();
    }

    @DELETE
    @Path("catalog-submissions/{submissionId}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response withdrawCatalogSubmission(@PathParam("submissionId") String submissionId) {
        auth.realm().requireManageRealm();
        CatalogSubmission updated = new CatalogSubmissionService(session, realm, store).withdraw(store.requireCatalogSubmission(submissionId));
        audit(OperationType.DELETE, updated);
        return Response.ok(updated).header(FedSetupSubmissionConstants.ETAG_HEADER, etag(updated.getVersion())).build();
    }

    @POST
    @Path("catalog-submissions/{submissionId}/link")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response linkCatalogSubmission(@PathParam("submissionId") String submissionId, Map<String, String> request) {
        auth.realm().requireManageRealm();
        CatalogSubmission updated = new CatalogSubmissionService(session, realm, store)
                .link(store.requireCatalogSubmission(submissionId), request == null ? null : request.get("listing_id"));
        audit(OperationType.UPDATE, updated);
        return Response.ok(updated).header(FedSetupSubmissionConstants.ETAG_HEADER, etag(updated.getVersion())).build();
    }

    @POST
    @Path("catalog-submissions/{submissionId}/link/poll")
    @Produces(MediaType.APPLICATION_JSON)
    public Response pollCatalogSubmissionLink(@PathParam("submissionId") String submissionId) {
        auth.realm().requireManageRealm();
        CatalogSubmission updated = new CatalogSubmissionService(session, realm, store).pollLink(store.requireCatalogSubmission(submissionId));
        audit(OperationType.UPDATE, updated);
        return Response.ok(updated).header(FedSetupSubmissionConstants.ETAG_HEADER, etag(updated.getVersion())).build();
    }

    private FedSetupSubmissionProfile requireListingProfile() {
        FedSetupSubmissionProfile profile = store.getListingProfile();
        if (profile == null) throw new NotFoundException("Listing profile is required");
        return profile;
    }

    private void validateListingProfile(FedSetupSubmissionProfile profile) {
        if (profile == null) throw new FedSetupSubmissionValidationException("Listing profile is required");
        canonicalizeIfPresent(profile.getLogoUri(), profile::setLogoUri);
        canonicalizeIfPresent(profile.getHomepageUri(), profile::setHomepageUri);
        canonicalizeIfPresent(profile.getTermsOfServiceUri(), profile::setTermsOfServiceUri);
        canonicalizeIfPresent(profile.getPrivacyPolicyUri(), profile::setPrivacyPolicyUri);
        canonicalizeIfPresent(profile.getOidcDocumentationUri(), profile::setOidcDocumentationUri);
        canonicalizeIfPresent(profile.getSamlDocumentationUri(), profile::setSamlDocumentationUri);
        canonicalizeIfPresent(profile.getInitiateLoginUri(), profile::setInitiateLoginUri);
    }

    private void validateCatalogTarget(CatalogTarget target) {
        if (target == null || blank(target.getName()) || blank(target.getDiscoveryUri())) {
            throw new FedSetupSubmissionValidationException("Catalog target name and discoveryUri are required");
        }
        target.setDiscoveryUri(CatalogSubmissionService.canonicalCatalogDiscoveryUri(target.getDiscoveryUri()));
        if (!"oauth2_bearer".equals(target.getAuthenticationMethod())) {
            throw new FedSetupSubmissionValidationException("Only oauth2_bearer Catalog authentication is supported by the default adapter");
        }
        if (blank(target.getCredentialVaultReference()) || !target.getCredentialVaultReference().matches("\\$\\{vault\\.[A-Za-z0-9_.-]+}")) {
            throw new FedSetupSubmissionValidationException("Catalog credentials must be a Keycloak Vault reference");
        }
    }

    private CatalogTarget redact(CatalogTarget source) {
        CatalogTarget result = org.keycloak.util.JsonSerialization.valueFromString(org.keycloak.util.JsonSerialization.valueAsString(source), CatalogTarget.class);
        result.setCredentialVaultReference(null);
        return result;
    }

    private void canonicalizeIfPresent(String value, java.util.function.Consumer<String> setter) {
        if (value != null) setter.accept(FedSetupSubmissionUri.canonicalize(value));
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }

    private static String etag(long version) {
        return "\"" + version + "\"";
    }

    private static Response error(Response.Status status, String message) {
        return Response.status(status).type(MediaType.APPLICATION_JSON)
                .entity(Map.of("error", "invalid_request", "error_description", message)).build();
    }

    private void audit(OperationType operation, Object representation) {
        adminEvent.operation(operation).resource(ResourceType.CUSTOM).resourcePath(session.getContext().getUri()).representation(representation).success();
    }
}
