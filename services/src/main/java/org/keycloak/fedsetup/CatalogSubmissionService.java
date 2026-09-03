/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup;

import java.io.IOException;
import java.net.URI;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import org.keycloak.fedsetup.representation.CatalogDiscovery;
import org.keycloak.fedsetup.representation.CatalogSubmission;
import org.keycloak.fedsetup.representation.CatalogTarget;
import org.keycloak.fedsetup.representation.FedSetupSubmissionProfile;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.http.simple.SimpleHttpRequest;
import org.keycloak.http.simple.SimpleHttpResponse;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.util.JsonSerialization;
import org.keycloak.vault.VaultStringSecret;

import com.fasterxml.jackson.databind.JsonNode;
import org.apache.http.client.config.RequestConfig;

/** Default adapter for the standard FedSetup Submission API. */
public final class CatalogSubmissionService {

    private static final Pattern VAULT_REFERENCE = Pattern.compile("\\$\\{vault\\.[A-Za-z0-9_.-]+}");
    // Section 4.1 supported_capabilities / approved_capabilities enumeration. Distinct from
    // express_configuration.capabilities (Section 6.4), which uses "scim"/"provider_delegation"/"id_jag".
    private static final Set<String> STANDARD_CAPABILITIES = Set.of("provisioning", "express_configuration", "id_jag", "marketplace", "identity_platform");
    private static final RequestConfig NO_REDIRECTS = RequestConfig.copy(RequestConfig.DEFAULT).setRedirectsEnabled(false).build();

    private final KeycloakSession session;
    private final RealmModel realm;
    private final RealmFedSetupSubmissionStore store;

    public CatalogSubmissionService(KeycloakSession session, RealmModel realm, RealmFedSetupSubmissionStore store) {
        this.session = session;
        this.realm = realm;
        this.store = store;
    }

    public CatalogDiscovery discover(CatalogTarget target) {
        requireActive(target);
        CatalogDiscovery discovered = execute(target, target.getDiscoveryUri(), http().doGet(target.getDiscoveryUri()).acceptJson(), response -> {
            requireStatus(response, 200);
            return JsonSerialization.readValue(response.asString(), CatalogDiscovery.class);
        }, false);
        validateDiscovery(target, discovered);
        target.setDiscovery(discovered);
        return discovered;
    }

    public CatalogSubmission submit(CatalogTarget target, FedSetupSubmissionProfile profile) {
        CatalogDiscovery discovery = requireDiscovery(target);
        Map<String, Object> manifest = SubmissionManifestGenerator.generate(session, realm, profile);
        validateCapabilities(discovery, manifest);
        return execute(target, discovery.getSubmissionEndpoint(), http().doPost(discovery.getSubmissionEndpoint()).json(manifest).acceptJson(), response -> {
            requireStatus(response, 202);
            CatalogSubmission submission = responseToSubmission(target, response);
            return store.createCatalogSubmission(submission);
        }, true);
    }

    public CatalogSubmission update(CatalogSubmission submission, FedSetupSubmissionProfile profile) {
        CatalogTarget target = store.requireCatalogTarget(submission.getCatalogTargetId());
        CatalogDiscovery discovery = requireDiscovery(target);
        if (blank(submission.getRemoteEtag())) {
            throw new FedSetupSubmissionValidationException("Poll the Catalog Submission to obtain its ETag before updating it");
        }
        Map<String, Object> manifest = SubmissionManifestGenerator.generate(session, realm, profile);
        if (!blank(submission.getListingId())) manifest.put("listing_id", submission.getListingId());
        validateCapabilities(discovery, manifest);
        String endpoint = trimTrailingSlash(discovery.getSubmissionEndpoint()) + "/" + pathSegment(submission.getSubmissionId());
        return execute(target, endpoint, http().doPut(endpoint).header(FedSetupSubmissionConstants.IF_MATCH_HEADER, submission.getRemoteEtag())
                .json(manifest).acceptJson(), response -> {
            requireStatus(response, 202);
            mergeSubmissionResponse(target, submission, response);
            return store.updateCatalogSubmission(submission, submission.getVersion());
        }, true);
    }

    public CatalogSubmission poll(CatalogSubmission submission) {
        CatalogTarget target = store.requireCatalogTarget(submission.getCatalogTargetId());
        if (blank(submission.getStatusUri())) throw new FedSetupSubmissionValidationException("Catalog Submission has no status URI");
        return execute(target, submission.getStatusUri(), http().doGet(submission.getStatusUri()).acceptJson(), response -> {
            requireStatus(response, 200);
            mergeSubmissionResponse(target, submission, response);
            return store.updateCatalogSubmission(submission, submission.getVersion());
        }, true);
    }

    public CatalogSubmission withdraw(CatalogSubmission submission) {
        CatalogTarget target = store.requireCatalogTarget(submission.getCatalogTargetId());
        CatalogDiscovery discovery = requireDiscovery(target);
        String endpoint = trimTrailingSlash(discovery.getSubmissionEndpoint()) + "/" + pathSegment(submission.getSubmissionId());
        return execute(target, endpoint, http().doDelete(endpoint), response -> {
            requireStatus(response, 204);
            submission.setStatus("withdrawn");
            return store.updateCatalogSubmission(submission, submission.getVersion());
        }, true);
    }

    public CatalogSubmission link(CatalogSubmission submission, String listingId) {
        if (blank(listingId)) throw new FedSetupSubmissionValidationException("listingId is required");
        CatalogTarget target = store.requireCatalogTarget(submission.getCatalogTargetId());
        CatalogDiscovery discovery = requireDiscovery(target);
        String endpoint = trimTrailingSlash(discovery.getSubmissionEndpoint()) + "/" + pathSegment(submission.getSubmissionId()) + "/link";
        return execute(target, endpoint, http().doPost(endpoint).json(Map.of("listing_id", listingId)).acceptJson(), response -> {
            requireStatus(response, 202);
            JsonNode body = json(response);
            submission.setListingId(listingId);
            String linkStatusUri = text(body, "link_status_uri", false);
            if (linkStatusUri != null) submission.setLinkStatusUri(catalogUri(target, linkStatusUri));
            return store.updateCatalogSubmission(submission, submission.getVersion());
        }, true);
    }

    public CatalogSubmission pollLink(CatalogSubmission submission) {
        CatalogTarget target = store.requireCatalogTarget(submission.getCatalogTargetId());
        if (blank(submission.getLinkStatusUri())) throw new FedSetupSubmissionValidationException("Catalog Submission has no link status URI");
        return execute(target, submission.getLinkStatusUri(), http().doGet(submission.getLinkStatusUri()).acceptJson(), response -> {
            requireStatus(response, 200);
            JsonNode body = json(response);
            String linkStatus = text(body, "status", true);
            if (!Set.of("pending", "linked", "rejected").contains(linkStatus)) {
                throw new FedSetupSubmissionValidationException("Catalog returned an unrecognized link status");
            }
            submission.setLinkStatus(linkStatus);
            if ("linked".equals(linkStatus)) {
                submission.setStatusUri(catalogUri(target, text(body, "status_uri", true)));
                String remoteEtag = responseEtag(body, response.getFirstHeader(FedSetupSubmissionConstants.ETAG_HEADER));
                if (remoteEtag != null) submission.setRemoteEtag(remoteEtag);
            }
            return store.updateCatalogSubmission(submission, submission.getVersion());
        }, true);
    }

    private CatalogDiscovery requireDiscovery(CatalogTarget target) {
        requireActive(target);
        CatalogDiscovery discovery = target.getDiscovery();
        if (discovery == null) throw new FedSetupSubmissionValidationException("Discover the Catalog before submitting");
        validateDiscovery(target, discovery);
        if (!discovery.getSupportedAuthMethods().contains(target.getAuthenticationMethod())) {
            throw new FedSetupSubmissionValidationException("Catalog does not support the configured authentication method");
        }
        return discovery;
    }

    static String canonicalCatalogDiscoveryUri(String raw) {
        String canonical = FedSetupSubmissionUri.canonicalize(raw);
        if (!canonical.endsWith("/.well-known/fedsetup-catalog")) {
            throw new FedSetupSubmissionValidationException("Catalog discoveryUri must be the Catalog's /.well-known/fedsetup-catalog endpoint");
        }
        FedSetupSubmissionUri.requirePublicAddress(canonical, "Catalog discovery source");
        return canonical;
    }

    private void validateDiscovery(CatalogTarget target, CatalogDiscovery discovery) {
        if (discovery == null || !"1.0".equals(discovery.getSubmissionVersion()) || blank(discovery.getSubmissionEndpoint())
                || blank(discovery.getStatusEndpointTemplate()) || discovery.getSupportedProtocols().isEmpty()) {
            throw new FedSetupSubmissionValidationException("Catalog discovery does not support the standard FedSetup Submission API");
        }
        discovery.setSubmissionEndpoint(catalogUri(target, discovery.getSubmissionEndpoint()));
        if (!discovery.getStatusEndpointTemplate().contains("{submission_id}")) {
            throw new FedSetupSubmissionValidationException("Catalog status_endpoint_template must contain {submission_id}");
        }
        String statusProbe = discovery.getStatusEndpointTemplate().replace("{submission_id}", "submission-id");
        catalogUri(target, statusProbe);
        if (!Set.of("oidc", "saml").containsAll(discovery.getSupportedProtocols())
                || !STANDARD_CAPABILITIES.containsAll(discovery.getSupportedCapabilities())
                || !Set.of("oauth2_bearer", "mtls").containsAll(discovery.getSupportedAuthMethods())) {
            throw new FedSetupSubmissionValidationException("Catalog discovery contains an unsupported protocol, capability, or authentication method");
        }
        if (discovery.getSupportedAuthMethods().isEmpty()) discovery.getSupportedAuthMethods().add("oauth2_bearer");
    }

    @SuppressWarnings("unchecked")
    static void validateCapabilities(CatalogDiscovery discovery, Map<String, Object> manifest) {
        Map<String, Object> identity = (Map<String, Object>) manifest.get("identity");
        if (identity.containsKey("oidc") && !discovery.getSupportedProtocols().contains("oidc")
                || identity.containsKey("saml") && !discovery.getSupportedProtocols().contains("saml")) {
            throw new FedSetupSubmissionValidationException("Catalog does not support every SSO protocol in the generated manifest");
        }
        // A catalog cannot silently publish an optional Manifest section it
        // does not advertise. Preserve the administrator's profile and fail
        // locally instead of changing the Manifest on its way to the Catalog.
        for (String capability : STANDARD_CAPABILITIES) {
            if (manifest.containsKey(capability) && !discovery.getSupportedCapabilities().contains(capability)) {
                throw new FedSetupSubmissionValidationException("Catalog does not support the " + capability + " Manifest section");
            }
        }
    }

    private CatalogSubmission responseToSubmission(CatalogTarget target, SimpleHttpResponse response) throws IOException {
        JsonNode body = json(response);
        CatalogSubmission submission = new CatalogSubmission();
        submission.setCatalogTargetId(target.getId());
        submission.setSubmissionId(text(body, "submission_id", true));
        submission.setStatus(text(body, "status", true));
        submission.setStatusUri(catalogUri(target, text(body, "status_uri", true)));
        mergeSubmissionResponse(target, submission, body, response.getFirstHeader(FedSetupSubmissionConstants.ETAG_HEADER));
        return submission;
    }

    private void mergeSubmissionResponse(CatalogTarget target, CatalogSubmission submission, SimpleHttpResponse response) throws IOException {
        mergeSubmissionResponse(target, submission, json(response), response.getFirstHeader(FedSetupSubmissionConstants.ETAG_HEADER));
    }

    private void mergeSubmissionResponse(CatalogTarget target, CatalogSubmission submission, JsonNode body, String etag) {
        String status = text(body, "status", false);
        if (status != null) submission.setStatus(status);
        String submissionId = text(body, "submission_id", false);
        if (submissionId != null) submission.setSubmissionId(submissionId);
        String listingId = text(body, "listing_id", false);
        if (listingId != null) submission.setListingId(listingId);
        String statusUri = text(body, "status_uri", false);
        if (statusUri != null) submission.setStatusUri(catalogUri(target, statusUri));
        String completion = text(body, "review_estimated_completion", false);
        if (completion != null) submission.setReviewEstimatedCompletion(completion);
        String comments = text(body, "reviewer_comments", false);
        if (comments != null) submission.setReviewerComments(comments);
        if (etag != null && !etag.isBlank()) submission.setRemoteEtag(etag);
    }

    static String responseEtag(JsonNode body, String httpEtag) {
        return blank(httpEtag) ? text(body, "etag", false) : httpEtag;
    }

    private <T> T execute(CatalogTarget target, String endpoint, SimpleHttpRequest request, ResponseMapper<T> mapper, boolean authenticated) {
        FedSetupSubmissionUri.requirePublicAddress(endpoint, "Catalog endpoint");
        if (authenticated) authenticate(target, request);
        try (SimpleHttpResponse response = request.asResponse()) {
            return mapper.map(response);
        } catch (FedSetupSubmissionValidationException e) {
            throw e;
        } catch (IOException | RuntimeException e) {
            throw new FedSetupSubmissionValidationException("Catalog request failed", e);
        }
    }

    private SimpleHttp http() {
        return SimpleHttp.create(session).withRequestConfig(NO_REDIRECTS);
    }

    private void authenticate(CatalogTarget target, SimpleHttpRequest request) {
        if (!"oauth2_bearer".equals(target.getAuthenticationMethod())) {
            throw new FedSetupSubmissionValidationException("Only oauth2_bearer Catalog authentication is supported by the default adapter");
        }
        if (blank(target.getCredentialVaultReference()) || !VAULT_REFERENCE.matcher(target.getCredentialVaultReference()).matches()) {
            throw new FedSetupSubmissionValidationException("Catalog credentials must be a Keycloak Vault reference");
        }
        try (VaultStringSecret secret = session.vault().getStringSecret(target.getCredentialVaultReference())) {
            String token = secret.get().orElseThrow(() -> new FedSetupSubmissionValidationException("Catalog credential could not be resolved from the Keycloak Vault"));
            request.auth(token);
        }
    }

    private void requireActive(CatalogTarget target) {
        if (target == null || !target.isActive()) throw new FedSetupSubmissionValidationException("Catalog target is not active");
    }

    private static JsonNode json(SimpleHttpResponse response) throws IOException {
        return JsonSerialization.mapper.readTree(response.asString());
    }

    private static String text(JsonNode body, String name, boolean required) {
        JsonNode node = body.get(name);
        if (node != null && node.isTextual() && !node.asText().isBlank()) return node.asText();
        if (required) throw new FedSetupSubmissionValidationException("Catalog response is missing " + name);
        return null;
    }

    private static void requireStatus(SimpleHttpResponse response, int expected) throws IOException {
        if (response.getStatus() != expected) {
            throw new FedSetupSubmissionValidationException("Catalog returned HTTP " + response.getStatus());
        }
    }

    private static String trimTrailingSlash(String value) {
        return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }

    private static String pathSegment(String value) {
        if (blank(value) || value.contains("/") || value.contains("?")) throw new FedSetupSubmissionValidationException("Catalog submission identifier is invalid");
        return value;
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }

    private static String catalogUri(CatalogTarget target, String raw) {
        String canonical = FedSetupSubmissionUri.canonicalize(raw);
        URI configured = URI.create(target.getDiscoveryUri());
        URI candidate = URI.create(canonical);
        if (!configured.getScheme().equals(candidate.getScheme()) || !configured.getHost().equals(candidate.getHost())
                || effectivePort(configured) != effectivePort(candidate)) {
            throw new FedSetupSubmissionValidationException("Catalog endpoint must use the configured Catalog origin");
        }
        return canonical;
    }

    private static int effectivePort(URI uri) {
        return uri.getPort() == -1 ? 443 : uri.getPort();
    }

    @FunctionalInterface
    private interface ResponseMapper<T> {
        T map(SimpleHttpResponse response) throws IOException;
    }
}
