package org.keycloak.fedsetup;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import org.keycloak.common.util.Time;
import org.keycloak.fedsetup.model.ConnectionRecord;
import org.keycloak.fedsetup.model.ConsentCodeRecord;
import org.keycloak.fedsetup.model.DeferredApprovalProposalRecord;
import org.keycloak.fedsetup.model.DirectInstallationTrustRecord;
import org.keycloak.fedsetup.model.PendingTrustAuthorizationRecord;
import org.keycloak.fedsetup.representations.CimdDocumentRepresentation;
import org.keycloak.fedsetup.representations.ConfigurationRequestRepresentation;
import org.keycloak.fedsetup.representations.ConfigurationResponseRepresentation;
import org.keycloak.fedsetup.representations.ConnectionQueryResponseRepresentation;
import org.keycloak.fedsetup.representations.DeferredApprovalResponseRepresentation;
import org.keycloak.fedsetup.representations.DiscoveryDocumentRepresentation;
import org.keycloak.fedsetup.security.FedSetupFetchService;
import org.keycloak.fedsetup.security.FedSetupJwtService;
import org.keycloak.fedsetup.storage.FedSetupStore;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.util.JsonSerialization;

/**
 * Core protocol engine for FedSetup Express Configuration, Deferred Trust, and Extensions.
 */
public class FedSetupService {

    private static final int DEFAULT_DEFERRED_INTERVAL_SECONDS = 300;
    private static final long DEFAULT_DEFERRED_EXPIRES_IN_SECONDS = 604800L; // 7 days
    private static final long CONSENT_CODE_TTL_SECONDS = 300L; // 5 minutes

    private final KeycloakSession session;
    private final RealmModel realm;
    private final FedSetupStore store;
    private final FedSetupFetchService fetchService;
    private final FedSetupJwtService jwtService;
    private final FedSetupProvisioningService provisioningService;

    public FedSetupService(KeycloakSession session, RealmModel realm) {
        this(session, realm, new FedSetupFetchService(session, realm));
    }

    public FedSetupService(KeycloakSession session, RealmModel realm, FedSetupFetchService fetchService) {
        this.session = session;
        this.realm = realm;
        this.store = new FedSetupStore(session, realm);
        this.fetchService = fetchService;
        this.jwtService = new FedSetupJwtService(session, realm, fetchService);
        this.provisioningService = new FedSetupProvisioningService(session, realm, fetchService);
    }

    public FedSetupStore getStore() {
        return store;
    }

    public FedSetupFetchService getFetchService() {
        return fetchService;
    }

    public FedSetupJwtService getJwtService() {
        return jwtService;
    }

    public FedSetupProvisioningService getProvisioningService() {
        return provisioningService;
    }

    public boolean isEnabled() {
        return realm == null || !"false".equalsIgnoreCase(realm.getAttribute(FedSetupConstants.ATTR_ENABLED));
    }

    public boolean isSingleTenantMode() {
        if (realm == null) {
            return false;
        }
        return Boolean.parseBoolean(realm.getAttribute("fedsetup.single_tenant"))
                || "single".equalsIgnoreCase(realm.getAttribute(FedSetupConstants.ATTR_TENANT_MODE));
    }

    public String getEffectiveTenantId() {
        return realm != null ? realm.getName() : "default";
    }

    public boolean isMultipleSsoCardinality() {
        if (realm == null) {
            return true;
        }
        String card = realm.getAttribute(FedSetupConstants.ATTR_SSO_CARDINALITY);
        return card == null || !"single".equalsIgnoreCase(card);
    }

    // ---- 1. Discovery Document ({{disc}}) ----

    public DiscoveryDocumentRepresentation buildDiscoveryDocument(String baseUri) {
        String realmBaseUri = baseUri + "/realms/" + realm.getName();
        String fedsetupBase = realmBaseUri + "/" + FedSetupConstants.PROVIDER_ID;

        DiscoveryDocumentRepresentation doc = new DiscoveryDocumentRepresentation();
        doc.setFedsetupVersion("1.0");
        doc.setApplicationBaseUri(realmBaseUri);
        doc.setApplicationName(realm.getDisplayName() != null && !realm.getDisplayName().isBlank()
                ? realm.getDisplayName()
                : realm.getName());
        doc.setApplicationTenantMode(isSingleTenantMode() ? "single" : "multiple");
        doc.setSsoConnectionCardinality(isMultipleSsoCardinality() ? "multiple" : "single");

        doc.setInstallationTrustProfilesSupported(List.of(
                FedSetupConstants.TRUST_PROFILE_BACK_CHANNEL,
                FedSetupConstants.TRUST_PROFILE_FRONT_CHANNEL
        ));
        doc.setInstallationEndpoint(fedsetupBase + "/install");
        doc.setInstallationConsentEndpoint(fedsetupBase + "/consent");
        doc.setInstallationTrustJwksUri(fedsetupBase + "/trust-jwks.json");
        doc.setInstallationTrustDeferredApprovalSupported(Boolean.TRUE);

        doc.setConfigurationEndpoint(fedsetupBase + "/configure");
        doc.setConfigurationResource(fedsetupBase + "/configure");
        doc.setAuthorizationServer(realmBaseUri);
        doc.setConnectionEndpointTemplate(fedsetupBase + "/connection/{connection_id}");
        doc.setConnectionQueryEndpoint(fedsetupBase + "/connections");

        doc.setProviderDelegationProfilesSupported(List.of(
                "urn:ietf:params:fedsetup:config-delegate:ssf-stream"
        ));
        doc.setFederationExtensionProfilesSupported(List.of(
                FedSetupConstants.EXT_STATIC_SECRET_DELIVERY,
                FedSetupConstants.EXT_SCIM_OAUTH_CC
        ));

        Map<String, Object> caps = new LinkedHashMap<>();

        Map<String, Object> oidcCap = new LinkedHashMap<>();
        String appCimdUri = realm.getAttribute("fedsetup.oidc.client_id_metadata_uri");
        if (appCimdUri != null && !appCimdUri.isBlank()) {
            oidcCap.put("client_id_metadata_uri", appCimdUri);
        } else {
            Map<String, Object> clientSec = new LinkedHashMap<>();
            clientSec.put("pkce_required", Boolean.TRUE);
            clientSec.put("dpop_bound_access_tokens", Boolean.FALSE);
            oidcCap.put("client_security", clientSec);
        }
        caps.put("oidc", oidcCap);

        Map<String, Object> samlCap = new LinkedHashMap<>();
        samlCap.put("sp_initiated_slo_supported", Boolean.TRUE);
        caps.put("saml", samlCap);

        Map<String, Object> scimCap = new LinkedHashMap<>();
        scimCap.put("features_supported", List.of(
                "PUSH_NEW_USERS",
                "PUSH_PROFILE_UPDATES",
                "PUSH_USER_UPDATES",
                "PUSH_USER_DEACTIVATION",
                "PUSH_GROUPS"
        ));
        scimCap.put("auth_modes_supported", List.of(
                "SAAS_ISSUED_BEARER",
                "OAUTH2_CLIENT_CREDENTIALS"
        ));
        caps.put("scim", scimCap);

        Map<String, Object> idJagCap = new LinkedHashMap<>();
        idJagCap.put("requester_types_supported", List.of("app_instance", "workload_principal"));
        idJagCap.put("client_credential_mechanisms_supported", List.of("CIMD", "CLIENT_SECRET"));
        caps.put("id_jag", idJagCap);

        caps.put("connection_query", Collections.emptyMap());
        caps.put("layered_updates", Collections.emptyMap());

        doc.setCapabilities(caps);
        return doc;
    }

    // ---- 2. Front-Channel Consent Endpoint ({{trust-front-consent}}) ----

    public Response handleConsentRequest(MultivaluedMap<String, String> queryParams, String decision, String csrfToken, String baseUri) {
        // Reject repeated parameters ({{trust-front-consent}})
        for (Map.Entry<String, List<String>> entry : queryParams.entrySet()) {
            if (entry.getValue() != null && entry.getValue().size() > 1) {
                throw FedSetupException.invalidRequest("Repeated query parameter is not permitted: " + entry.getKey());
            }
        }

        String clientId = queryParams.getFirst("client_id");
        String redirectUriParam = queryParams.getFirst("redirect_uri");
        String state = queryParams.getFirst("state");
        String responseType = queryParams.getFirst("response_type");
        String scope = queryParams.getFirst("scope");
        String idpIssuer = queryParams.getFirst("idp_issuer");
        String appTenantHint = queryParams.getFirst("application_tenant_id");

        if (clientId == null || clientId.isBlank()) {
            throw FedSetupException.invalidRequest("Missing required parameter: client_id");
        }
        if (state == null || state.isBlank()) {
            throw FedSetupException.invalidRequest("Missing required parameter: state");
        }

        // Resolve CIMD and verify redirect_uri BEFORE redirecting anywhere ({{trust-front-response}})
        CimdDocumentRepresentation cimd = fetchService.fetchAndValidateCimd(clientId, true);
        List<String> cimdRedirectUris = cimd.getRedirectUris();
        if (cimdRedirectUris == null || cimdRedirectUris.isEmpty()) {
            throw FedSetupException.invalidRequest("Runtime CIMD document contains no redirect_uris");
        }

        String resolvedRedirectUri;
        boolean redirectUriExplicit;
        if (redirectUriParam != null && !redirectUriParam.isBlank()) {
            if (!cimdRedirectUris.contains(redirectUriParam)) {
                // Must NOT redirect to unvalidated redirect_uri
                throw FedSetupException.invalidRequest("redirect_uri does not exactly match any entry in CIMD redirect_uris");
            }
            resolvedRedirectUri = redirectUriParam;
            redirectUriExplicit = true;
        } else {
            if (cimdRedirectUris.size() != 1) {
                throw FedSetupException.invalidRequest("redirect_uri is required when CIMD registers multiple redirect_uris");
            }
            resolvedRedirectUri = cimdRedirectUris.get(0);
            redirectUriExplicit = false;
        }

        // Now that resolvedRedirectUri is verified against CIMD, parameter errors redirect back with error=...
        if (!"code".equals(responseType)) {
            return buildConsentErrorRedirect(resolvedRedirectUri, "unsupported_response_type", "response_type must be 'code'", state);
        }
        if (!FedSetupConstants.SCOPE_TRUST.equals(scope)) {
            return buildConsentErrorRedirect(resolvedRedirectUri, "invalid_scope", "scope must be 'fedsetup:trust'", state);
        }
        if (idpIssuer == null || idpIssuer.isBlank()) {
            return buildConsentErrorRedirect(resolvedRedirectUri, "invalid_request", "idp_issuer is required", state);
        }
        try {
            fetchService.validateHttpsUri(idpIssuer, "idp_issuer", true);
        } catch (FedSetupException e) {
            return buildConsentErrorRedirect(resolvedRedirectUri, "invalid_request", e.getErrorDescription(), state);
        }

        String effectiveTenant = getEffectiveTenantId();
        if (!isSingleTenantMode()) {
            if (appTenantHint == null || appTenantHint.isBlank()) {
                return buildConsentErrorRedirect(resolvedRedirectUri, "invalid_request", "application_tenant_id is required", state);
            }
            if (!effectiveTenant.equals(appTenantHint)) {
                return buildConsentErrorRedirect(resolvedRedirectUri, "untrusted_issuer", "Tenant mismatch", state);
            }
        } else if (appTenantHint != null && !appTenantHint.isBlank() && !effectiveTenant.equals(appTenantHint)) {
            return buildConsentErrorRedirect(resolvedRedirectUri, "untrusted_issuer", "Tenant mismatch", state);
        }

        List<String> requestedCaps = parseSpaceDelimited(queryParams.getFirst("authorized_capabilities"));
        List<String> requestedDeleg = parseSpaceDelimited(queryParams.getFirst("provider_delegation_profiles"));
        List<String> requestedExt = parseSpaceDelimited(queryParams.getFirst("federation_extension_profiles"));

        if ("deny".equalsIgnoreCase(decision)) {
            return buildConsentErrorRedirect(resolvedRedirectUri, "access_denied", "The Application Tenant Admin denied the request", state);
        }

        if ("approve".equalsIgnoreCase(decision)) {
            List<String> approvedCaps = queryParams.containsKey("approved_capabilities")
                    ? parseSpaceDelimited(queryParams.getFirst("approved_capabilities"))
                    : requestedCaps;
            List<String> approvedDeleg = queryParams.containsKey("approved_delegation_profiles")
                    ? parseSpaceDelimited(queryParams.getFirst("approved_delegation_profiles"))
                    : requestedDeleg;
            List<String> approvedExt = queryParams.containsKey("approved_extension_profiles")
                    ? parseSpaceDelimited(queryParams.getFirst("approved_extension_profiles"))
                    : requestedExt;

            // Ensure approved sets are subsets of requested sets ({{trust-front-consent}})
            if (!requestedCaps.containsAll(approvedCaps)
                    || !requestedDeleg.containsAll(approvedDeleg)
                    || !requestedExt.containsAll(approvedExt)) {
                return buildConsentErrorRedirect(resolvedRedirectUri, "invalid_request", "Cannot approve scope outside requested set", state);
            }

            ConsentCodeRecord codeRecord = new ConsentCodeRecord();
            codeRecord.setCode(FedSetupStore.generateSecureId("fsc"));
            codeRecord.setApplicationTenantId(effectiveTenant);
            codeRecord.setIdpIssuer(idpIssuer);
            codeRecord.setCimdUri(clientId);
            codeRecord.setRedirectUri(redirectUriExplicit ? resolvedRedirectUri : null);
            codeRecord.setState(state);
            codeRecord.setRequestedCapabilities(requestedCaps);
            codeRecord.setRequestedDelegationProfiles(requestedDeleg);
            codeRecord.setRequestedExtensionProfiles(requestedExt);
            codeRecord.setApprovedCapabilities(approvedCaps);
            codeRecord.setApprovedDelegationProfiles(approvedDeleg);
            codeRecord.setApprovedExtensionProfiles(approvedExt);
            codeRecord.setExpiresAt(Time.currentTime() + CONSENT_CODE_TTL_SECONDS);
            store.saveConsentCode(codeRecord);

            String sep = resolvedRedirectUri.contains("?") ? "&" : "?";
            String location = resolvedRedirectUri + sep
                    + "code=" + urlEncode(codeRecord.getCode())
                    + "&state=" + urlEncode(state);
            return Response.status(Response.Status.FOUND)
                    .location(URI.create(location))
                    .header("Cache-Control", "no-store")
                    .header("Pragma", "no-cache")
                    .build();
        }

        // Render interactive HTML Consent UI for Application Tenant Admin ({{sec-consent}})
        String html = renderConsentHtml(
                cimd,
                idpIssuer,
                effectiveTenant,
                resolvedRedirectUri,
                redirectUriExplicit,
                state,
                requestedCaps,
                requestedDeleg,
                requestedExt,
                baseUri);
        return Response.ok(html, "text/html; charset=UTF-8")
                .header("X-Frame-Options", "DENY")
                .header("Content-Security-Policy", "frame-ancestors 'none'")
                .header("Cache-Control", "no-store")
                .build();
    }

    private Response buildConsentErrorRedirect(String redirectUri, String error, String description, String state) {
        String sep = redirectUri.contains("?") ? "&" : "?";
        StringBuilder sb = new StringBuilder(redirectUri).append(sep)
                .append("error=").append(urlEncode(error));
        if (description != null && !description.isBlank()) {
            sb.append("&error_description=").append(urlEncode(description));
        }
        if (state != null && !state.isBlank()) {
            sb.append("&state=").append(urlEncode(state));
        }
        return Response.status(Response.Status.FOUND)
                .location(URI.create(sb.toString()))
                .header("Cache-Control", "no-store")
                .build();
    }

    private String renderConsentHtml(
            CimdDocumentRepresentation cimd,
            String idpIssuer,
            String applicationTenantId,
            String resolvedRedirectUri,
            boolean redirectUriExplicit,
            String state,
            List<String> requestedCaps,
            List<String> requestedDeleg,
            List<String> requestedExt,
            String baseUri) {
        String clientName = cimd.getClientName() != null ? escapeHtml(cimd.getClientName()) : escapeHtml(cimd.getClientId());
        String actionUrl = baseUri + "/realms/" + realm.getName() + "/" + FedSetupConstants.PROVIDER_ID + "/consent";
        String capsStr = String.join(" ", requestedCaps);
        String delegStr = String.join(" ", requestedDeleg);
        String extStr = String.join(" ", requestedExt);

        return "<!DOCTYPE html>\n"
                + "<html lang=\"en\">\n"
                + "<head>\n"
                + "  <meta charset=\"UTF-8\">\n"
                + "  <title>FedSetup Direct Installation Trust Consent - " + escapeHtml(realm.getName()) + "</title>\n"
                + "  <style>\n"
                + "    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; margin: 0; padding: 40px; }\n"
                + "    .card { max-width: 560px; margin: 0 auto; background: #fff; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.08); padding: 32px; }\n"
                + "    h1 { font-size: 20px; margin-top: 0; color: #151515; }\n"
                + "    .field { margin: 12px 0; font-size: 14px; color: #333; }\n"
                + "    .field strong { color: #000; }\n"
                + "    .badge { display: inline-block; background: #e7f1fa; color: #0066cc; padding: 2px 8px; border-radius: 4px; margin-right: 6px; font-family: monospace; }\n"
                + "    .actions { margin-top: 24px; display: flex; gap: 12px; }\n"
                + "    button { padding: 10px 20px; border-radius: 4px; border: none; font-size: 14px; cursor: pointer; font-weight: 600; }\n"
                + "    .btn-approve { background: #0066cc; color: #fff; }\n"
                + "    .btn-deny { background: #d9534f; color: #fff; }\n"
                + "  </style>\n"
                + "</head>\n"
                + "<body>\n"
                + "  <div class=\"card\">\n"
                + "    <h1>Authorize Federation Installation Trust</h1>\n"
                + "    <div class=\"field\"><strong>Identity Provider Platform:</strong> " + clientName + "</div>\n"
                + "    <div class=\"field\"><strong>Runtime CIMD URI:</strong> <code>" + escapeHtml(cimd.getClientId()) + "</code></div>\n"
                + "    <div class=\"field\"><strong>IdP Tenant Issuer:</strong> <code>" + escapeHtml(idpIssuer) + "</code></div>\n"
                + "    <div class=\"field\"><strong>Application Tenant (Realm):</strong> <code>" + escapeHtml(applicationTenantId) + "</code></div>\n"
                + "    <div class=\"field\"><strong>Requested Capabilities:</strong> "
                + (requestedCaps.isEmpty() ? "<em>None</em>" : requestedCaps.stream().map(c -> "<span class=\"badge\">" + escapeHtml(c) + "</span>").reduce("", String::concat))
                + "</div>\n"
                + "    <form method=\"GET\" action=\"" + escapeHtml(actionUrl) + "\">\n"
                + "      <input type=\"hidden\" name=\"response_type\" value=\"code\" />\n"
                + "      <input type=\"hidden\" name=\"client_id\" value=\"" + escapeHtml(cimd.getClientId()) + "\" />\n"
                + "      <input type=\"hidden\" name=\"idp_issuer\" value=\"" + escapeHtml(idpIssuer) + "\" />\n"
                + (redirectUriExplicit ? "      <input type=\"hidden\" name=\"redirect_uri\" value=\"" + escapeHtml(resolvedRedirectUri) + "\" />\n" : "")
                + "      <input type=\"hidden\" name=\"application_tenant_id\" value=\"" + escapeHtml(applicationTenantId) + "\" />\n"
                + "      <input type=\"hidden\" name=\"scope\" value=\"fedsetup:trust\" />\n"
                + "      <input type=\"hidden\" name=\"state\" value=\"" + escapeHtml(state) + "\" />\n"
                + (!capsStr.isEmpty() ? "      <input type=\"hidden\" name=\"authorized_capabilities\" value=\"" + escapeHtml(capsStr) + "\" />\n" : "")
                + (!delegStr.isEmpty() ? "      <input type=\"hidden\" name=\"provider_delegation_profiles\" value=\"" + escapeHtml(delegStr) + "\" />\n" : "")
                + (!extStr.isEmpty() ? "      <input type=\"hidden\" name=\"federation_extension_profiles\" value=\"" + escapeHtml(extStr) + "\" />\n" : "")
                + "      <div class=\"actions\">\n"
                + "        <button type=\"submit\" name=\"decision\" value=\"approve\" class=\"btn-approve\">Approve Installation</button>\n"
                + "        <button type=\"submit\" name=\"decision\" value=\"deny\" class=\"btn-deny\">Deny</button>\n"
                + "      </div>\n"
                + "    </form>\n"
                + "  </div>\n"
                + "</body>\n"
                + "</html>";
    }

    // ---- 3. Installation Endpoint (POST /install) ({{trust-back}}, {{trust-front-confirm}}, {{deferred}}) ----

    public Response handleInstall(
            String authorizationHeader,
            String idempotencyKey,
            byte[] rawBodyBytes,
            String baseUri) {

        String realmBaseUri = baseUri + "/realms/" + realm.getName();
        String installationEndpoint = realmBaseUri + "/" + FedSetupConstants.PROVIDER_ID + "/install";
        String effectiveTenant = getEffectiveTenantId();

        String rawJwt = FedSetupJwtService.extractBearerToken(authorizationHeader);
        byte[] body = rawBodyBytes != null ? rawBodyBytes : new byte[0];

        FedSetupJwtService.ValidatedTrustJwt jwt = jwtService.parseAndValidateClaims(
                rawJwt,
                "POST",
                installationEndpoint,
                body,
                isSingleTenantMode(),
                effectiveTenant);

        // Verify tenant agreement between path-scoped Application Base URI and JWT application_tenant_id ({{disc-doc}})
        if (!effectiveTenant.equals(jwt.getApplicationTenantId())) {
            throw FedSetupException.untrustedIssuer("application_tenant_id does not match target realm");
        }

        if (idempotencyKey == null || idempotencyKey.isBlank()) {
            throw FedSetupException.invalidRequest("Idempotency-Key header is required on POST");
        }

        // Distinguish bodyless Deferred Approval proposal/poll vs complete-body Installation Request ({{deferred}})
        if (body.length == 0) {
            return handleBodylessDeferredApproval(jwt, idempotencyKey);
        }

        return handleCompleteBodyInstallation(jwt, idempotencyKey, body, baseUri, realmBaseUri, installationEndpoint);
    }

    private Response handleBodylessDeferredApproval(
            FedSetupJwtService.ValidatedTrustJwt jwt,
            String idempotencyKey) {

        if (jwt.getConfirmationCode() != null || jwt.getTrustPreAuthorization() != null) {
            throw FedSetupException.invalidRequest("Bodyless Deferred Approval request cannot carry confirmation_code or trust_pre_authorization");
        }

        String proposalFingerprint = jwt.getApplicationTenantId() + "|" + jwt.getIdpIssuer() + "|" + jwt.getIss()
                + "|" + jwt.getAuthorizedCapabilities()
                + "|" + jwt.getProviderDelegationProfiles()
                + "|" + jwt.getFederationExtensionProfiles();

        // Check Idempotency-Key BEFORE proof-of-possession or advancing state ({{deferred}} line 185)
        Optional<FedSetupStore.IdempotencyRecord> existingIdem = store.getIdempotencyRecord(
                jwt.getIss(), "deferred-proposal", idempotencyKey);
        if (existingIdem.isPresent()) {
            FedSetupStore.IdempotencyRecord rec = existingIdem.get();
            if (!rec.getRequestHash().equals(proposalFingerprint)) {
                throw FedSetupException.conflict("Idempotency-Key already used with different proposal parameters");
            }
            // If this is a retry of an already-approved (200) response, or a retry without pending_id while still pending,
            // check if the underlying proposal has since transitioned!
            if (jwt.getPendingId() == null && rec.getStatusCode() == 202) {
                // Retry of initial proposal when response was lost
                try {
                    DeferredApprovalResponseRepresentation cached = JsonSerialization.readValue(
                            rec.getResponseBodyJson(), DeferredApprovalResponseRepresentation.class);
                    Optional<DeferredApprovalProposalRecord> propOpt = store.getDeferredProposal(cached.getPendingId());
                    if (propOpt.isPresent()) {
                        return evaluateDeferredProposalState(propOpt.get(), jwt, idempotencyKey, proposalFingerprint);
                    }
                } catch (FedSetupException e) {
                    throw e;
                } catch (Exception ignored) {
                }
            }
            if (rec.getStatusCode() == 200) {
                return Response.status(200)
                        .type("application/json")
                        .entity(rec.getResponseBodyJson())
                        .build();
            }
        }

        // Verify runtime-to-issuer eligibility before fetching candidate CIMD ({{deferred}} line 179)
        verifyCandidateRuntimeEligibility(jwt.getIdpIssuer(), jwt.getIss());

        // Verify signature using candidate CIMD
        jwtService.verifySignatureWithCimdOrStaticJwks(jwt, jwt.getIss(), null);

        // Check JTI replay
        if (!store.checkAndRecordJti(jwt.getIss(), jwt.getJti(), jwt.getExp())) {
            throw FedSetupException.invalidCredential("Replayed JWT 'jti'");
        }

        // Poll with pending_id
        if (jwt.getPendingId() != null) {
            DeferredApprovalProposalRecord proposal = store.getDeferredProposal(jwt.getPendingId())
                    .orElseThrow(() -> FedSetupException.untrustedIssuer("Unknown or expired pending_id"));
            if (!proposal.getApplicationTenantId().equals(jwt.getApplicationTenantId())
                    || !proposal.getIdpIssuer().equals(jwt.getIdpIssuer())
                    || !proposal.getCimdUri().equals(jwt.getIss())) {
                throw FedSetupException.untrustedIssuer("Proposal binding mismatch");
            }
            if (!proposal.getRequestedCapabilities().equals(jwt.getAuthorizedCapabilities())
                    || !proposal.getRequestedDelegationProfiles().equals(jwt.getProviderDelegationProfiles())
                    || !proposal.getRequestedExtensionProfiles().equals(jwt.getFederationExtensionProfiles())) {
                throw FedSetupException.conflict("Poll scope differs from original proposal scope");
            }
            return evaluateDeferredProposalState(proposal, jwt, idempotencyKey, proposalFingerprint);
        }

        // Initial proposal without pending_id
        if (jwt.getApprovalNotificationEndpoint() != null) {
            fetchService.validateHttpsUri(jwt.getApprovalNotificationEndpoint(), "approval_notification_endpoint", true);
        }

        long now = Time.currentTime();
        DeferredApprovalProposalRecord proposal = new DeferredApprovalProposalRecord();
        proposal.setPendingId(FedSetupStore.generateSecureId("pending"));
        proposal.setApplicationTenantId(jwt.getApplicationTenantId());
        proposal.setIdpIssuer(jwt.getIdpIssuer());
        proposal.setCimdUri(jwt.getIss());
        proposal.setAuthorizedCapabilities(jwt.getAuthorizedCapabilities());
        proposal.setProviderDelegationProfiles(jwt.getProviderDelegationProfiles());
        proposal.setFederationExtensionProfiles(jwt.getFederationExtensionProfiles());
        proposal.setApprovalNotificationEndpoint(jwt.getApprovalNotificationEndpoint());
        proposal.setStatus("PENDING");
        proposal.setIntervalSeconds(DEFAULT_DEFERRED_INTERVAL_SECONDS);
        proposal.setCreatedAt(now);
        proposal.setExpiresAt(now + DEFAULT_DEFERRED_EXPIRES_IN_SECONDS);
        store.saveDeferredProposal(proposal);

        DeferredApprovalResponseRepresentation resp = DeferredApprovalResponseRepresentation.pending(
                proposal.getPendingId(),
                proposal.getIntervalSeconds(),
                DEFAULT_DEFERRED_EXPIRES_IN_SECONDS);
        String json = toJson(resp);
        store.saveIdempotencyRecord(jwt.getIss(), "deferred-proposal", idempotencyKey, proposalFingerprint, 202, json, null, true);

        return Response.status(Response.Status.ACCEPTED)
                .type("application/json")
                .header("Cache-Control", "no-store")
                .entity(resp)
                .build();
    }

    private Response evaluateDeferredProposalState(
            DeferredApprovalProposalRecord proposal,
            FedSetupJwtService.ValidatedTrustJwt jwt,
            String idempotencyKey,
            String proposalFingerprint) {
        long now = Time.currentTime();
        if (proposal.getExpiresAt() <= now || "DENIED".equals(proposal.getStatus())) {
            throw FedSetupException.untrustedIssuer("Deferred Approval proposal was denied or expired");
        }
        if ("PENDING".equals(proposal.getStatus())) {
            long remaining = Math.max(1L, proposal.getExpiresAt() - now);
            DeferredApprovalResponseRepresentation resp = DeferredApprovalResponseRepresentation.pending(
                    proposal.getPendingId(),
                    proposal.getIntervalSeconds(),
                    remaining);
            return Response.status(Response.Status.ACCEPTED)
                    .type("application/json")
                    .header("Cache-Control", "no-store")
                    .entity(resp)
                    .build();
        }
        if ("APPROVED".equals(proposal.getStatus()) || "COMPLETED".equals(proposal.getStatus())) {
            proposal.setStatus("COMPLETED");
            store.saveDeferredProposal(proposal);
            DeferredApprovalResponseRepresentation resp = DeferredApprovalResponseRepresentation.approved(
                    proposal.getPendingId(),
                    proposal.getApplicationTenantId(),
                    proposal.getIdpIssuer(),
                    proposal.getAuthorizedCapabilities(),
                    proposal.getProviderDelegationProfiles(),
                    proposal.getFederationExtensionProfiles());
            String json = toJson(resp);
            store.saveIdempotencyRecord(jwt.getIss(), "deferred-proposal", idempotencyKey, proposalFingerprint, 200, json, null, true);
            return Response.ok(resp).type("application/json").build();
        }
        throw FedSetupException.untrustedIssuer("Invalid proposal state");
    }

    private void verifyCandidateRuntimeEligibility(String idpIssuer, String cimdUri) {
        try {
            URI idp = URI.create(idpIssuer);
            URI cimd = URI.create(cimdUri);
            if (idp.getHost() != null && cimd.getHost() != null) {
                String idpDomain = getRegistrableDomain(idp.getHost());
                String cimdDomain = getRegistrableDomain(cimd.getHost());
                if (idpDomain.equalsIgnoreCase(cimdDomain)) {
                    return;
                }
            }
            // Otherwise check if IdP AS metadata lists cimdUri in fedsetup_installation_cimd_uris ({{metadata}})
            String asMetaUri = idpIssuer.endsWith("/")
                    ? idpIssuer + ".well-known/openid-configuration"
                    : idpIssuer + "/.well-known/openid-configuration";
            Map<String, Object> meta = fetchService.fetchOidcProviderMetadata(asMetaUri);
            if (idpIssuer.equals(meta.get("issuer"))
                    && meta.get("fedsetup_installation_cimd_uris") instanceof List<?> allowedUris
                    && allowedUris.contains(cimdUri)) {
                return;
            }
        } catch (Exception ignored) {
        }
        throw FedSetupException.untrustedIssuer("Runtime CIMD URI is not eligible to act for idp_issuer");
    }

    private static String getRegistrableDomain(String host) {
        String[] parts = host.split("\\.");
        if (parts.length >= 2) {
            return parts[parts.length - 2] + "." + parts[parts.length - 1];
        }
        return host;
    }

    private Response handleCompleteBodyInstallation(
            FedSetupJwtService.ValidatedTrustJwt jwt,
            String idempotencyKey,
            byte[] rawBodyBytes,
            String baseUri,
            String realmBaseUri,
            String installationEndpoint) {

        if (jwt.getPendingId() != null || jwt.getApprovalNotificationEndpoint() != null) {
            throw FedSetupException.invalidRequest("Complete-body installation request must not carry pending_id or approval_notification_endpoint");
        }

        ConfigurationRequestRepresentation req;
        try {
            req = JsonSerialization.readValue(rawBodyBytes, ConfigurationRequestRepresentation.class);
        } catch (Exception e) {
            throw FedSetupException.invalidRequest("Malformed Configuration Request JSON body");
        }

        if (req.getIdpIssuer() == null || !req.getIdpIssuer().equals(jwt.getIdpIssuer())) {
            throw FedSetupException.invalidRequest("Request body idp_issuer must equal JWT idp_issuer");
        }
        if (req.getApplicationTenantId() != null && !req.getApplicationTenantId().equals(jwt.getApplicationTenantId())) {
            throw FedSetupException.invalidRequest("Request body application_tenant_id must equal JWT application_tenant_id");
        }

        boolean validateOnly = Boolean.TRUE.equals(req.getValidateOnly());

        // Check static JWKS if a local PendingTrustAuthorizationRecord exists
        PendingTrustAuthorizationRecord localPending = store
                .findActivePendingTrustAuthorization(jwt.getApplicationTenantId(), jwt.getIdpIssuer(), jwt.getIss())
                .orElse(null);
        DirectInstallationTrustRecord existingTrust = store
                .findActiveTrustRecord(jwt.getApplicationTenantId(), jwt.getIdpIssuer(), jwt.getIss())
                .orElse(null);

        String staticJwks = localPending != null ? localPending.getStaticJwksJson()
                : (existingTrust != null ? existingTrust.getStaticJwksJson() : null);

        // Verify signature against runtime's CIMD or static JWKS
        jwtService.verifySignatureWithCimdOrStaticJwks(jwt, jwt.getIss(), staticJwks);

        // Check Idempotency-Key BEFORE consuming confirmation_code, pre-auth, or JTI ({{trust-front-confirm}} line 641)
        String bodyFingerprint = FedSetupStore.sha256Base64Url(rawBodyBytes)
                + "|" + jwt.getApplicationTenantId() + "|" + jwt.getIdpIssuer();
        if (!validateOnly) {
            Optional<FedSetupStore.IdempotencyRecord> idemOpt = store.getIdempotencyRecord(jwt.getIss(), "install", idempotencyKey);
            if (idemOpt.isPresent()) {
                FedSetupStore.IdempotencyRecord rec = idemOpt.get();
                if (!rec.getRequestHash().equals(bodyFingerprint)) {
                    throw FedSetupException.conflict("Idempotency-Key reused with different request content");
                }
                Response.ResponseBuilder rb = Response.status(rec.getStatusCode())
                        .type("application/json")
                        .entity(rec.getResponseBodyJson());
                if (rec.getEtag() != null) {
                    rb.header("ETag", rec.getEtag());
                }
                if (rec.isCacheNoStore()) {
                    rb.header("Cache-Control", "no-store").header("Pragma", "no-cache");
                }
                return rb.build();
            }
        }

        // Check single-use JTI replay
        if (!store.checkAndRecordJti(jwt.getIss(), jwt.getJti(), jwt.getExp())) {
            throw FedSetupException.invalidCredential("Replayed Trust Establishment Authorization JWT 'jti'");
        }

        // Resolve or establish Direct Installation Trust
        DirectInstallationTrustRecord effectiveTrust = resolveOrCreateTrustOnInstall(
                jwt,
                localPending,
                existingTrust,
                realmBaseUri,
                installationEndpoint,
                validateOnly);

        // Enforce SSO connection cardinality ({{disc-members}} sso_connection_cardinality)
        if ((req.getOidc() != null || req.getSaml() != null) && !isMultipleSsoCardinality()) {
            List<ConnectionRecord> activeSso = store.findActiveSsoConnections(
                    jwt.getApplicationTenantId(), jwt.getIdpIssuer());
            if (!activeSso.isEmpty()) {
                throw FedSetupException.conflict(
                        "An active SSO Connection already exists for this IdP issuer and Application Tenant");
            }
        }

        ConnectionRecord conn = new ConnectionRecord();
        conn.setConnectionId(FedSetupStore.generateSecureId("conn"));
        conn.setTrustId(effectiveTrust.getId());
        conn.setAuthenticatedClientContext(jwt.getIss());
        conn.setApplicationTenantId(jwt.getApplicationTenantId());
        conn.setIdpIssuer(jwt.getIdpIssuer());
        conn.setOrigin("fedsetup");
        conn.setStatus("active");
        long now = Time.currentTime();
        conn.setCreatedAt(now);
        conn.setUpdatedAt(now);

        FedSetupProvisioningService.ProvisioningOutcome outcome = provisioningService.validateAndApplyCapabilities(
                conn,
                req,
                effectiveTrust.getAuthorizedCapabilities(),
                effectiveTrust.getProviderDelegationProfiles(),
                effectiveTrust.getFederationExtensionProfiles(),
                baseUri,
                true,
                validateOnly,
                false);

        if (validateOnly) {
            return Response.ok(outcome.getResponse()).type("application/json").build();
        }

        store.saveConnection(conn);
        String respJson = toJson(outcome.getResponse());
        store.saveIdempotencyRecord(
                jwt.getIss(),
                "install",
                idempotencyKey,
                bodyFingerprint,
                201,
                respJson,
                conn.getEtag(),
                outcome.isSecretIssuedOrCarried());

        Response.ResponseBuilder rb = Response.status(Response.Status.CREATED)
                .type("application/json")
                .header("ETag", conn.getEtag())
                .entity(outcome.getResponse());
        if (outcome.isSecretIssuedOrCarried()) {
            rb.header("Cache-Control", "no-store").header("Pragma", "no-cache");
        }
        return rb.build();
    }

    private DirectInstallationTrustRecord resolveOrCreateTrustOnInstall(
            FedSetupJwtService.ValidatedTrustJwt jwt,
            PendingTrustAuthorizationRecord localPending,
            DirectInstallationTrustRecord existingTrust,
            String realmBaseUri,
            String installationEndpoint,
            boolean validateOnly) {

        // 1. Front-Channel Confirmation Code redemption ({{trust-front-confirm}})
        if (jwt.getConfirmationCode() != null) {
            ConsentCodeRecord codeRec = store.consumeConsentCode(jwt.getConfirmationCode())
                    .orElseThrow(() -> FedSetupException.invalidCredential("Invalid, expired, or already-used confirmation_code"));

            if (!codeRec.getApplicationTenantId().equals(jwt.getApplicationTenantId())
                    || !codeRec.getIdpIssuer().equals(jwt.getIdpIssuer())
                    || !codeRec.getCimdUri().equals(jwt.getIss())) {
                throw FedSetupException.invalidCredential("confirmation_code binding mismatch");
            }
            if (codeRec.getRedirectUri() != null) {
                if (!codeRec.getRedirectUri().equals(jwt.getRedirectUri())) {
                    throw FedSetupException.invalidCredential("confirmation_code redirect_uri mismatch");
                }
            } else if (jwt.getRedirectUri() != null) {
                throw FedSetupException.invalidCredential("redirect_uri claim must be absent when defaulted in Consent Request");
            }
            if (jwt.isAuthorizedCapabilitiesPresent()
                    && !codeRec.getRequestedCapabilities().equals(jwt.getAuthorizedCapabilities())) {
                throw FedSetupException.invalidCredential("JWT authorized_capabilities does not match Consent Request");
            }
            if (jwt.isProviderDelegationProfilesPresent()
                    && !codeRec.getRequestedDelegationProfiles().equals(jwt.getProviderDelegationProfiles())) {
                throw FedSetupException.invalidCredential("JWT provider_delegation_profiles does not match Consent Request");
            }
            if (jwt.isFederationExtensionProfilesPresent()
                    && !codeRec.getRequestedExtensionProfiles().equals(jwt.getFederationExtensionProfiles())) {
                throw FedSetupException.invalidCredential("JWT federation_extension_profiles does not match Consent Request");
            }

            DirectInstallationTrustRecord trust = buildTrustRecord(
                    jwt.getApplicationTenantId(),
                    jwt.getIdpIssuer(),
                    jwt.getIss(),
                    codeRec.getApprovedCapabilities(),
                    codeRec.getApprovedDelegationProfiles(),
                    codeRec.getApprovedExtensionProfiles(),
                    null);
            if (!validateOnly) {
                provisionOAuthConfigClientForTrust(trust);
                store.saveTrustRecord(trust);
            }
            return trust;
        }

        // 2. Signed Trust Pre-Authorization JWT ({{preauth}})
        if (jwt.getTrustPreAuthorization() != null) {
            PendingTrustAuthorizationRecord preAuth = jwtService.validateTrustPreAuthorizationJwt(
                    jwt.getTrustPreAuthorization(),
                    realmBaseUri,
                    installationEndpoint,
                    jwt,
                    store);
            verifyScopeSubset(jwt, preAuth.getAuthorizedCapabilities(), preAuth.getProviderDelegationProfiles(), preAuth.getFederationExtensionProfiles());

            DirectInstallationTrustRecord trust = existingTrust != null ? existingTrust : buildTrustRecord(
                    jwt.getApplicationTenantId(),
                    jwt.getIdpIssuer(),
                    jwt.getIss(),
                    jwt.isAuthorizedCapabilitiesPresent() ? jwt.getAuthorizedCapabilities() : preAuth.getAuthorizedCapabilities(),
                    jwt.isProviderDelegationProfilesPresent() ? jwt.getProviderDelegationProfiles() : preAuth.getProviderDelegationProfiles(),
                    jwt.isFederationExtensionProfilesPresent() ? jwt.getFederationExtensionProfiles() : preAuth.getFederationExtensionProfiles(),
                    null);
            if (existingTrust != null) {
                // Widen existing trust if replacement pre-authorization authorized a wider scope ({{preauth}} line 175)
                trust.setAuthorizedCapabilities(jwt.isAuthorizedCapabilitiesPresent() ? jwt.getAuthorizedCapabilities() : preAuth.getAuthorizedCapabilities());
                trust.setProviderDelegationProfiles(jwt.isProviderDelegationProfilesPresent() ? jwt.getProviderDelegationProfiles() : preAuth.getProviderDelegationProfiles());
                trust.setFederationExtensionProfiles(jwt.isFederationExtensionProfilesPresent() ? jwt.getFederationExtensionProfiles() : preAuth.getFederationExtensionProfiles());
            }
            if (!validateOnly) {
                store.markPreAuthConsumed(preAuth.getId());
                provisionOAuthConfigClientForTrust(trust);
                store.saveTrustRecord(trust);
            }
            return trust;
        }

        // 3. Local Pending Trust Authorization ({{trust-back}})
        if (localPending != null) {
            verifyScopeSubset(jwt, localPending.getAuthorizedCapabilities(), localPending.getProviderDelegationProfiles(), localPending.getFederationExtensionProfiles());
            DirectInstallationTrustRecord trust = existingTrust != null ? existingTrust : buildTrustRecord(
                    jwt.getApplicationTenantId(),
                    jwt.getIdpIssuer(),
                    jwt.getIss(),
                    jwt.isAuthorizedCapabilitiesPresent() ? jwt.getAuthorizedCapabilities() : localPending.getAuthorizedCapabilities(),
                    jwt.isProviderDelegationProfilesPresent() ? jwt.getProviderDelegationProfiles() : localPending.getProviderDelegationProfiles(),
                    jwt.isFederationExtensionProfilesPresent() ? jwt.getFederationExtensionProfiles() : localPending.getFederationExtensionProfiles(),
                    localPending.getStaticJwksJson());
            if (!validateOnly) {
                store.markPreAuthConsumed(localPending.getId());
                provisionOAuthConfigClientForTrust(trust);
                store.saveTrustRecord(trust);
            }
            return trust;
        }

        // 4. Existing active Direct Installation Trust (e.g. from Deferred Approval or prior installation)
        if (existingTrust != null) {
            verifyScopeSubset(jwt, existingTrust.getAuthorizedCapabilities(), existingTrust.getProviderDelegationProfiles(), existingTrust.getFederationExtensionProfiles());
            return existingTrust;
        }

        throw FedSetupException.untrustedIssuer("No Pending Trust Authorization or active Direct Installation Trust found for issuer and tenant");
    }

    private static void verifyScopeSubset(
            FedSetupJwtService.ValidatedTrustJwt jwt,
            List<String> allowedCaps,
            List<String> allowedDeleg,
            List<String> allowedExt) {
        if (jwt.isAuthorizedCapabilitiesPresent() && (allowedCaps == null || !allowedCaps.containsAll(jwt.getAuthorizedCapabilities()))) {
            throw FedSetupException.untrustedIssuer("Requested authorized_capabilities exceed the authorized scope");
        }
        if (jwt.isProviderDelegationProfilesPresent() && (allowedDeleg == null || !allowedDeleg.containsAll(jwt.getProviderDelegationProfiles()))) {
            throw FedSetupException.untrustedIssuer("Requested provider_delegation_profiles exceed the authorized scope");
        }
        if (jwt.isFederationExtensionProfilesPresent() && (allowedExt == null || !allowedExt.containsAll(jwt.getFederationExtensionProfiles()))) {
            throw FedSetupException.untrustedIssuer("Requested federation_extension_profiles exceed the authorized scope");
        }
    }

    private DirectInstallationTrustRecord buildTrustRecord(
            String appTenantId,
            String idpIssuer,
            String cimdUri,
            List<String> caps,
            List<String> deleg,
            List<String> ext,
            String staticJwksJson) {
        DirectInstallationTrustRecord trust = new DirectInstallationTrustRecord();
        trust.setId(FedSetupStore.generateSecureId("trust"));
        trust.setApplicationTenantId(appTenantId);
        trust.setIdpIssuer(idpIssuer);
        trust.setCimdUri(cimdUri);
        trust.setAuthorizedCapabilities(caps != null ? new ArrayList<>(caps) : new ArrayList<>());
        trust.setProviderDelegationProfiles(deleg != null ? new ArrayList<>(deleg) : new ArrayList<>());
        trust.setFederationExtensionProfiles(ext != null ? new ArrayList<>(ext) : new ArrayList<>());
        trust.setStaticJwksJson(staticJwksJson);
        trust.setCreatedAt(Time.currentTime());
        trust.setOauthClientId("fedsetup-cfg-" + trust.getId());
        return trust;
    }

    private void provisionOAuthConfigClientForTrust(DirectInstallationTrustRecord trust) {
        if (realm == null || trust.getOauthClientId() == null) {
            return;
        }
        ClientModel client = realm.getClientByClientId(trust.getOauthClientId());
        if (client == null) {
            client = realm.addClient(trust.getOauthClientId());
        }
        client.setEnabled(true);
        client.setPublicClient(false);
        client.setServiceAccountsEnabled(true);
        client.setClientAuthenticatorType("client-jwt");
        client.setAttribute("fedsetup.trust_id", trust.getId());
        client.setAttribute("fedsetup.cimd_uri", trust.getCimdUri());
    }

    // ---- 4. Configuration Endpoint (POST /configure) ({{auth-oauth}} & {{config}}) ----

    public Response handleConfigure(
            String authorizationHeader,
            String idempotencyKey,
            byte[] rawBodyBytes,
            String baseUri) {

        String realmBaseUri = baseUri + "/realms/" + realm.getName();
        String configureEndpoint = realmBaseUri + "/" + FedSetupConstants.PROVIDER_ID + "/configure";
        byte[] body = rawBodyBytes != null ? rawBodyBytes : new byte[0];
        if (body.length == 0) {
            throw FedSetupException.invalidRequest("Request body is required");
        }
        if (idempotencyKey == null || idempotencyKey.isBlank()) {
            throw FedSetupException.invalidRequest("Idempotency-Key header is required on POST");
        }

        ConfigurationRequestRepresentation req;
        try {
            req = JsonSerialization.readValue(body, ConfigurationRequestRepresentation.class);
        } catch (Exception e) {
            throw FedSetupException.invalidRequest("Malformed Configuration Request JSON body");
        }

        AuthenticatedConfigCaller caller = authenticateConfigApiRequest(
                authorizationHeader, "POST", configureEndpoint, body);

        if (req.getIdpIssuer() == null || !req.getIdpIssuer().equals(caller.trust.getIdpIssuer())) {
            throw FedSetupException.invalidRequest("Request body idp_issuer does not match authorized IdP Tenant issuer");
        }
        if (req.getApplicationTenantId() != null && !req.getApplicationTenantId().equals(caller.trust.getApplicationTenantId())) {
            throw FedSetupException.invalidRequest("Request body application_tenant_id does not match authorized Application Tenant");
        }

        checkOAuthScopesIfApplicable(caller, req);

        boolean validateOnly = Boolean.TRUE.equals(req.getValidateOnly());
        String bodyFingerprint = FedSetupStore.sha256Base64Url(body)
                + "|" + caller.trust.getApplicationTenantId() + "|" + caller.trust.getIdpIssuer();

        if (!validateOnly) {
            Optional<FedSetupStore.IdempotencyRecord> idemOpt = store.getIdempotencyRecord(
                    caller.clientContext, "configure", idempotencyKey);
            if (idemOpt.isPresent()) {
                FedSetupStore.IdempotencyRecord rec = idemOpt.get();
                if (!rec.getRequestHash().equals(bodyFingerprint)) {
                    throw FedSetupException.conflict("Idempotency-Key reused with different request content");
                }
                Response.ResponseBuilder rb = Response.status(rec.getStatusCode())
                        .type("application/json")
                        .entity(rec.getResponseBodyJson());
                if (rec.getEtag() != null) {
                    rb.header("ETag", rec.getEtag());
                }
                if (rec.isCacheNoStore()) {
                    rb.header("Cache-Control", "no-store").header("Pragma", "no-cache");
                }
                return rb.build();
            }
        }

        if ((req.getOidc() != null || req.getSaml() != null) && !isMultipleSsoCardinality()) {
            List<ConnectionRecord> activeSso = store.findActiveSsoConnections(
                    caller.trust.getApplicationTenantId(), caller.trust.getIdpIssuer());
            if (!activeSso.isEmpty()) {
                throw FedSetupException.conflict(
                        "An active SSO Connection already exists for this IdP issuer and Application Tenant");
            }
        }

        ConnectionRecord conn = new ConnectionRecord();
        conn.setConnectionId(FedSetupStore.generateSecureId("conn"));
        conn.setTrustId(caller.trust.getId());
        conn.setAuthenticatedClientContext(caller.clientContext);
        conn.setApplicationTenantId(caller.trust.getApplicationTenantId());
        conn.setIdpIssuer(caller.trust.getIdpIssuer());
        conn.setOrigin("fedsetup");
        conn.setStatus("active");
        long now = Time.currentTime();
        conn.setCreatedAt(now);
        conn.setUpdatedAt(now);

        FedSetupProvisioningService.ProvisioningOutcome outcome = provisioningService.validateAndApplyCapabilities(
                conn,
                req,
                caller.trust.getAuthorizedCapabilities(),
                caller.trust.getProviderDelegationProfiles(),
                caller.trust.getFederationExtensionProfiles(),
                baseUri,
                true,
                validateOnly,
                false);

        if (validateOnly) {
            return Response.ok(outcome.getResponse()).type("application/json").build();
        }

        store.saveConnection(conn);
        String respJson = toJson(outcome.getResponse());
        store.saveIdempotencyRecord(
                caller.clientContext,
                "configure",
                idempotencyKey,
                bodyFingerprint,
                201,
                respJson,
                conn.getEtag(),
                outcome.isSecretIssuedOrCarried());

        Response.ResponseBuilder rb = Response.status(Response.Status.CREATED)
                .type("application/json")
                .header("ETag", conn.getEtag())
                .entity(outcome.getResponse());
        if (outcome.isSecretIssuedOrCarried()) {
            rb.header("Cache-Control", "no-store").header("Pragma", "no-cache");
        }
        return rb.build();
    }

    // ---- 5. Connection Lifecycle Endpoints (GET, PATCH, DELETE /connection/{connection_id}) ----

    public Response handleGetConnection(String connectionId, String authorizationHeader, String baseUri) {
        String realmBaseUri = baseUri + "/realms/" + realm.getName();
        String endpointUri = realmBaseUri + "/" + FedSetupConstants.PROVIDER_ID + "/connection/" + connectionId;

        AuthenticatedConfigCaller caller = authenticateConfigApiRequest(
                authorizationHeader, "GET", endpointUri, new byte[0]);

        ConnectionRecord conn = getAuthorizedActiveConnection(connectionId, caller);
        ConfigurationResponseRepresentation resp = provisioningService.buildGetResponse(conn, baseUri);
        return Response.ok(resp)
                .type("application/json")
                .header("ETag", conn.getEtag())
                .build();
    }

    public Response handlePatchConnection(
            String connectionId,
            String authorizationHeader,
            String ifMatchHeader,
            String idempotencyKey,
            byte[] rawBodyBytes,
            String baseUri) {

        String realmBaseUri = baseUri + "/realms/" + realm.getName();
        String endpointUri = realmBaseUri + "/" + FedSetupConstants.PROVIDER_ID + "/connection/" + connectionId;
        byte[] body = rawBodyBytes != null ? rawBodyBytes : new byte[0];
        if (body.length == 0) {
            throw FedSetupException.invalidRequest("PATCH request body is required");
        }

        ConfigurationRequestRepresentation req;
        try {
            req = JsonSerialization.readValue(body, ConfigurationRequestRepresentation.class);
        } catch (Exception e) {
            throw FedSetupException.invalidRequest("Malformed Configuration Request JSON body");
        }

        AuthenticatedConfigCaller caller = authenticateConfigApiRequest(
                authorizationHeader, "PATCH", endpointUri, body);

        ConnectionRecord conn = getAuthorizedActiveConnection(connectionId, caller);

        if (req.getIdpIssuer() != null && !req.getIdpIssuer().equals(conn.getIdpIssuer())) {
            throw FedSetupException.conflict("Cannot change immutable Connection idp_issuer");
        }
        if (req.getApplicationTenantId() != null && !req.getApplicationTenantId().equals(conn.getApplicationTenantId())) {
            throw FedSetupException.conflict("Cannot change immutable Connection application_tenant_id");
        }

        checkOAuthScopesIfApplicable(caller, req);

        boolean validateOnly = Boolean.TRUE.equals(req.getValidateOnly());
        boolean rotateToken = req.getScim() != null && Boolean.TRUE.equals(req.getScim().getRotateAccessToken());

        if (rotateToken && (idempotencyKey == null || idempotencyKey.isBlank())) {
            throw FedSetupException.invalidRequest("Idempotency-Key header is required when scim.rotate_access_token is true");
        }

        String bodyFingerprint = FedSetupStore.sha256Base64Url(body) + "|" + connectionId;

        // Per {{config-syntax}} line 774: Before applying If-Match precondition, return cached rotation result on matching Idempotency-Key!
        if (!validateOnly && idempotencyKey != null && !idempotencyKey.isBlank()) {
            Optional<FedSetupStore.IdempotencyRecord> idemOpt = store.getIdempotencyRecord(
                    caller.clientContext, "patch:" + connectionId, idempotencyKey);
            if (idemOpt.isPresent()) {
                FedSetupStore.IdempotencyRecord rec = idemOpt.get();
                if (!rec.getRequestHash().equals(bodyFingerprint)) {
                    throw FedSetupException.conflict("Idempotency-Key reused with different PATCH content");
                }
                Response.ResponseBuilder rb = Response.status(rec.getStatusCode())
                        .type("application/json")
                        .entity(rec.getResponseBodyJson());
                if (rec.getEtag() != null) {
                    rb.header("ETag", rec.getEtag());
                }
                if (rec.isCacheNoStore()) {
                    rb.header("Cache-Control", "no-store").header("Pragma", "no-cache");
                }
                return rb.build();
            }
        }

        // Enforce strong ETag in If-Match ({{config-syntax}} line 768)
        if (ifMatchHeader == null || ifMatchHeader.isBlank()) {
            throw FedSetupException.preconditionFailed("If-Match header with strong ETag is required on PATCH");
        }
        if (!conn.getEtag().equals(ifMatchHeader.trim())) {
            throw FedSetupException.preconditionFailed("If-Match ETag does not match current Connection ETag");
        }

        FedSetupProvisioningService.ProvisioningOutcome outcome = provisioningService.validateAndApplyCapabilities(
                conn,
                req,
                caller.trust.getAuthorizedCapabilities(),
                caller.trust.getProviderDelegationProfiles(),
                caller.trust.getFederationExtensionProfiles(),
                baseUri,
                false,
                validateOnly,
                false);

        if (validateOnly) {
            return Response.ok(outcome.getResponse()).type("application/json").build();
        }

        store.saveConnection(conn);
        String respJson = toJson(outcome.getResponse());
        if (idempotencyKey != null && !idempotencyKey.isBlank()) {
            store.saveIdempotencyRecord(
                    caller.clientContext,
                    "patch:" + connectionId,
                    idempotencyKey,
                    bodyFingerprint,
                    200,
                    respJson,
                    conn.getEtag(),
                    outcome.isSecretIssuedOrCarried());
        }

        Response.ResponseBuilder rb = Response.ok(outcome.getResponse())
                .type("application/json")
                .header("ETag", conn.getEtag());
        if (outcome.isSecretIssuedOrCarried()) {
            rb.header("Cache-Control", "no-store").header("Pragma", "no-cache");
        }
        return rb.build();
    }

    public Response handleDeleteConnection(String connectionId, String authorizationHeader, String baseUri) {
        String realmBaseUri = baseUri + "/realms/" + realm.getName();
        String endpointUri = realmBaseUri + "/" + FedSetupConstants.PROVIDER_ID + "/connection/" + connectionId;

        AuthenticatedConfigCaller caller = authenticateConfigApiRequest(
                authorizationHeader, "DELETE", endpointUri, new byte[0]);

        ConnectionRecord conn = store.getConnection(connectionId)
                .orElseThrow(() -> FedSetupException.notFound("Connection not found: " + connectionId));
        if (!conn.getApplicationTenantId().equals(caller.trust.getApplicationTenantId())
                || !conn.getIdpIssuer().equals(caller.trust.getIdpIssuer())) {
            throw FedSetupException.notFound("Connection not found: " + connectionId);
        }
        if ("deactivated".equals(conn.getStatus())) {
            return Response.noContent().build();
        }
        provisioningService.deactivateConnectionResources(conn);
        conn.setStatus("deactivated");
        conn.setVersion(conn.getVersion() + 1);
        conn.setUpdatedAt(Time.currentTime());
        conn.setEtag(FedSetupProvisioningService.computeConnectionEtag(conn));
        store.saveConnection(conn);

        return Response.noContent().build();
    }

    private ConnectionRecord getAuthorizedActiveConnection(String connectionId, AuthenticatedConfigCaller caller) {
        ConnectionRecord conn = store.getConnection(connectionId)
                .orElseThrow(() -> FedSetupException.notFound("Connection not found: " + connectionId));
        if (!conn.getApplicationTenantId().equals(caller.trust.getApplicationTenantId())
                || !conn.getIdpIssuer().equals(caller.trust.getIdpIssuer())) {
            throw FedSetupException.notFound("Connection not found: " + connectionId);
        }
        if ("deactivated".equals(conn.getStatus())) {
            throw FedSetupException.notFound("Connection has been deactivated: " + connectionId);
        }
        return conn;
    }

    // ---- 6. Connection Query Endpoint (GET /connections) ({{query}}) ----

    public Response handleQueryConnections(
            String authorizationHeader,
            String fullRequestUri,
            String capabilityFilter,
            String statusFilter,
            Integer limitParam,
            String cursorParam,
            String baseUri) {

        AuthenticatedConfigCaller caller = authenticateConfigApiRequest(
                authorizationHeader, "GET", fullRequestUri, new byte[0]);

        if (statusFilter != null && !"active".equals(statusFilter) && !"deactivated".equals(statusFilter)) {
            throw FedSetupException.invalidRequest("status filter must be 'active' or 'deactivated'");
        }
        int limit = 50;
        if (limitParam != null) {
            if (limitParam <= 0) {
                throw FedSetupException.invalidRequest("limit must be a positive integer");
            }
            limit = Math.min(limitParam, 100);
        }

        int offset = 0;
        if (cursorParam != null && !cursorParam.isBlank()) {
            String expectedPrefix = caller.trust.getId() + ":";
            String decoded;
            try {
                decoded = new String(java.util.Base64.getUrlDecoder().decode(cursorParam), StandardCharsets.UTF_8);
            } catch (Exception e) {
                throw FedSetupException.invalidRequest("Malformed cursor");
            }
            if (!decoded.startsWith(expectedPrefix)) {
                throw FedSetupException.invalidRequest("Cursor is not bound to the authenticated Direct Installation Trust");
            }
            try {
                offset = Integer.parseInt(decoded.substring(expectedPrefix.length()));
                if (offset < 0) {
                    throw FedSetupException.invalidRequest("Invalid cursor offset");
                }
            } catch (NumberFormatException e) {
                throw FedSetupException.invalidRequest("Invalid cursor offset");
            }
        }

        List<ConnectionRecord> matching = store.listConnections().stream()
                .filter(c -> caller.trust.getApplicationTenantId().equals(c.getApplicationTenantId())
                        && caller.trust.getIdpIssuer().equals(c.getIdpIssuer()))
                .filter(c -> statusFilter == null || statusFilter.equals(c.getStatus()))
                .filter(c -> capabilityFilter == null || c.getEnabledCapabilities().contains(capabilityFilter))
                .toList();

        List<ConnectionQueryResponseRepresentation.ConnectionSummary> summaries = new ArrayList<>();
        int end = Math.min(matching.size(), offset + limit);
        for (int i = offset; i < end; i++) {
            ConnectionRecord c = matching.get(i);
            ConnectionQueryResponseRepresentation.ConnectionSummary sum = new ConnectionQueryResponseRepresentation.ConnectionSummary();
            sum.setConnectionId(c.getConnectionId());
            sum.setEtag(c.getEtag());
            sum.setCapabilities(c.getEnabledCapabilities());
            sum.setStatus(c.getStatus());
            sum.setIdpIssuer(c.getIdpIssuer());
            sum.setApplicationTenantId(c.getApplicationTenantId());
            sum.setOrigin(c.getOrigin());
            sum.setConnectionName(c.getConnectionName());
            if (c.getCreatedAt() > 0) {
                sum.setCreatedAt(Instant.ofEpochSecond(c.getCreatedAt()).toString());
                sum.setUpdatedAt(Instant.ofEpochSecond(c.getUpdatedAt()).toString());
            }
            summaries.add(sum);
        }

        ConnectionQueryResponseRepresentation resp = new ConnectionQueryResponseRepresentation();
        resp.setConnections(summaries);
        if (end < matching.size()) {
            String rawCursor = caller.trust.getId() + ":" + end;
            resp.setNextCursor(java.util.Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(rawCursor.getBytes(StandardCharsets.UTF_8)));
        }
        return Response.ok(resp).type("application/json").build();
    }

    // ---- 7. Configuration API Authentication (Signed JWT or OAuth 2.0 Bearer Token) ----

    private static class AuthenticatedConfigCaller {
        final DirectInstallationTrustRecord trust;
        final String clientContext;
        final boolean oauthAuthenticated;
        final Set<String> grantedScopes;

        AuthenticatedConfigCaller(
                DirectInstallationTrustRecord trust,
                String clientContext,
                boolean oauthAuthenticated,
                Set<String> grantedScopes) {
            this.trust = trust;
            this.clientContext = clientContext;
            this.oauthAuthenticated = oauthAuthenticated;
            this.grantedScopes = grantedScopes;
        }
    }

    @SuppressWarnings("unchecked")
    private AuthenticatedConfigCaller authenticateConfigApiRequest(
            String authorizationHeader,
            String httpMethod,
            String expectedEndpointUri,
            byte[] rawBodyBytes) {

        String rawToken = FedSetupJwtService.extractBearerToken(authorizationHeader);

        // Peek at JWT payload to see if it is an OAuth 2.0 access token issued by this realm or a Trust Establishment Authorization JWT
        try {
            JWSInput jws = new JWSInput(rawToken);
            Map<String, Object> claims = JsonSerialization.readValue(jws.getContent(), Map.class);
            if (claims.containsKey("htm") && claims.containsKey("htu") && claims.containsKey("request_hash")) {
                // Signed Trust Establishment Authorization JWT
                FedSetupJwtService.ValidatedTrustJwt jwt = jwtService.parseAndValidateClaims(
                        rawToken,
                        httpMethod,
                        expectedEndpointUri,
                        rawBodyBytes,
                        isSingleTenantMode(),
                        getEffectiveTenantId());

                if (!getEffectiveTenantId().equals(jwt.getApplicationTenantId())) {
                    throw FedSetupException.untrustedIssuer("Tenant mismatch");
                }

                DirectInstallationTrustRecord trust = store
                        .findActiveTrustRecord(jwt.getApplicationTenantId(), jwt.getIdpIssuer(), jwt.getIss())
                        .orElseThrow(() -> FedSetupException.untrustedIssuer("No active Direct Installation Trust for caller"));

                jwtService.verifySignatureWithCimdOrStaticJwks(jwt, jwt.getIss(), trust.getStaticJwksJson());

                if (!store.checkAndRecordJti(jwt.getIss(), jwt.getJti(), jwt.getExp())) {
                    throw FedSetupException.invalidCredential("Replayed Trust Establishment Authorization JWT 'jti'");
                }

                return new AuthenticatedConfigCaller(trust, jwt.getIss(), false, Collections.emptySet());
            } else {
                // OAuth 2.0 Access Token issued by this realm's authorization server ({{auth-oauth}})
                if (!jwtService.verifyJwsWithJwks(jws, jwtService.getRealmTrustJwks())) {
                    throw FedSetupException.invalidCredential("Invalid OAuth access token signature");
                }
                long now = Time.currentTime();
                Number exp = (Number) claims.get("exp");
                if (exp == null || exp.longValue() <= now) {
                    throw FedSetupException.invalidCredential("Expired OAuth access token");
                }
                String azp = (String) claims.getOrDefault("azp", claims.get("client_id"));
                if (azp == null || azp.isBlank()) {
                    throw FedSetupException.invalidCredential("OAuth access token missing client identity");
                }
                DirectInstallationTrustRecord trust = store.findActiveTrustRecordByOAuthClient(azp)
                        .orElseThrow(() -> FedSetupException.untrustedIssuer("OAuth client has no active Direct Installation Trust"));

                String scopeStr = (String) claims.getOrDefault("scope", "");
                Set<String> scopes = Set.copyOf(parseSpaceDelimited(scopeStr));
                return new AuthenticatedConfigCaller(trust, azp, true, scopes);
            }
        } catch (FedSetupException e) {
            throw e;
        } catch (Exception e) {
            throw FedSetupException.invalidCredential("Malformed Bearer token");
        }
    }

    private void checkOAuthScopesIfApplicable(AuthenticatedConfigCaller caller, ConfigurationRequestRepresentation req) {
        if (!caller.oauthAuthenticated) {
            return;
        }
        if (req.getOidc() != null && !caller.grantedScopes.contains(FedSetupConstants.SCOPE_CONFIG_PREFIX + "oidc")) {
            throw FedSetupException.insufficientScope(
                    "Missing required OAuth scope for oidc", FedSetupConstants.SCOPE_CONFIG_PREFIX + "oidc");
        }
        if (req.getSaml() != null && !caller.grantedScopes.contains(FedSetupConstants.SCOPE_CONFIG_PREFIX + "saml")) {
            throw FedSetupException.insufficientScope(
                    "Missing required OAuth scope for saml", FedSetupConstants.SCOPE_CONFIG_PREFIX + "saml");
        }
        if (req.getScim() != null && !caller.grantedScopes.contains(FedSetupConstants.SCOPE_CONFIG_PREFIX + "scim")) {
            throw FedSetupException.insufficientScope(
                    "Missing required OAuth scope for scim", FedSetupConstants.SCOPE_CONFIG_PREFIX + "scim");
        }
        if (req.getIdJag() != null && !caller.grantedScopes.contains(FedSetupConstants.SCOPE_CONFIG_PREFIX + "id_jag")) {
            throw FedSetupException.insufficientScope(
                    "Missing required OAuth scope for id_jag", FedSetupConstants.SCOPE_CONFIG_PREFIX + "id_jag");
        }
    }

    // ---- 8. Application Tenant Admin Operations ({{trust-back}}, {{trust-revoke}}, {{preauth}}, {{deferred}}, {{update}}) ----

    public PendingTrustAuthorizationRecord createPendingTrustAuthorization(
            String idpIssuer,
            String cimdUri,
            List<String> authorizedCapabilities,
            List<String> providerDelegationProfiles,
            List<String> federationExtensionProfiles,
            String staticJwksJson,
            long ttlSeconds) {

        String appTenantId = getEffectiveTenantId();
        fetchService.validateHttpsUri(idpIssuer, "idp_issuer", true);
        fetchService.validateHttpsUri(cimdUri, "cimd_uri", true);

        // Replacement scope comparison rule per draft-tamm-express-configuration-deferred-trust {{preauth}} line 173
        DirectInstallationTrustRecord existingTrust = store.findActiveTrustRecord(appTenantId, idpIssuer, cimdUri).orElse(null);
        PendingTrustAuthorizationRecord existingPending = store.findActivePendingTrustAuthorization(appTenantId, idpIssuer, cimdUri).orElse(null);

        List<String> reqCaps = authorizedCapabilities != null ? authorizedCapabilities : Collections.emptyList();
        List<String> reqDeleg = providerDelegationProfiles != null ? providerDelegationProfiles : Collections.emptyList();
        List<String> reqExt = federationExtensionProfiles != null ? federationExtensionProfiles : Collections.emptyList();

        if (existingTrust != null) {
            if (!reqCaps.containsAll(existingTrust.getAuthorizedCapabilities())
                    || !reqDeleg.containsAll(existingTrust.getProviderDelegationProfiles())
                    || !reqExt.containsAll(existingTrust.getFederationExtensionProfiles())) {
                throw FedSetupException.conflict("Replacement pre-authorization scope must be equal to or a superset of active Trust scope");
            }
        } else if (existingPending != null) {
            if (!reqCaps.containsAll(existingPending.getAuthorizedCapabilities())
                    || !reqDeleg.containsAll(existingPending.getProviderDelegationProfiles())
                    || !reqExt.containsAll(existingPending.getFederationExtensionProfiles())) {
                throw FedSetupException.conflict("Replacement pre-authorization scope must be equal to or a superset of active Pending Trust Authorization scope");
            }
            store.revokePreAuth(existingPending.getId());
        }

        long now = Time.currentTime();
        PendingTrustAuthorizationRecord rec = new PendingTrustAuthorizationRecord();
        rec.setId(FedSetupStore.generateSecureId("pta"));
        rec.setApplicationTenantId(appTenantId);
        rec.setIdpIssuer(idpIssuer);
        rec.setCimdUri(cimdUri);
        rec.setAuthorizedCapabilities(new ArrayList<>(reqCaps));
        rec.setProviderDelegationProfiles(new ArrayList<>(reqDeleg));
        rec.setFederationExtensionProfiles(new ArrayList<>(reqExt));
        rec.setStaticJwksJson(staticJwksJson);
        rec.setIssuedAt(now);
        rec.setExpiresAt(now + (ttlSeconds > 0 ? ttlSeconds : 604800L));
        store.savePendingTrustAuthorization(rec);
        return rec;
    }

    public String serializePendingTrustAuthorizationJwt(PendingTrustAuthorizationRecord record, String baseUri) {
        String realmBaseUri = baseUri + "/realms/" + realm.getName();
        String installationEndpoint = realmBaseUri + "/" + FedSetupConstants.PROVIDER_ID + "/install";
        return jwtService.issueTrustPreAuthorizationJwt(record, realmBaseUri, installationEndpoint);
    }

    public void revokePendingTrustAuthorization(String pendingAuthId) {
        store.revokePreAuth(pendingAuthId);
    }

    public DirectInstallationTrustRecord approveDeferredProposal(
            String pendingId,
            List<String> approvedCapabilities,
            List<String> approvedDelegationProfiles,
            List<String> approvedExtensionProfiles,
            String baseUri) {

        DeferredApprovalProposalRecord proposal = store.getDeferredProposal(pendingId)
                .orElseThrow(() -> FedSetupException.notFound("Deferred proposal not found: " + pendingId));

        long now = Time.currentTime();
        if (proposal.getExpiresAt() <= now || !"PENDING".equals(proposal.getStatus())) {
            throw FedSetupException.invalidRequest("Proposal is no longer pending");
        }

        // Collision check per draft-tamm-express-configuration-deferred-trust {{deferred}} line 191:
        // Must not approve a proposal whose Application Tenant and IdP issuer already have an active Trust or Connection through a different CIMD URI!
        for (DirectInstallationTrustRecord t : store.listTrustRecords()) {
            if (!t.isRevoked()
                    && t.getApplicationTenantId().equals(proposal.getApplicationTenantId())
                    && t.getIdpIssuer().equals(proposal.getIdpIssuer())
                    && !t.getCimdUri().equals(proposal.getCimdUri())) {
                throw FedSetupException.conflict(
                        "Application Tenant and IdP issuer already have an active Direct Installation Trust through a different CIMD URI");
            }
        }
        for (ConnectionRecord c : store.listConnections()) {
            if ("active".equals(c.getStatus())
                    && c.getApplicationTenantId().equals(proposal.getApplicationTenantId())
                    && c.getIdpIssuer().equals(proposal.getIdpIssuer())
                    && c.getAuthenticatedClientContext() != null
                    && !c.getAuthenticatedClientContext().equals(proposal.getCimdUri())) {
                throw FedSetupException.conflict(
                        "Application Tenant and IdP issuer already have an active Connection through a different runtime");
            }
        }

        List<String> finalCaps = approvedCapabilities != null ? approvedCapabilities : proposal.getAuthorizedCapabilities();
        List<String> finalDeleg = approvedDelegationProfiles != null ? approvedDelegationProfiles : proposal.getProviderDelegationProfiles();
        List<String> finalExt = approvedExtensionProfiles != null ? approvedExtensionProfiles : proposal.getFederationExtensionProfiles();

        if (!proposal.getAuthorizedCapabilities().containsAll(finalCaps)
                || !proposal.getProviderDelegationProfiles().containsAll(finalDeleg)
                || !proposal.getFederationExtensionProfiles().containsAll(finalExt)) {
            throw FedSetupException.invalidRequest("Approved scope cannot exceed proposal's requested scope");
        }

        proposal.setAuthorizedCapabilities(finalCaps);
        proposal.setProviderDelegationProfiles(finalDeleg);
        proposal.setFederationExtensionProfiles(finalExt);
        proposal.setStatus("APPROVED");

        String notifEndpoint = proposal.getApprovalNotificationEndpoint();
        proposal.setApprovalNotificationEndpoint(null); // Discard notification endpoint on terminal state ({{deferred}} line 181)
        store.saveDeferredProposal(proposal);

        DirectInstallationTrustRecord trust = buildTrustRecord(
                proposal.getApplicationTenantId(),
                proposal.getIdpIssuer(),
                proposal.getCimdUri(),
                finalCaps,
                finalDeleg,
                finalExt,
                null);
        provisionOAuthConfigClientForTrust(trust);
        store.saveTrustRecord(trust);

        if (notifEndpoint != null && baseUri != null) {
            String realmBaseUri = baseUri + "/realms/" + realm.getName();
            String notifJwt = jwtService.issueApprovalNotificationJwt(
                    realmBaseUri,
                    notifEndpoint,
                    proposal.getCimdUri(),
                    proposal.getPendingId(),
                    proposal.getApplicationTenantId(),
                    proposal.getIdpIssuer());
            fetchService.postApprovalNotification(notifEndpoint, notifJwt);
        }

        return trust;
    }

    public void denyDeferredProposal(String pendingId) {
        DeferredApprovalProposalRecord proposal = store.getDeferredProposal(pendingId)
                .orElseThrow(() -> FedSetupException.notFound("Deferred proposal not found: " + pendingId));
        proposal.setStatus("DENIED");
        proposal.setApprovalNotificationEndpoint(null);
        store.saveDeferredProposal(proposal);
    }

    /**
     * Revokes Direct Installation Trust without deactivating existing Connections ({{trust-revoke}}).
     */
    public void revokeDirectInstallationTrust(String trustId) {
        DirectInstallationTrustRecord trust = store.getTrustRecord(trustId)
                .orElseThrow(() -> FedSetupException.notFound("Trust record not found: " + trustId));
        trust.setRevoked(true);
        store.saveTrustRecord(trust);

        // Disable OAuth Configuration API client if one was provisioned
        if (realm != null && trust.getOauthClientId() != null) {
            ClientModel client = realm.getClientByClientId(trust.getOauthClientId());
            if (client != null) {
                client.setEnabled(false);
            }
        }

        // Also revoke any active Pending Trust Authorization for the same binding ({{preauth}} line 171)
        store.findActivePendingTrustAuthorization(trust.getApplicationTenantId(), trust.getIdpIssuer(), trust.getCimdUri())
                .ifPresent(pta -> store.revokePreAuth(pta.getId()));

        // Purge cached signing keys for this CIMD URI
        fetchService.purgeCachedKeysForUri(trust.getCimdUri());
    }

    public void purgeCachedSigningKeys(String cimdOrJwksUri) {
        fetchService.purgeCachedKeysForUri(cimdOrJwksUri);
    }

    public ConnectionRecord adoptExistingIdentityProvider(String idpAlias, String trustId) {
        DirectInstallationTrustRecord trust = store.getTrustRecord(trustId)
                .orElseThrow(() -> FedSetupException.notFound("Direct Installation Trust record not found: " + trustId));
        if (trust.isRevoked()) {
            throw FedSetupException.untrustedIssuer("Cannot adopt a Connection under a revoked Direct Installation Trust");
        }
        ConnectionRecord adopted = provisioningService.adoptExistingIdentityProvider(
                idpAlias,
                trust.getApplicationTenantId(),
                trust.getIdpIssuer(),
                trust.getId(),
                trust.getCimdUri());
        store.saveConnection(adopted);
        return adopted;
    }

    public void setPreAuthorizedResourceBindings(List<Map<String, Object>> bindings) {
        try {
            String json = JsonSerialization.writeValueAsString(bindings != null ? bindings : Collections.emptyList());
            realm.setAttribute(FedSetupConstants.PREFIX_RESOURCE_BINDING + "all", json);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to serialize pre-authorized resource bindings", e);
        }
    }

    // ---- Utility methods ----

    private static List<String> parseSpaceDelimited(String input) {
        if (input == null || input.isBlank()) {
            return Collections.emptyList();
        }
        return Arrays.stream(input.trim().split("\\s+"))
                .filter(s -> !s.isEmpty())
                .toList();
    }

    private static String urlEncode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static String escapeHtml(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    private static String toJson(Object obj) {
        try {
            return JsonSerialization.writeValueAsString(obj);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to serialize JSON response", e);
        }
    }
}
