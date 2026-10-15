package org.keycloak.fedsetup;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.keycloak.fedsetup.model.ConnectionRecord;
import org.keycloak.fedsetup.model.PendingTrustAuthorizationRecord;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;

/**
 * Realm-admin REST resource mounted at `/admin/realms/{realm}/fedsetup` for managing
 * Pending Trust Authorizations, Signed Trust Pre-Authorization JWTs, Deferred Approval
 * proposals, Direct Installation Trust records, and Connection Adoption.
 */
public class FedSetupAdminResource {

    private final KeycloakSession session;
    private final RealmModel realm;
    private final AdminPermissionEvaluator auth;
    private final FedSetupService service;

    public FedSetupAdminResource(
            KeycloakSession session,
            RealmModel realm,
            AdminPermissionEvaluator auth,
            AdminEventBuilder adminEvent) {
        this.session = session;
        this.realm = realm;
        this.auth = auth;
        this.service = new FedSetupService(session, realm);
    }

    private void requireManageRealm() {
        if (auth != null && auth.realm() != null) {
            auth.realm().requireManageRealm();
        }
    }

    @GET
    @Path("pending-trust")
    @Produces(MediaType.APPLICATION_JSON)
    public Response listPendingTrust() {
        requireManageRealm();
        return Response.ok(service.getStore().listPendingTrustAuthorizations()).build();
    }

    @POST
    @Path("pending-trust")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @SuppressWarnings("unchecked")
    public Response createPendingTrust(Map<String, Object> body) {
        requireManageRealm();
        try {
            String idpIssuer = (String) body.get("idp_issuer");
            String cimdUri = (String) body.get("cimd_uri");
            List<String> caps = (List<String>) body.get("authorized_capabilities");
            List<String> deleg = (List<String>) body.get("provider_delegation_profiles");
            List<String> ext = (List<String>) body.get("federation_extension_profiles");
            String staticJwks = (String) body.get("static_jwks_json");
            Number ttl = (Number) body.getOrDefault("ttl_seconds", 604800);
            boolean serializeJwt = Boolean.TRUE.equals(body.get("serialize_jwt"));

            PendingTrustAuthorizationRecord rec = service.createPendingTrustAuthorization(
                    idpIssuer, cimdUri, caps, deleg, ext, staticJwks, ttl.longValue());

            Map<String, Object> resp = new LinkedHashMap<>();
            resp.put("pending_trust_authorization", rec);
            if (serializeJwt) {
                resp.put("trust_pre_authorization", service.serializePendingTrustAuthorizationJwt(rec, getBaseUri()));
            }
            return Response.status(Response.Status.CREATED).entity(resp).build();
        } catch (FedSetupException e) {
            return e.toResponse();
        }
    }

    @DELETE
    @Path("pending-trust/{id}")
    public Response revokePendingTrust(@PathParam("id") String id) {
        requireManageRealm();
        service.revokePendingTrustAuthorization(id);
        return Response.noContent().build();
    }

    @GET
    @Path("deferred-proposals")
    @Produces(MediaType.APPLICATION_JSON)
    public Response listDeferredProposals() {
        requireManageRealm();
        return Response.ok(service.getStore().listDeferredProposals()).build();
    }

    @POST
    @Path("deferred-proposals/{pendingId}/approve")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @SuppressWarnings("unchecked")
    public Response approveDeferredProposal(
            @PathParam("pendingId") String pendingId,
            Map<String, Object> body) {
        requireManageRealm();
        try {
            List<String> caps = body != null ? (List<String>) body.get("authorized_capabilities") : null;
            List<String> deleg = body != null ? (List<String>) body.get("provider_delegation_profiles") : null;
            List<String> ext = body != null ? (List<String>) body.get("federation_extension_profiles") : null;
            var trust = service.approveDeferredProposal(pendingId, caps, deleg, ext, getBaseUri());
            return Response.ok(trust).build();
        } catch (FedSetupException e) {
            return e.toResponse();
        }
    }

    @POST
    @Path("deferred-proposals/{pendingId}/deny")
    public Response denyDeferredProposal(@PathParam("pendingId") String pendingId) {
        requireManageRealm();
        try {
            service.denyDeferredProposal(pendingId);
            return Response.noContent().build();
        } catch (FedSetupException e) {
            return e.toResponse();
        }
    }

    @GET
    @Path("trust")
    @Produces(MediaType.APPLICATION_JSON)
    public Response listTrustRecords() {
        requireManageRealm();
        return Response.ok(service.getStore().listTrustRecords()).build();
    }

    @DELETE
    @Path("trust/{trustId}")
    public Response revokeTrustRecord(@PathParam("trustId") String trustId) {
        requireManageRealm();
        try {
            service.revokeDirectInstallationTrust(trustId);
            return Response.noContent().build();
        } catch (FedSetupException e) {
            return e.toResponse();
        }
    }

    @POST
    @Path("trust/purge-keys")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response purgeCachedSigningKeys(Map<String, String> body) {
        requireManageRealm();
        String uri = body != null ? body.get("uri") : null;
        service.purgeCachedSigningKeys(uri);
        return Response.noContent().build();
    }

    @GET
    @Path("connections")
    @Produces(MediaType.APPLICATION_JSON)
    public Response listConnections() {
        requireManageRealm();
        return Response.ok(service.getStore().listConnections()).build();
    }

    @POST
    @Path("connections/adopt")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response adoptConnection(Map<String, String> body) {
        requireManageRealm();
        try {
            String idpAlias = body != null ? body.get("idp_alias") : null;
            String trustId = body != null ? body.get("trust_id") : null;
            if (idpAlias == null || trustId == null) {
                throw FedSetupException.invalidRequest("Both 'idp_alias' and 'trust_id' are required");
            }
            ConnectionRecord adopted = service.adoptExistingIdentityProvider(idpAlias, trustId);
            return Response.status(Response.Status.CREATED).entity(adopted).build();
        } catch (FedSetupException e) {
            return e.toResponse();
        }
    }

    @GET
    @Path("resource-bindings")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getResourceBindings() {
        requireManageRealm();
        return Response.ok(service.getProvisioningService().getRealmPreAuthorizedResourceBindings()).build();
    }

    @PUT
    @Path("resource-bindings")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response configureResourceBindings(List<Map<String, Object>> bindings) {
        requireManageRealm();
        service.setPreAuthorizedResourceBindings(bindings);
        return Response.noContent().build();
    }

    @GET
    @Path("settings")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getSettings() {
        requireManageRealm();
        Map<String, Object> settings = new LinkedHashMap<>();
        settings.put("enabled", service.isEnabled());
        settings.put("application_tenant_mode", service.isSingleTenantMode() ? "single" : "multiple");
        settings.put("sso_connection_cardinality", service.isMultipleSsoCardinality() ? "multiple" : "single");
        settings.put("oauth_flow_enabled", Boolean.TRUE.equals(realm.getAttribute(FedSetupConstants.ATTR_OAUTH_FLOW_ENABLED, Boolean.TRUE)));
        settings.put("deferred_approval_enabled", Boolean.TRUE.equals(realm.getAttribute(FedSetupConstants.ATTR_DEFERRED_APPROVAL_ENABLED, Boolean.FALSE)));
        settings.put("oidc_client_id_metadata_uri", realm.getAttribute(FedSetupConstants.ATTR_OIDC_CIMD_URI));
        return Response.ok(settings).build();
    }

    @PUT
    @Path("settings")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response updateSettings(Map<String, Object> body) {
        requireManageRealm();
        if (body != null) {
            if (body.containsKey("enabled")) {
                realm.setAttribute(FedSetupConstants.ATTR_ENABLED, String.valueOf(Boolean.TRUE.equals(body.get("enabled"))));
            }
            if (body.get("application_tenant_mode") instanceof String tm && !tm.isBlank()) {
                realm.setAttribute(FedSetupConstants.ATTR_TENANT_MODE, tm);
            }
            if (body.get("sso_connection_cardinality") instanceof String card && !card.isBlank()) {
                realm.setAttribute(FedSetupConstants.ATTR_SSO_CARDINALITY, card);
            }
            if (body.containsKey("oauth_flow_enabled")) {
                realm.setAttribute(FedSetupConstants.ATTR_OAUTH_FLOW_ENABLED, String.valueOf(Boolean.TRUE.equals(body.get("oauth_flow_enabled"))));
            }
            if (body.containsKey("deferred_approval_enabled")) {
                realm.setAttribute(FedSetupConstants.ATTR_DEFERRED_APPROVAL_ENABLED, String.valueOf(Boolean.TRUE.equals(body.get("deferred_approval_enabled"))));
            }
            if (body.containsKey("oidc_client_id_metadata_uri")) {
                Object val = body.get("oidc_client_id_metadata_uri");
                if (val instanceof String s && !s.isBlank()) {
                    realm.setAttribute(FedSetupConstants.ATTR_OIDC_CIMD_URI, s);
                } else {
                    realm.removeAttribute(FedSetupConstants.ATTR_OIDC_CIMD_URI);
                }
            }
        }
        return getSettings();
    }

    private String getBaseUri() {
        String uri = session.getContext().getUri().getBaseUri().toString();
        if (uri.endsWith("/")) {
            uri = uri.substring(0, uri.length() - 1);
        }
        return uri;
    }
}
