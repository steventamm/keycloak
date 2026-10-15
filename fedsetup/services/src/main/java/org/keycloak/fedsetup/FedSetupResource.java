package org.keycloak.fedsetup;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.PATCH;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * JAX-RS resource mounted at `/realms/{realm}/fedsetup` implementing the runtime endpoints of
 * FedSetup Express Configuration, Deferred Trust, and Extensions.
 */
public class FedSetupResource {

    private final KeycloakSession session;
    private final RealmModel realm;
    private final FedSetupService service;

    public FedSetupResource(KeycloakSession session) {
        this.session = session;
        this.realm = session.getContext().getRealm();
        this.service = new FedSetupService(session, realm);
    }

    public FedSetupResource(KeycloakSession session, FedSetupService service) {
        this.session = session;
        this.realm = session.getContext().getRealm();
        this.service = service;
    }

    @POST
    @Path("install")
    @Produces(MediaType.APPLICATION_JSON)
    public Response install(
            @HeaderParam("Authorization") String authorizationHeader,
            @HeaderParam("Idempotency-Key") String idempotencyKey,
            byte[] rawBodyBytes) {
        try {
            return service.handleInstall(authorizationHeader, idempotencyKey, rawBodyBytes, getBaseUri());
        } catch (FedSetupException e) {
            return e.toResponse();
        }
    }

    @GET
    @Path("consent")
    public Response consent(
            @Context UriInfo uriInfo,
            @QueryParam("decision") String decision,
            @QueryParam("csrf_token") String csrfToken) {
        try {
            return service.handleConsentRequest(uriInfo.getQueryParameters(), decision, csrfToken, getBaseUri());
        } catch (FedSetupException e) {
            return e.toResponse();
        }
    }

    @POST
    @Path("configure")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response configure(
            @HeaderParam("Authorization") String authorizationHeader,
            @HeaderParam("Idempotency-Key") String idempotencyKey,
            byte[] rawBodyBytes) {
        try {
            return service.handleConfigure(authorizationHeader, idempotencyKey, rawBodyBytes, getBaseUri());
        } catch (FedSetupException e) {
            return e.toResponse();
        }
    }

    @GET
    @Path("connection/{connection_id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getConnection(
            @PathParam("connection_id") String connectionId,
            @HeaderParam("Authorization") String authorizationHeader) {
        try {
            return service.handleGetConnection(connectionId, authorizationHeader, getBaseUri());
        } catch (FedSetupException e) {
            return e.toResponse();
        }
    }

    @PATCH
    @Path("connection/{connection_id}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response patchConnection(
            @PathParam("connection_id") String connectionId,
            @HeaderParam("Authorization") String authorizationHeader,
            @HeaderParam("If-Match") String ifMatchHeader,
            @HeaderParam("Idempotency-Key") String idempotencyKey,
            byte[] rawBodyBytes) {
        try {
            return service.handlePatchConnection(
                    connectionId, authorizationHeader, ifMatchHeader, idempotencyKey, rawBodyBytes, getBaseUri());
        } catch (FedSetupException e) {
            return e.toResponse();
        }
    }

    @DELETE
    @Path("connection/{connection_id}")
    public Response deleteConnection(
            @PathParam("connection_id") String connectionId,
            @HeaderParam("Authorization") String authorizationHeader) {
        try {
            return service.handleDeleteConnection(connectionId, authorizationHeader, getBaseUri());
        } catch (FedSetupException e) {
            return e.toResponse();
        }
    }

    @GET
    @Path("connections")
    @Produces(MediaType.APPLICATION_JSON)
    public Response queryConnections(
            @Context UriInfo uriInfo,
            @HeaderParam("Authorization") String authorizationHeader,
            @QueryParam("capability") String capability,
            @QueryParam("status") String status,
            @QueryParam("limit") Integer limit,
            @QueryParam("cursor") String cursor) {
        try {
            String fullUri = uriInfo != null && uriInfo.getRequestUri() != null
                    ? uriInfo.getRequestUri().toString()
                    : getBaseUri() + "/realms/" + realm.getName() + "/" + FedSetupConstants.PROVIDER_ID + "/connections";
            return service.handleQueryConnections(
                    authorizationHeader, fullUri, capability, status, limit, cursor, getBaseUri());
        } catch (FedSetupException e) {
            return e.toResponse();
        }
    }

    @GET
    @Path("trust-jwks.json")
    @Produces("application/jwk-set+json")
    public Response getTrustJwks() {
        return Response.ok(service.getJwtService().getRealmTrustJwks())
                .type("application/jwk-set+json")
                .build();
    }

    @GET
    @Path("oidc-jwks/{connection_id}")
    @Produces("application/jwk-set+json")
    public Response getOidcConnectionJwks(@PathParam("connection_id") String connectionId) {
        try {
            if (service.getStore().getConnection(connectionId).isEmpty()) {
                throw FedSetupException.notFound("Connection not found: " + connectionId);
            }
            return Response.ok(service.getJwtService().getRealmTrustJwks())
                    .type("application/jwk-set+json")
                    .build();
        } catch (FedSetupException e) {
            return e.toResponse();
        }
    }

    private String getBaseUri() {
        String uri = session.getContext().getUri().getBaseUri().toString();
        if (uri.endsWith("/")) {
            uri = uri.substring(0, uri.length() - 1);
        }
        return uri;
    }
}
