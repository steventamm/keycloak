package org.keycloak.scim.services;

import java.io.InputStream;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.function.BiFunction;
import java.util.stream.Stream;

import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.PATCH;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import jakarta.ws.rs.core.UriBuilder;

import org.keycloak.events.admin.OperationType;
import org.keycloak.fedsetup.representation.FedSetupConnection;
import org.keycloak.models.KeycloakSession;
import org.keycloak.scim.protocol.ForbiddenException;
import org.keycloak.scim.protocol.request.PatchRequest;
import org.keycloak.scim.protocol.request.PatchRequest.PatchOperation;
import org.keycloak.scim.protocol.request.SearchRequest;
import org.keycloak.scim.protocol.response.ListResponse;
import org.keycloak.scim.resource.ResourceTypeRepresentation;
import org.keycloak.scim.resource.Scim;
import org.keycloak.scim.resource.common.Meta;
import org.keycloak.scim.resource.spi.ScimResourceTypeProvider;
import org.keycloak.scim.resource.spi.SingletonResourceTypeProvider;
import org.keycloak.scim.resource.group.Group;
import org.keycloak.scim.resource.user.User;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.util.JsonSerialization;

import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import org.jboss.logging.Logger;

import static org.keycloak.scim.services.Error.badRequest;
import static org.keycloak.scim.services.Error.forbidden;
import static org.keycloak.scim.services.Error.invalidSyntax;
import static org.keycloak.scim.services.Error.resourceNotFound;
import static org.keycloak.scim.services.Error.toResponse;

public class ScimResourceTypeResource<R extends ResourceTypeRepresentation> {

    private static final Logger logger = Logger.getLogger(ScimResourceTypeResource.class);
    private static final String APPLICATION_SCIM_JSON = "application/scim+json";

    private final KeycloakSession session;
    private final ScimResourceTypeProvider<R> resourceTypeProvider;
    private final Class<? extends ResourceTypeRepresentation> resourceTypeClazz;
    private final AdminEventBuilder adminEvent;
    private final FedSetupConnection fedSetupConnection;

    public ScimResourceTypeResource(KeycloakSession session, ScimResourceTypeProvider<R> resourceTypeProvider, AdminEventBuilder adminEvent) {
        this(session, resourceTypeProvider, adminEvent, null);
    }

    public ScimResourceTypeResource(KeycloakSession session, ScimResourceTypeProvider<R> resourceTypeProvider,
                                    AdminEventBuilder adminEvent, FedSetupConnection fedSetupConnection) {
        this.session = session;
        this.resourceTypeProvider = resourceTypeProvider;
        this.resourceTypeClazz = resourceTypeProvider.getResourceType();
        this.adminEvent = adminEvent.resource(resourceTypeProvider.getAdminEventResourceType());
        this.fedSetupConnection = fedSetupConnection;
    }

    @POST
    @Consumes({APPLICATION_SCIM_JSON, MediaType.APPLICATION_JSON})
    @Produces(APPLICATION_SCIM_JSON)
    public Response create(InputStream is) {
        if (!allowsCreate()) return forbidden();
        R resource = parseResourceTypePayload(is);

        if (resource.getId() != null) {
            return invalidSyntax("Unexpected identifier");
        }

        return onPersist(resource, Status.CREATED,
                (rScimResourceTypeProvider, r) -> {
                    R created = resourceTypeProvider.create(r);
                    logger.debugf("SCIM CREATE %s id=%s", resourceTypeProvider.getName(), created.getId());
                    adminEvent.operation(OperationType.CREATE)
                            .resourcePath(session.getContext().getUri(), created.getId())
                            .representation(created)
                            .success();
                    return created;
                });
    }

    @Path("{id}")
    @GET
    @Produces(APPLICATION_SCIM_JSON)
    public Response get(@PathParam("id") String id,
                        @QueryParam("attributes") String attributes,
                        @QueryParam("excludedAttributes") String excludedAttributes) {
        if (!allowsRead()) return forbidden();
        logger.debugf("SCIM GET %s id=%s", resourceTypeProvider.getName(), id);
        List<String> attrList = attributes != null ? List.of(attributes.split(",")) : null;
        List<String> excludedList = excludedAttributes != null ? List.of(excludedAttributes.split(",")) : null;

        R resource = getResource(id, attrList, excludedList);

        if (resource == null) {
            return resourceNotFound(id);
        }

        setMetadata(resource);

        return Response.ok().entity(resource).build();
    }

    @GET
    @Produces(APPLICATION_SCIM_JSON)
    public Response getAll(@QueryParam("filter") String filterExpression,
                           @QueryParam("attributes") String attributes,
                           @QueryParam("excludedAttributes") String excludedAttributes,
                           @QueryParam("sortBy") String sortBy,
                           @QueryParam("sortOrder") String sortOrder,
                           @QueryParam("startIndex") Integer startIndex,
                           @QueryParam("count") Integer count) {
        if (!allowsRead()) return forbidden();
        // Delegate to common search logic
        return search(SearchRequest.builder().withFilter(filterExpression)
                        .withAttributes(attributes != null ? List.of(attributes.split(",")) : null)
                        .withExcludedAttributes(excludedAttributes != null ? List.of(excludedAttributes.split(",")) : null)
                        .withSortBy(sortBy)
                        .withSortOrder(sortOrder)
                        .withStartIndex(startIndex)
                        .withCount(count).build());
    }

    @Path(".search")
    @POST
    @Consumes({APPLICATION_SCIM_JSON, MediaType.APPLICATION_JSON})
    @Produces(APPLICATION_SCIM_JSON)
    public Response search(SearchRequest searchRequest) {
        if (!allowsRead()) return forbidden();
        logger.debugf("SCIM SEARCH %s filter=%s", resourceTypeProvider.getName(), searchRequest.getFilter());
        try {
            Stream<R> stream = resourceTypeProvider.getAll(searchRequest)
                    .peek(this::setMetadata);

            if (resourceTypeProvider instanceof SingletonResourceTypeProvider<R>) {
                return Response.ok().entity(stream
                                .findAny().orElseThrow(NotFoundException::new))
                        .build();
            }

            List<R> resources = stream.toList();
            Long totalResults = resourceTypeProvider.count(searchRequest);
            ListResponse<R> response = new ListResponse<>();

            response.setResources(resources);
            response.setTotalResults(totalResults.intValue());
            response.setStartIndex(searchRequest.getStartIndex() != null ? searchRequest.getStartIndex() : 1);
            response.setItemsPerPage(resources.size());

            return Response.ok().entity(response).build();
        } catch (Exception e) {
            return toResponse(session, e);
        }
    }

    @Path("{id}")
    @DELETE
    @Produces(APPLICATION_SCIM_JSON)
    public Response delete(@PathParam("id") String id) {
        if (!allowsDelete()) return forbidden();
        logger.debugf("SCIM DELETE %s id=%s", resourceTypeProvider.getName(), id);
        try {
            R resource = getResource(id);

            if (resource == null) {
                return resourceNotFound(id);
            }

            if (resourceTypeProvider.delete(id)) {
                adminEvent.operation(OperationType.DELETE)
                        .resourcePath(session.getContext().getUri())
                        .representation(resource)
                        .success();
                return Response.noContent().build();
            }

            return badRequest("Could not delete resource not found with id " + id);
        } catch (Exception e) {
            return toResponse(session, e);
        }
    }

    @Path("{id}")
    @PUT
    @Consumes({APPLICATION_SCIM_JSON, MediaType.APPLICATION_JSON})
    @Produces(APPLICATION_SCIM_JSON)
    public Response update(@PathParam("id") String id, InputStream is) {
        if (!allowsUpdateOperation()) return forbidden();
        logger.debugf("SCIM UPDATE %s id=%s", resourceTypeProvider.getName(), id);
        R existing = getResource(id);

        if (existing == null) {
            return resourceNotFound(id);
        }

        R resource = parseResourceTypePayload(is);

        if (!existing.getId().equals(resource.getId())) {
            return invalidSyntax("Invalid reference to resource");
        }
        if (!allowsUpdate(existing, resource)) return forbidden();

        return onPersist(resource, Status.OK,
                (rScimResourceTypeProvider, r) -> {
                    R updated = resourceTypeProvider.update(r);
                    adminEvent.operation(OperationType.UPDATE)
                            .resourcePath(session.getContext().getUri())
                            .representation(updated)
                            .success();
                    return updated;
                });
    }

    @Path("{id}")
    @PATCH
    @Consumes({APPLICATION_SCIM_JSON, MediaType.APPLICATION_JSON})
    @Produces(APPLICATION_SCIM_JSON)
    public Response patch(@PathParam("id") String id, PatchRequest request) {
        if (!allowsUpdateOperation() || !allowsPatch(request)) return forbidden();
        logger.debugf("SCIM PATCH %s id=%s", resourceTypeProvider.getName(), id);
        R existing = getResource(id);

        if (existing == null) {
            return resourceNotFound(id);
        }

        if (!request.getSchemas().contains(Scim.PATCH_OP_CORE_SCHEMA)) {
            return invalidSyntax("No PATCH op schema provided in request");
        }

        return onPersist(existing, Status.OK, (rScimResourceTypeProvider, r) -> {
            resourceTypeProvider.patch(existing, request.getOperations());
            R patched = getResource(id);
            adminEvent.operation(OperationType.UPDATE)
                    .resourcePath(session.getContext().getUri())
                    .representation(patched)
                    .success();
            return patched;
        });
    }

    @SuppressWarnings("unchecked")
    private R parseResourceTypePayload(InputStream is) {
        try {
            return  (R) JsonSerialization.readValue(is, resourceTypeClazz);
        } catch (UnrecognizedPropertyException upe) {
            String message = "Unrecognized attribute: " + upe.getPropertyName();
            throw new BadRequestException(invalidSyntax(message));
        } catch (Exception e) {
            throw new BadRequestException(badRequest("Unknown error parsing the request"));
        }
    }

    private void setMetadata(R resource) {
        Meta meta = new Meta();
        meta.setResourceType(resourceTypeProvider.getName());
        Long createdTimestamp = resource.getCreatedTimestamp();
        Long lastModifiedTimestamp = resource.getLastModifiedTimestamp();
        if (createdTimestamp != null) {
            meta.setCreated(Instant.ofEpochMilli(createdTimestamp).toString());
        }
        if (lastModifiedTimestamp != null) {
            meta.setLastModified(Instant.ofEpochMilli(lastModifiedTimestamp).toString());
        }
        UriBuilder location = session.getContext().getUri().getAbsolutePathBuilder();
        if (resource.getId() != null) {
            String path = session.getContext().getUri().getAbsolutePath().getPath();
            if (!path.endsWith("/" + resource.getId())) {
                location.path(resource.getId());
            }
        }
        meta.setLocation(location.build().toString());
        resource.setMeta(meta);
    }

    private Response onPersist(R resource, Status status, BiFunction<ScimResourceTypeProvider<R>, R, R> consumer) {
        try {
            R r = consumer.apply(resourceTypeProvider, resource);

            setMetadata(r);

            return Response.status(status).entity(r).build();
        } catch (Exception e) {
            return toResponse(session, e);
        }
    }

    private R getResource(String id) {
        return getResource(id, null, null);
    }

    private R getResource(String id, List<String> attributes, List<String> excludedAttributes) {
        if (id == null) {
            return null;
        }

        try {
            return resourceTypeProvider.get(id, attributes, excludedAttributes);
        } catch (ForbiddenException fe) {
            throw new jakarta.ws.rs.ForbiddenException(forbidden());
        }
    }

    /** Applies FedSetup's negotiated operation subset without changing ordinary SCIM callers. */
    private boolean allowsRead() {
        return allowsRead(fedSetupConnection, resourceTypeClazz);
    }

    private boolean allowsCreate() {
        return allowsCreate(fedSetupConnection, resourceTypeClazz);
    }

    private boolean allowsDelete() {
        return allowsDelete(fedSetupConnection, resourceTypeClazz);
    }

    private boolean allowsUpdateOperation() {
        return allowsUpdateOperation(fedSetupConnection, resourceTypeClazz);
    }

    private boolean allowsUpdate(R existing, R replacement) {
        if (fedSetupConnection == null || isGroup()) return true;
        if (!isUser() || !(existing instanceof User before) || !(replacement instanceof User after)) return false;
        // A complete SCIM PUT is also a profile replacement.  The active
        // transition, when present, is separately constrained below.
        return allowsUserPut(fedSetupConnection, before, after);
    }

    private boolean allowsPatch(PatchRequest request) {
        return allowsPatch(fedSetupConnection, resourceTypeClazz, request);
    }

    static boolean allowsRead(FedSetupConnection connection, Class<?> resourceType) {
        return connection == null || isUser(resourceType) || isGroup(resourceType);
    }

    static boolean allowsCreate(FedSetupConnection connection, Class<?> resourceType) {
        if (connection == null) return true;
        if (isUser(resourceType)) return hasFeature(connection, "PUSH_NEW_USERS");
        return isGroup(resourceType) && hasFeature(connection, "PUSH_GROUPS");
    }

    static boolean allowsDelete(FedSetupConnection connection, Class<?> resourceType) {
        if (connection == null) return true;
        // The negotiated FedSetup subset deactivates Users. It does not
        // authorize SCIM DELETE for them.
        return isGroup(resourceType) && hasFeature(connection, "PUSH_GROUPS");
    }

    static boolean allowsUpdateOperation(FedSetupConnection connection, Class<?> resourceType) {
        if (connection == null) return true;
        if (isGroup(resourceType)) return hasFeature(connection, "PUSH_GROUPS");
        return isUser(resourceType);
    }

    static boolean allowsUserPut(FedSetupConnection connection, User before, User after) {
        if (connection == null) return true;
        if (!hasFeature(connection, "PUSH_PROFILE_UPDATES")) return false;
        return allowsActiveTransition(connection, before.getActive(), after.getActive());
    }

    static boolean allowsPatch(FedSetupConnection connection, Class<?> resourceType, PatchRequest request) {
        if (connection == null || isGroup(resourceType)) return true;
        if (!isUser(resourceType) || request == null || request.getOperations() == null || request.getOperations().isEmpty()) return false;
        for (PatchOperation operation : request.getOperations()) {
            String path = operation.getPath();
            if (targetsActive(operation)) {
                Boolean active = patchActiveValue(operation);
                if (active == null || !allowsActiveTransition(connection, null, active)) return false;
                // A root object can carry both active and profile attributes.
                if (path == null && operation.getValue() != null && operation.getValue().isObject()
                        && operation.getValue().size() > 1 && !hasFeature(connection, "PUSH_PROFILE_UPDATES")) return false;
            } else if (!hasFeature(connection, "PUSH_PROFILE_UPDATES")) {
                return false;
            }
        }
        return true;
    }

    private static boolean targetsActive(PatchOperation operation) {
        String path = operation.getPath();
        return path != null && isCoreUserActivePath(path)
                || path == null && operation.getValue() != null && operation.getValue().isObject() && operation.getValue().has("active");
    }

    private static Boolean patchActiveValue(PatchOperation operation) {
        String path = operation.getPath();
        if (path != null && isCoreUserActivePath(path)) {
            return operation.getValue() != null && operation.getValue().isBoolean() ? operation.getValue().booleanValue() : null;
        }
        if (path == null && operation.getValue() != null && operation.getValue().isObject() && operation.getValue().has("active")) {
            return operation.getValue().get("active").isBoolean() ? operation.getValue().get("active").booleanValue() : null;
        }
        return null;
    }

    private static boolean isCoreUserActivePath(String path) {
        String value = path.trim();
        return "active".equalsIgnoreCase(value)
                || "urn:ietf:params:scim:schemas:core:2.0:User:active".equalsIgnoreCase(value);
    }

    private static boolean allowsActiveTransition(FedSetupConnection connection, Boolean before, Boolean after) {
        if (Objects.equals(before, after)) return true;
        return Boolean.TRUE.equals(after) ? hasFeature(connection, "REACTIVATE_USERS") : hasFeature(connection, "PUSH_USER_DEACTIVATION");
    }

    private static boolean hasFeature(FedSetupConnection connection, String feature) {
        // An empty feature set represents a record created by the preview
        // before feature selection was persisted.
        return connection.getScimFeatures().isEmpty() || connection.getScimFeatures().contains(feature);
    }

    private boolean isUser() {
        return isUser(resourceTypeClazz);
    }

    private boolean isGroup() {
        return isGroup(resourceTypeClazz);
    }

    private static boolean isUser(Class<?> resourceType) {
        return User.class.isAssignableFrom(resourceType);
    }

    private static boolean isGroup(Class<?> resourceType) {
        return Group.class.isAssignableFrom(resourceType);
    }
}
