package org.keycloak.fedsetup;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.keycloak.fedsetup.representations.ErrorResponseRepresentation;

/**
 * Exception representing a normative FedSetup Express Configuration error response.
 */
public class FedSetupException extends RuntimeException {

    private final String error;
    private final String errorDescription;
    private final Response.Status status;
    private final String wwwAuthenticate;

    public FedSetupException(String error, String errorDescription, Response.Status status) {
        this(error, errorDescription, status, null);
    }

    public FedSetupException(String error, String errorDescription, Response.Status status, String wwwAuthenticate) {
        super(errorDescription != null ? error + ": " + errorDescription : error);
        this.error = error;
        this.errorDescription = errorDescription;
        this.status = status;
        this.wwwAuthenticate = wwwAuthenticate;
    }

    public String getError() {
        return error;
    }

    public String getErrorDescription() {
        return errorDescription;
    }

    public Response.Status getStatus() {
        return status;
    }

    public String getWwwAuthenticate() {
        return wwwAuthenticate;
    }

    public Response toResponse() {
        Response.ResponseBuilder builder = Response.status(status)
                .type(MediaType.APPLICATION_JSON)
                .entity(new ErrorResponseRepresentation(error, errorDescription));
        if (wwwAuthenticate != null && !wwwAuthenticate.isBlank()) {
            builder.header(FedSetupConstants.HEADER_WWW_AUTHENTICATE, wwwAuthenticate);
        }
        return builder.build();
    }

    public static FedSetupException invalidRequest(String description) {
        return new FedSetupException(FedSetupConstants.ERR_INVALID_REQUEST, description, Response.Status.BAD_REQUEST);
    }

    public static FedSetupException invalidCredential(String description) {
        return new FedSetupException(
                FedSetupConstants.ERR_INVALID_CREDENTIAL,
                description,
                Response.Status.UNAUTHORIZED,
                "Bearer error=\"invalid_token\""
        );
    }

    public static FedSetupException untrustedIssuer(String description) {
        return new FedSetupException(FedSetupConstants.ERR_UNTRUSTED_ISSUER, description, Response.Status.FORBIDDEN);
    }

    public static FedSetupException insufficientScope(String requiredScope, String description) {
        String challenge = "Bearer error=\"insufficient_scope\", scope=\"" + requiredScope + "\"";
        return new FedSetupException(
                FedSetupConstants.ERR_INSUFFICIENT_SCOPE,
                description,
                Response.Status.FORBIDDEN,
                challenge
        );
    }

    public static FedSetupException unsupportedProtocol(String description) {
        return new FedSetupException(FedSetupConstants.ERR_UNSUPPORTED_PROTOCOL, description, Response.Status.BAD_REQUEST);
    }

    public static FedSetupException conflict(String description) {
        return new FedSetupException(FedSetupConstants.ERR_CONFLICT, description, Response.Status.CONFLICT);
    }

    public static FedSetupException preconditionFailed(String description) {
        return new FedSetupException(FedSetupConstants.ERR_PRECONDITION_FAILED, description, Response.Status.PRECONDITION_FAILED);
    }

    public static FedSetupException notFound(String description) {
        return new FedSetupException(FedSetupConstants.ERR_NOT_FOUND, description, Response.Status.NOT_FOUND);
    }

    public static FedSetupException serverError(String description) {
        return new FedSetupException(FedSetupConstants.ERR_SERVER_ERROR, description, Response.Status.INTERNAL_SERVER_ERROR);
    }

    public static FedSetupException authorizationPending(String description) {
        return new FedSetupException(FedSetupConstants.ERR_AUTHORIZATION_PENDING, description, Response.Status.BAD_REQUEST);
    }

    public static FedSetupException slowDown(String description) {
        return new FedSetupException(FedSetupConstants.ERR_SLOW_DOWN, description, Response.Status.BAD_REQUEST);
    }

    public static FedSetupException expiredToken(String description) {
        return new FedSetupException(FedSetupConstants.ERR_EXPIRED_TOKEN, description, Response.Status.BAD_REQUEST);
    }

    public static FedSetupException accessDenied(String description) {
        return new FedSetupException(FedSetupConstants.ERR_ACCESS_DENIED, description, Response.Status.FORBIDDEN);
    }
}
