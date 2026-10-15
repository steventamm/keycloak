package org.keycloak.fedsetup.representations;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class ConnectionQueryResponseRepresentation {

    @JsonProperty("connections")
    private List<ConnectionSummary> connections;

    @JsonProperty("next_cursor")
    private String nextCursor;

    public List<ConnectionSummary> getConnections() {
        return connections;
    }

    public void setConnections(List<ConnectionSummary> connections) {
        this.connections = connections;
    }

    public String getNextCursor() {
        return nextCursor;
    }

    public void setNextCursor(String nextCursor) {
        this.nextCursor = nextCursor;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class ConnectionSummary {
        @JsonProperty("connection_id")
        private String connectionId;

        @JsonProperty("etag")
        private String etag;

        @JsonProperty("capabilities")
        private List<String> capabilities;

        @JsonProperty("status")
        private String status;

        @JsonProperty("idp_issuer")
        private String idpIssuer;

        @JsonProperty("application_tenant_id")
        private String applicationTenantId;

        @JsonProperty("origin")
        private String origin;

        @JsonProperty("connection_name")
        private String connectionName;

        @JsonProperty("created_at")
        private String createdAt;

        @JsonProperty("updated_at")
        private String updatedAt;

        public String getConnectionId() {
            return connectionId;
        }

        public void setConnectionId(String connectionId) {
            this.connectionId = connectionId;
        }

        public String getEtag() {
            return etag;
        }

        public void setEtag(String etag) {
            this.etag = etag;
        }

        public List<String> getCapabilities() {
            return capabilities;
        }

        public void setCapabilities(List<String> capabilities) {
            this.capabilities = capabilities;
        }

        public String getStatus() {
            return status;
        }

        public void setStatus(String status) {
            this.status = status;
        }

        public String getIdpIssuer() {
            return idpIssuer;
        }

        public void setIdpIssuer(String idpIssuer) {
            this.idpIssuer = idpIssuer;
        }

        public String getApplicationTenantId() {
            return applicationTenantId;
        }

        public void setApplicationTenantId(String applicationTenantId) {
            this.applicationTenantId = applicationTenantId;
        }

        public String getOrigin() {
            return origin;
        }

        public void setOrigin(String origin) {
            this.origin = origin;
        }

        public String getConnectionName() {
            return connectionName;
        }

        public void setConnectionName(String connectionName) {
            this.connectionName = connectionName;
        }

        public String getCreatedAt() {
            return createdAt;
        }

        public void setCreatedAt(String createdAt) {
            this.createdAt = createdAt;
        }

        public String getUpdatedAt() {
            return updatedAt;
        }

        public void setUpdatedAt(String updatedAt) {
            this.updatedAt = updatedAt;
        }
    }
}
