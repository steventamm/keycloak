/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.fedsetup.representation;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/** Core ID-JAG desired and applied state for one independently administered requesting client. */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class FedSetupIdJagConfiguration {
    @JsonProperty("client_id") private String clientId;
    @JsonProperty("cimd_uri") private String cimdUri;
    @JsonProperty("requester_type") private String requesterType;
    @JsonProperty("requester_name") private String requesterName;
    @JsonProperty("resource_connections") private List<ResourceConnection> resourceConnections = new ArrayList<>();

    public String getClientId() { return clientId; }
    public void setClientId(String value) { clientId = value; }
    public String getCimdUri() { return cimdUri; }
    public void setCimdUri(String value) { cimdUri = value; }
    public String getRequesterType() { return requesterType; }
    public void setRequesterType(String value) { requesterType = value; }
    public String getRequesterName() { return requesterName; }
    public void setRequesterName(String value) { requesterName = value; }
    public List<ResourceConnection> getResourceConnections() { return resourceConnections; }
    public void setResourceConnections(List<ResourceConnection> value) { resourceConnections = value == null ? new ArrayList<>() : new ArrayList<>(value); }

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public static class ResourceConnection {
        @JsonProperty("resource_connection_id") private String resourceConnectionId;
        @JsonProperty("resource_issuer") private String resourceIssuer;
        private String resource;
        private Set<String> scopes = new LinkedHashSet<>();
        private Map<String, Object> conditions = new LinkedHashMap<>();
        public String getResourceConnectionId() { return resourceConnectionId; }
        public void setResourceConnectionId(String value) { resourceConnectionId = value; }
        public String getResourceIssuer() { return resourceIssuer; }
        public void setResourceIssuer(String value) { resourceIssuer = value; }
        public String getResource() { return resource; }
        public void setResource(String value) { resource = value; }
        public Set<String> getScopes() { return scopes; }
        public void setScopes(Set<String> value) { scopes = value == null ? new LinkedHashSet<>() : new LinkedHashSet<>(value); }
        public Map<String, Object> getConditions() { return conditions; }
        public void setConditions(Map<String, Object> value) { conditions = value == null ? new LinkedHashMap<>() : new LinkedHashMap<>(value); }
    }
}
