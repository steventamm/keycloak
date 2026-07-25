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

import java.util.LinkedHashSet;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/** Administrator-approved mapping from a FedSetup resource URI to a local Keycloak resource client. */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class FedSetupIdJagResourceBinding {
    private String resource;
    @JsonProperty("client_id") private String clientId;
    private Set<String> scopes = new LinkedHashSet<>();
    public String getResource() { return resource; }
    public void setResource(String value) { resource = value; }
    public String getClientId() { return clientId; }
    public void setClientId(String value) { clientId = value; }
    public Set<String> getScopes() { return scopes; }
    public void setScopes(Set<String> value) { scopes = value == null ? new LinkedHashSet<>() : new LinkedHashSet<>(value); }
}
