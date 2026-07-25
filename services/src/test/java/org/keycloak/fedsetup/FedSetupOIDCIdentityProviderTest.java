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
package org.keycloak.fedsetup;

import org.junit.jupiter.api.Test;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.http.simple.SimpleHttpRequest;
import org.keycloak.models.IdentityProviderModel;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class FedSetupOIDCIdentityProviderTest {

    @Test
    void sendsOnlyClientIdForFedSetupPublicClientAuthentication() {
        OIDCIdentityProviderConfig config = new OIDCIdentityProviderConfig(new IdentityProviderModel());
        config.setDefaultScope("");
        config.setClientId("application-client");
        config.setClientAuthMethod("none");
        FedSetupOIDCIdentityProvider provider = new FedSetupOIDCIdentityProvider(null, config);
        SimpleHttpRequest request = SimpleHttp.create((org.apache.http.client.HttpClient) null)
                .doPost("https://issuer.example/token");

        SimpleHttpRequest authenticated = provider.authenticateTokenRequest(request);

        assertEquals("application-client", authenticated.getParam("client_id"));
        assertNull(authenticated.getParam("client_secret"));
        assertNull(authenticated.getHeader("Authorization"));
    }
}
