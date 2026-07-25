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

import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.http.simple.SimpleHttpRequest;
import org.keycloak.models.KeycloakSession;

/**
 * OIDC broker used only for a FedSetup-managed connection.  It isolates
 * FedSetup's encrypted credential records and public-client authentication
 * from the ordinary OIDC broker provider.
 */
public final class FedSetupOIDCIdentityProvider extends OIDCIdentityProvider {

    public FedSetupOIDCIdentityProvider(KeycloakSession session, OIDCIdentityProviderConfig config) {
        super(session, config);
    }

    @Override
    public SimpleHttpRequest authenticateTokenRequest(SimpleHttpRequest tokenRequest) {
        if ("none".equals(getConfig().getClientAuthMethod())) {
            return tokenRequest.param(OAuth2Constants.CLIENT_ID, getConfig().getClientId());
        }
        return super.authenticateTokenRequest(tokenRequest);
    }

    @Override
    protected String resolveClientSecret() {
        // The inherited refresh helpers still accept a historical
        // client-secret argument even though token-request authentication is
        // applied separately.  A public FedSetup client must not trigger a
        // Vault or encrypted-record lookup along that path.
        if ("none".equals(getConfig().getClientAuthMethod())) {
            return "";
        }
        return FedSetupCredentialResolver.resolve(session, super.resolveClientSecret());
    }
}
