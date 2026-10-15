package org.keycloak.fedsetup;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.wellknown.WellKnownProvider;
import org.keycloak.wellknown.WellKnownProviderFactory;

/**
 * Factory for {@link FedSetupWellKnownProvider}, enabled for RFC 8414 path-inserted server metadata
 * (`/.well-known/fedsetup/realms/{realm}`).
 */
public class FedSetupWellKnownProviderFactory implements WellKnownProviderFactory {

    @Override
    public WellKnownProvider create(KeycloakSession session) {
        return new FedSetupWellKnownProvider(session);
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return FedSetupConstants.PROVIDER_ID;
    }

    @Override
    public boolean isAvailableViaServerMetadata() {
        return true;
    }
}
