package org.keycloak.fedsetup;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

public class FedSetupRealmResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;

    public FedSetupRealmResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return new FedSetupResource(session);
    }

    @Override
    public void close() {
    }
}
