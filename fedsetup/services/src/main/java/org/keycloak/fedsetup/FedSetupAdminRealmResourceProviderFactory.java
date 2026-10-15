package org.keycloak.fedsetup;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory;

public class FedSetupAdminRealmResourceProviderFactory implements AdminRealmResourceProviderFactory {

    @Override
    public AdminRealmResourceProvider create(KeycloakSession session) {
        return new FedSetupAdminRealmResourceProvider(session);
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
}
