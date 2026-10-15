package org.keycloak.fedsetup;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;

public class FedSetupAdminRealmResourceProvider implements AdminRealmResourceProvider {

    private final KeycloakSession session;

    public FedSetupAdminRealmResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource(
            KeycloakSession session,
            RealmModel realm,
            AdminPermissionEvaluator auth,
            AdminEventBuilder adminEvent) {
        return new FedSetupAdminResource(session, realm, auth, adminEvent);
    }

    @Override
    public void close() {
    }
}
