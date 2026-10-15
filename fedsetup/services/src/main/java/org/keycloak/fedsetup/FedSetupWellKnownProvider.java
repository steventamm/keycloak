package org.keycloak.fedsetup;

import java.net.URI;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.wellknown.WellKnownProvider;

/**
 * Serves the FedSetup Configuration Discovery Document at `/.well-known/fedsetup/realms/{realm}`.
 */
public class FedSetupWellKnownProvider implements WellKnownProvider {

    private final KeycloakSession session;

    public FedSetupWellKnownProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getConfig() {
        RealmModel realm = session.getContext().getRealm();
        URI baseUri = session.getContext().getUri().getBaseUri();
        String baseUriStr = baseUri.toString();
        if (baseUriStr.endsWith("/")) {
            baseUriStr = baseUriStr.substring(0, baseUriStr.length() - 1);
        }
        FedSetupService service = new FedSetupService(session, realm);
        return service.buildDiscoveryDocument(baseUriStr);
    }

    @Override
    public void close() {
    }
}
