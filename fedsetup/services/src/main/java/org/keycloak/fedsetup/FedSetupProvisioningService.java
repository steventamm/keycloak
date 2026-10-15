package org.keycloak.fedsetup;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.saml.SAMLIdentityProviderConfig;
import org.keycloak.common.util.Time;
import org.keycloak.fedsetup.model.ConnectionRecord;
import org.keycloak.fedsetup.representations.ConfigurationRequestRepresentation;
import org.keycloak.fedsetup.representations.ConfigurationResponseRepresentation;
import org.keycloak.fedsetup.security.FedSetupFetchService;
import org.keycloak.fedsetup.storage.FedSetupStore;
import org.keycloak.models.ClientModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.util.JsonSerialization;

/**
 * Maps FedSetup Express Configuration capabilities (OIDC, SAML, SCIM, ID-JAG, Provider Delegation,
 * and Federation Extension Profiles) onto native Keycloak IdentityProviderModel and ClientModel instances.
 */
public class FedSetupProvisioningService {

    private static final Set<String> SUPPORTED_SCIM_FEATURES = Set.of(
            "PUSH_NEW_USERS",
            "PUSH_PROFILE_UPDATES",
            "PUSH_USER_UPDATES",
            "PUSH_USER_DEACTIVATION",
            "PUSH_GROUPS",
            "PUSH_PASSWORD_UPDATES"
    );

    private final KeycloakSession session;
    private final RealmModel realm;
    private final FedSetupFetchService fetchService;

    public FedSetupProvisioningService(KeycloakSession session, RealmModel realm, FedSetupFetchService fetchService) {
        this.session = session;
        this.realm = realm;
        this.fetchService = fetchService;
    }

    public static class ProvisioningOutcome {
        private final ConfigurationResponseRepresentation response;
        private final boolean secretIssuedOrCarried;

        public ProvisioningOutcome(ConfigurationResponseRepresentation response, boolean secretIssuedOrCarried) {
            this.response = response;
            this.secretIssuedOrCarried = secretIssuedOrCarried;
        }

        public ConfigurationResponseRepresentation getResponse() {
            return response;
        }

        public boolean isSecretIssuedOrCarried() {
            return secretIssuedOrCarried;
        }
    }

    /**
     * Validates and applies requested capabilities and extensions to a ConnectionRecord.
     */
    @SuppressWarnings("unchecked")
    public ProvisioningOutcome validateAndApplyCapabilities(
            ConnectionRecord connection,
            ConfigurationRequestRepresentation request,
            List<String> authorizedCapabilities,
            List<String> authorizedDelegationProfiles,
            List<String> authorizedExtensionProfiles,
            String baseUri,
            boolean isCreate,
            boolean validateOnly,
            boolean trustEstablishedResponse) {

        // connection_id MUST NOT appear in a POST or PATCH body ({{config-syntax}})
        if (request.getConnectionId() != null) {
            throw FedSetupException.invalidRequest("connection_id must not appear in a POST or PATCH request body");
        }

        // Validate remove / remove_provider_delegation / remove_extensions on POST vs PATCH
        if (isCreate) {
            if (request.getRemove() != null && !request.getRemove().isEmpty()) {
                throw FedSetupException.invalidRequest("'remove' must not appear in a POST request");
            }
            if (request.getRemoveProviderDelegation() != null && !request.getRemoveProviderDelegation().isEmpty()) {
                throw FedSetupException.invalidRequest("'remove_provider_delegation' must not appear in a POST request");
            }
            if (request.getRemoveExtensions() != null && !request.getRemoveExtensions().isEmpty()) {
                throw FedSetupException.invalidRequest("'remove_extensions' must not appear in a POST request");
            }
        }

        boolean hasOidc = request.getOidc() != null;
        boolean hasSaml = request.getSaml() != null;
        boolean hasScim = request.getScim() != null;
        boolean hasIdJag = request.getIdJag() != null;
        boolean hasRemove = request.getRemove() != null && !request.getRemove().isEmpty();
        boolean hasDelegation = request.getProviderDelegation() != null && !request.getProviderDelegation().isEmpty();
        boolean hasRemoveDelegation = request.getRemoveProviderDelegation() != null && !request.getRemoveProviderDelegation().isEmpty();
        boolean hasExtensions = request.getExtensions() != null && !request.getExtensions().isEmpty();
        boolean hasRemoveExtensions = request.getRemoveExtensions() != null && !request.getRemoveExtensions().isEmpty();

        if (isCreate && !hasOidc && !hasSaml && !hasScim && !hasIdJag) {
            throw FedSetupException.invalidRequest("POST request must contain at least one capability object (oidc, saml, scim, id_jag)");
        }
        if (!isCreate && !hasOidc && !hasSaml && !hasScim && !hasIdJag
                && !hasRemove && !hasDelegation && !hasRemoveDelegation && !hasExtensions && !hasRemoveExtensions) {
            throw FedSetupException.invalidRequest("PATCH request must modify at least one capability, delegation, or extension");
        }

        // Verify requested capabilities are authorized in Direct Installation Trust
        checkCapabilityAuthorized("oidc", hasOidc, authorizedCapabilities);
        checkCapabilityAuthorized("saml", hasSaml, authorizedCapabilities);
        checkCapabilityAuthorized("scim", hasScim, authorizedCapabilities);
        checkCapabilityAuthorized("id_jag", hasIdJag, authorizedCapabilities);

        // Prepare candidate state copies so validate_only does not mutate connection
        ConnectionRecord.OidcState nextOidc = copyOidcState(connection.getOidcState());
        ConnectionRecord.SamlState nextSaml = copySamlState(connection.getSamlState());
        ConnectionRecord.ScimState nextScim = copyScimState(connection.getScimState());
        ConnectionRecord.IdJagState nextIdJag = copyIdJagState(connection.getIdJagState());
        Map<String, Map<String, Object>> nextDelegation = new LinkedHashMap<>(connection.getProviderDelegationState());
        Map<String, Map<String, Object>> nextExtensions = new LinkedHashMap<>(connection.getExtensionsState());
        Map<String, String> nextStaticSecrets = new LinkedHashMap<>(connection.getStaticSecretsHashes());

        // Process capability removals on PATCH first ({{update}})
        if (hasRemove) {
            for (String rem : request.getRemove()) {
                checkCapabilityAuthorized(rem, true, authorizedCapabilities);
                if (("oidc".equals(rem) && hasOidc)
                        || ("saml".equals(rem) && hasSaml)
                        || ("scim".equals(rem) && hasScim)
                        || ("id_jag".equals(rem) && hasIdJag)) {
                    throw FedSetupException.invalidRequest("Capability '" + rem + "' cannot appear in both 'remove' and as a request object");
                }
                switch (rem) {
                    case "oidc" -> nextOidc = null;
                    case "saml" -> nextSaml = null;
                    case "scim" -> {
                        if (!validateOnly && nextScim != null && nextScim.getKeycloakClientId() != null && realm != null) {
                            ClientModel c = realm.getClientByClientId(nextScim.getKeycloakClientId());
                            if (c != null) {
                                c.setEnabled(false);
                            }
                        }
                        nextScim = null;
                        nextExtensions.remove(FedSetupConstants.EXT_SCIM_OAUTH_CC);
                    }
                    case "id_jag" -> {
                        if (!validateOnly && nextIdJag != null && nextIdJag.getClientId() != null && realm != null) {
                            ClientModel c = realm.getClientByClientId(nextIdJag.getClientId());
                            if (c != null) {
                                c.setEnabled(false);
                            }
                        }
                        nextIdJag = null;
                    }
                    default -> throw FedSetupException.invalidRequest("Unsupported capability in 'remove': " + rem);
                }
            }
        }

        // Core SSO category cardinality rule: at most one SSO capability (oidc or saml) per Connection
        boolean willHaveOidc = hasOidc || nextOidc != null;
        boolean willHaveSaml = hasSaml || nextSaml != null;
        if (willHaveOidc && willHaveSaml) {
            throw FedSetupException.invalidRequest("Capabilities 'oidc' and 'saml' both belong to category 'sso' and are mutually exclusive on a single Connection");
        }

        // Process provider_delegation and remove_provider_delegation
        if (hasRemoveDelegation) {
            for (String uri : request.getRemoveProviderDelegation()) {
                checkDelegationAuthorized(uri, authorizedDelegationProfiles);
                if (hasDelegation && request.getProviderDelegation().containsKey(uri)) {
                    throw FedSetupException.invalidRequest("Profile '" + uri + "' cannot be in both provider_delegation and remove_provider_delegation");
                }
                nextDelegation.remove(uri);
            }
        }
        if (hasDelegation) {
            for (Map.Entry<String, Map<String, Object>> entry : request.getProviderDelegation().entrySet()) {
                String uri = entry.getKey();
                checkDelegationAuthorized(uri, authorizedDelegationProfiles);
                validateProviderDelegationInput(uri, entry.getValue(), connection.getIdpIssuer());
                nextDelegation.put(uri, new LinkedHashMap<>(entry.getValue()));
            }
        }

        // Process extensions and remove_extensions
        boolean staticSecretCarried = false;
        boolean scimStaticSecretActive = false;
        boolean scimOAuthProfileRequestedNow = false;

        if (hasRemoveExtensions) {
            for (String uri : request.getRemoveExtensions()) {
                checkExtensionAuthorized(uri, authorizedExtensionProfiles);
                if (hasExtensions && request.getExtensions().containsKey(uri)) {
                    throw FedSetupException.invalidRequest("Profile '" + uri + "' cannot be in both extensions and remove_extensions");
                }
                nextExtensions.remove(uri);
                if (FedSetupConstants.EXT_SCIM_OAUTH_CC.equals(uri) && nextScim != null) {
                    if (!validateOnly && nextScim.getKeycloakClientId() != null && realm != null) {
                        ClientModel c = realm.getClientByClientId(nextScim.getKeycloakClientId());
                        if (c != null) {
                            c.setEnabled(false);
                        }
                    }
                    nextScim.setAuthMode("SAAS_ISSUED_BEARER");
                }
                if (FedSetupConstants.EXT_STATIC_SECRET_DELIVERY.equals(uri)) {
                    nextStaticSecrets.clear();
                }
            }
        }

        String realmBaseUri = baseUri + "/realms/" + realm.getName();
        String idpAlias = connection.getKeycloakIdpAlias() != null
                ? connection.getKeycloakIdpAlias()
                : "fedsetup-" + connection.getConnectionId();

        if (hasExtensions) {
            for (Map.Entry<String, Map<String, Object>> entry : request.getExtensions().entrySet()) {
                String uri = entry.getKey();
                Map<String, Object> val = entry.getValue();
                checkExtensionAuthorized(uri, authorizedExtensionProfiles);

                if (FedSetupConstants.EXT_STATIC_SECRET_DELIVERY.equals(uri)) {
                    if (val == null || !(val.get("secrets") instanceof Map<?, ?> secretsMap) || secretsMap.isEmpty()) {
                        throw FedSetupException.invalidRequest("Static Secret Delivery profile requires a non-empty 'secrets' object");
                    }
                    for (Map.Entry<?, ?> secEntry : secretsMap.entrySet()) {
                        String secName = String.valueOf(secEntry.getKey());
                        Object secVal = secEntry.getValue();
                        if (request.getConfigValues() != null && request.getConfigValues().containsKey(secName)) {
                            throw FedSetupException.invalidRequest("config_values must not contain a key with the same name as a secret: " + secName);
                        }
                        if (secVal == null) {
                            if (isCreate) {
                                throw FedSetupException.invalidRequest("Secret '" + secName + "' cannot be null on POST");
                            }
                            nextStaticSecrets.remove(secName);
                        } else if (secVal instanceof String s && !s.isBlank()) {
                            nextStaticSecrets.put(secName, FedSetupStore.sha256Base64Url(s));
                            staticSecretCarried = true;
                            if (secName.contains("scim")) {
                                scimStaticSecretActive = true;
                            }
                        } else {
                            throw FedSetupException.invalidRequest("Secret '" + secName + "' must be a non-empty string");
                        }
                    }
                } else if (FedSetupConstants.EXT_SCIM_OAUTH_CC.equals(uri)) {
                    if (!hasScim && nextScim == null) {
                        throw FedSetupException.invalidRequest("OAuth 2.0 SCIM Client-Credentials Profile requires a core 'scim' object");
                    }
                    if (val == null || !(val.get("scim_client_jwks_uri") instanceof String jwksUri) || jwksUri.isBlank()) {
                        throw FedSetupException.invalidRequest("scim-oauth-client-credentials requires 'scim_client_jwks_uri'");
                    }
                    fetchService.validateSameOrigin(connection.getIdpIssuer(), jwksUri, "scim_client_jwks_uri");
                    fetchService.fetchAndValidateJwks(jwksUri);
                    scimOAuthProfileRequestedNow = true;

                    String scimClientId = (nextScim != null && nextScim.getKeycloakClientId() != null)
                            ? nextScim.getKeycloakClientId()
                            : "scim_client_" + connection.getConnectionId();
                    String provisioningEndpoint = realmBaseUri + "/scim/v2";
                    Map<String, Object> extResp = new LinkedHashMap<>();
                    extResp.put("token_endpoint", realmBaseUri + "/protocol/openid-connect/token");
                    extResp.put("client_id", scimClientId);
                    extResp.put("scope", "scim");
                    extResp.put("resource", provisioningEndpoint);
                    nextExtensions.put(FedSetupConstants.EXT_SCIM_OAUTH_CC, extResp);
                    if (!validateOnly) {
                        provisionScimOAuthClient(scimClientId, jwksUri);
                    }
                } else {
                    throw FedSetupException.invalidRequest("Unsupported Federation Extension Profile: " + uri);
                }
            }
        }

        boolean secretIssuedInResponse = staticSecretCarried;
        ConfigurationResponseRepresentation.OidcResponse oidcResp = null;
        ConfigurationResponseRepresentation.SamlResponse samlResp = null;
        ConfigurationResponseRepresentation.ScimResponse scimResp = null;
        ConfigurationResponseRepresentation.IdJagResponse idJagResp = null;

        // 1. OIDC capability
        if (hasOidc) {
            OidcOutcome outcome = processOidc(
                    connection,
                    request.getOidc(),
                    nextOidc,
                    authorizedDelegationProfiles,
                    realmBaseUri,
                    isCreate);
            nextOidc = outcome.state;
            oidcResp = outcome.response;
        } else if (nextOidc != null) {
            oidcResp = buildOidcResponse(nextOidc, realmBaseUri, connection.getConnectionId());
        }

        // 2. SAML capability
        if (hasSaml) {
            SamlOutcome outcome = processSaml(
                    connection,
                    request.getSaml(),
                    nextSaml,
                    realmBaseUri,
                    idpAlias);
            nextSaml = outcome.state;
            samlResp = outcome.response;
        } else if (nextSaml != null) {
            samlResp = buildSamlResponse(nextSaml, realmBaseUri, idpAlias);
        }

        // 3. SCIM capability
        if (hasScim) {
            ScimOutcome outcome = processScim(
                    connection,
                    request.getScim(),
                    nextScim,
                    nextExtensions.containsKey(FedSetupConstants.EXT_SCIM_OAUTH_CC) || scimOAuthProfileRequestedNow,
                    scimStaticSecretActive,
                    nextDelegation,
                    realmBaseUri,
                    isCreate,
                    validateOnly);
            nextScim = outcome.state;
            scimResp = outcome.response;
            if (outcome.secretIssued) {
                secretIssuedInResponse = true;
            }
        } else if (nextScim != null) {
            scimResp = buildScimResponse(nextScim, realmBaseUri, null);
        } else if (scimStaticSecretActive) {
            throw FedSetupException.invalidRequest("A secret with a scim_authorization binding requires a 'scim' capability object");
        }

        // 4. ID-JAG capability
        if (hasIdJag) {
            IdJagOutcome outcome = processIdJag(
                    connection,
                    request.getIdJag(),
                    nextIdJag,
                    nextOidc,
                    idpAlias,
                    isCreate,
                    validateOnly);
            nextIdJag = outcome.state;
            idJagResp = outcome.response;
        } else if (nextIdJag != null) {
            idJagResp = buildIdJagResponse(nextIdJag, true);
        }

        // Verify the Connection still has at least one enabled capability after applying changes ({{update}})
        if (nextOidc == null && nextSaml == null && nextScim == null && nextIdJag == null) {
            throw FedSetupException.invalidRequest("Update cannot leave the Connection with no enabled capabilities");
        }

        if (!validateOnly) {
            connection.setKeycloakIdpAlias(idpAlias);
            if (request.getIdpDomain() != null) {
                connection.setIdpDomain(request.getIdpDomain());
            }
            if (request.getIdpName() != null) {
                connection.setIdpName(request.getIdpName());
            }
            if (request.getIdpLogoUri() != null) {
                connection.setIdpLogoUri(request.getIdpLogoUri());
            }
            connection.setOidcState(nextOidc);
            connection.setSamlState(nextSaml);
            connection.setScimState(nextScim);
            connection.setIdJagState(nextIdJag);
            connection.setProviderDelegationState(nextDelegation);
            connection.setExtensionsState(nextExtensions);
            connection.setStaticSecretsHashes(nextStaticSecrets);
            if (!isCreate) {
                connection.setVersion(connection.getVersion() + 1);
            }
            connection.setUpdatedAt(Time.currentTime());
            connection.setEtag(computeConnectionEtag(connection));

            syncKeycloakIdentityProvider(connection);
        }

        ConfigurationResponseRepresentation response = new ConfigurationResponseRepresentation();
        if (!validateOnly) {
            response.setConnectionId(connection.getConnectionId());
        }
        response.setApplicationTenantId(connection.getApplicationTenantId());
        response.setIdpIssuer(connection.getIdpIssuer());
        String domain = request.getIdpDomain() != null ? request.getIdpDomain() : connection.getIdpDomain();
        if (domain != null) {
            response.setIdpDomain(domain);
        }
        if (trustEstablishedResponse && !validateOnly) {
            response.setTrustEstablished(Boolean.TRUE);
        }
        if (nextOidc != null || nextSaml != null) {
            response.setInitiateLoginUri(realmBaseUri + "/protocol/openid-connect/auth?kc_idp_hint=" + idpAlias);
        }
        response.setOidc(oidcResp);
        response.setSaml(samlResp);
        response.setScim(scimResp);
        response.setIdJag(idJagResp);
        if (!nextExtensions.isEmpty()) {
            response.setExtensions(new LinkedHashMap<>(nextExtensions));
        }
        if (!validateOnly && connection.getCreatedAt() > 0) {
            response.setCreatedAt(Instant.ofEpochSecond(connection.getCreatedAt()).toString());
            response.setUpdatedAt(Instant.ofEpochSecond(connection.getUpdatedAt()).toString());
        }

        return new ProvisioningOutcome(response, secretIssuedInResponse && !validateOnly);
    }

    public ConfigurationResponseRepresentation buildGetResponse(ConnectionRecord connection, String baseUri) {
        String realmBaseUri = baseUri + "/realms/" + realm.getName();
        String idpAlias = connection.getKeycloakIdpAlias() != null
                ? connection.getKeycloakIdpAlias()
                : "fedsetup-" + connection.getConnectionId();

        ConfigurationResponseRepresentation resp = new ConfigurationResponseRepresentation();
        resp.setConnectionId(connection.getConnectionId());
        resp.setApplicationTenantId(connection.getApplicationTenantId());
        resp.setIdpIssuer(connection.getIdpIssuer());
        if (connection.getIdpDomain() != null) {
            resp.setIdpDomain(connection.getIdpDomain());
        }
        if (connection.getConnectionName() != null) {
            resp.setConnectionName(connection.getConnectionName());
        }
        if (connection.getOidcState() != null || connection.getSamlState() != null) {
            resp.setInitiateLoginUri(realmBaseUri + "/protocol/openid-connect/auth?kc_idp_hint=" + idpAlias);
        }
        if (connection.getOidcState() != null) {
            resp.setOidc(buildOidcResponse(connection.getOidcState(), realmBaseUri, connection.getConnectionId()));
        }
        if (connection.getSamlState() != null) {
            resp.setSaml(buildSamlResponse(connection.getSamlState(), realmBaseUri, idpAlias));
        }
        if (connection.getScimState() != null) {
            resp.setScim(buildScimResponse(connection.getScimState(), realmBaseUri, null));
        }
        if (connection.getIdJagState() != null) {
            resp.setIdJag(buildIdJagResponse(connection.getIdJagState(), true));
        }
        if (connection.getExtensionsState() != null && !connection.getExtensionsState().isEmpty()) {
            resp.setExtensions(new LinkedHashMap<>(connection.getExtensionsState()));
        }
        if (connection.getCreatedAt() > 0) {
            resp.setCreatedAt(Instant.ofEpochSecond(connection.getCreatedAt()).toString());
            resp.setUpdatedAt(Instant.ofEpochSecond(connection.getUpdatedAt()).toString());
        }
        return resp;
    }

    public void deactivateConnectionResources(ConnectionRecord connection) {
        if (realm == null) {
            return;
        }
        if (connection.getKeycloakIdpAlias() != null) {
            IdentityProviderModel idp = realm.getIdentityProviderByAlias(connection.getKeycloakIdpAlias());
            if (idp != null) {
                idp.setEnabled(false);
                realm.updateIdentityProvider(idp);
            }
        }
        if (connection.getScimState() != null && connection.getScimState().getKeycloakClientId() != null) {
            ClientModel scimClient = realm.getClientByClientId(connection.getScimState().getKeycloakClientId());
            if (scimClient != null) {
                scimClient.setEnabled(false);
            }
        }
        if (connection.getIdJagState() != null && connection.getIdJagState().getClientId() != null) {
            ClientModel idJagClient = realm.getClientByClientId(connection.getIdJagState().getClientId());
            if (idJagClient != null) {
                idJagClient.setEnabled(false);
            }
        }
    }

    /**
     * Adopts an existing Keycloak IdentityProviderModel into a FedSetup ConnectionRecord ({{update}}).
     */
    public ConnectionRecord adoptExistingIdentityProvider(
            String idpAlias,
            String applicationTenantId,
            String expectedIdpIssuer,
            String trustId,
            String authenticatedClientContext) {
        IdentityProviderModel idp = realm.getIdentityProviderByAlias(idpAlias);
        if (idp == null) {
            throw FedSetupException.notFound("IdentityProvider with alias '" + idpAlias + "' not found in realm");
        }

        ConnectionRecord record = new ConnectionRecord();
        record.setConnectionId(FedSetupStore.generateSecureId("conn"));
        record.setTrustId(trustId);
        record.setAuthenticatedClientContext(authenticatedClientContext);
        record.setApplicationTenantId(applicationTenantId);
        record.setOrigin("adopted");
        record.setStatus("active");
        record.setKeycloakIdpAlias(idpAlias);
        record.setConnectionName(idp.getDisplayName() != null ? idp.getDisplayName() : idpAlias);
        long now = Time.currentTime();
        record.setCreatedAt(now);
        record.setUpdatedAt(now);

        Map<String, String> cfg = idp.getConfig() != null ? idp.getConfig() : Collections.emptyMap();
        if ("oidc".equalsIgnoreCase(idp.getProviderId()) || "keycloak-oidc".equalsIgnoreCase(idp.getProviderId())) {
            String issuer = expectedIdpIssuer != null ? expectedIdpIssuer : cfg.getOrDefault("issuer", "https://idp.example.com");
            record.setIdpIssuer(issuer);
            ConnectionRecord.OidcState oidc = new ConnectionRecord.OidcState();
            oidc.setIssuer(issuer);
            oidc.setAuthorizationEndpoint(cfg.get("authorizationUrl"));
            oidc.setTokenEndpoint(cfg.get("tokenUrl"));
            oidc.setJwksUri(cfg.get("jwksUrl"));
            oidc.setUserinfoEndpoint(cfg.get("userInfoUrl"));
            oidc.setEndSessionEndpoint(cfg.get("logoutUrl"));
            oidc.setClientId(cfg.getOrDefault("clientId", "adopted-client"));
            oidc.setClientSecret(cfg.get("clientSecret"));
            oidc.setTokenEndpointAuthMethod(cfg.getOrDefault("clientAuthMethod", "client_secret_basic"));
            record.setOidcState(oidc);
        } else if ("saml".equalsIgnoreCase(idp.getProviderId())) {
            String entityId = cfg.getOrDefault("idpEntityId", expectedIdpIssuer != null ? expectedIdpIssuer : "https://idp.example.com/saml");
            record.setIdpIssuer(expectedIdpIssuer != null ? expectedIdpIssuer : entityId);
            ConnectionRecord.SamlState saml = new ConnectionRecord.SamlState();
            saml.setIdpEntityId(entityId);
            saml.setIdpSsoUrl(cfg.get("singleSignOnServiceUrl"));
            saml.setIdpSloUrl(cfg.get("singleLogoutServiceUrl"));
            saml.setIdpCertificate(cfg.get("signingCertificate"));
            saml.setNameIdFormat(cfg.getOrDefault("nameIDPolicyFormat", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"));
            record.setSamlState(saml);
        } else {
            throw FedSetupException.invalidRequest("Unsupported IdentityProvider type for adoption: " + idp.getProviderId());
        }

        record.setEtag(computeConnectionEtag(record));
        return record;
    }

    // ---- Internal capability processors ----

    private static class OidcOutcome {
        final ConnectionRecord.OidcState state;
        final ConfigurationResponseRepresentation.OidcResponse response;

        OidcOutcome(ConnectionRecord.OidcState state, ConfigurationResponseRepresentation.OidcResponse response) {
            this.state = state;
            this.response = response;
        }
    }

    private OidcOutcome processOidc(
            ConnectionRecord connection,
            ConfigurationRequestRepresentation.OidcRequest req,
            ConnectionRecord.OidcState existing,
            List<String> authorizedDelegationProfiles,
            String realmBaseUri,
            boolean isCreate) {

        ConnectionRecord.OidcState state = existing != null ? existing : new ConnectionRecord.OidcState();

        String issuer = req.getIssuer();
        if (issuer == null || issuer.isBlank()) {
            throw FedSetupException.invalidRequest("oidc.issuer is required");
        }
        if (!connection.getIdpIssuer().equals(issuer)) {
            throw FedSetupException.invalidRequest(
                    "oidc.issuer (" + issuer + ") must equal idp_issuer (" + connection.getIdpIssuer() + ")");
        }
        state.setIssuer(issuer);

        String clientId = req.getClientId();
        if (clientId == null || clientId.isBlank()) {
            throw FedSetupException.invalidRequest("oidc.client_id is required");
        }
        state.setClientId(clientId);

        // Check if realm advertises capabilities.oidc.client_id_metadata_uri
        String advertisedAppCimdUri = realm != null ? realm.getAttribute("fedsetup.oidc.client_id_metadata_uri") : null;
        if (advertisedAppCimdUri != null && !advertisedAppCimdUri.isBlank()) {
            if (!advertisedAppCimdUri.equals(clientId)) {
                throw FedSetupException.invalidRequest(
                        "When capabilities.oidc.client_id_metadata_uri is advertised, oidc.client_id must equal " + advertisedAppCimdUri);
            }
            if (req.getClientSecurity() != null) {
                throw FedSetupException.invalidRequest(
                        "oidc.client_security must be absent when capabilities.oidc.client_id_metadata_uri is advertised");
            }
            state.setUseCimd(true);
            state.setAppClientIdMetadataUri(advertisedAppCimdUri);
        } else {
            state.setUseCimd(false);
        }

        String authMethod = req.getTokenEndpointAuthMethod();
        if (authMethod == null || authMethod.isBlank()) {
            authMethod = state.getTokenEndpointAuthMethod() != null ? state.getTokenEndpointAuthMethod() : "client_secret_basic";
        }
        if (!Set.of("client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt", "none").contains(authMethod)) {
            throw FedSetupException.invalidRequest("Unsupported oidc.token_endpoint_auth_method: " + authMethod);
        }
        state.setTokenEndpointAuthMethod(authMethod);

        // Write-only client_secret rules ({{oidc}} & {{update}})
        String providedSecret = req.getClientSecret();
        if ("private_key_jwt".equals(authMethod) || "none".equals(authMethod)) {
            if (providedSecret != null) {
                throw FedSetupException.invalidRequest("oidc.client_secret must be absent when token_endpoint_auth_method is " + authMethod);
            }
            state.setClientSecret(null);
        } else {
            if (providedSecret != null) {
                if (providedSecret.isEmpty()) {
                    throw FedSetupException.invalidRequest("oidc.client_secret must not be an empty string");
                }
                state.setClientSecret(providedSecret);
            } else if (existing == null || state.getClientSecret() == null) {
                throw FedSetupException.invalidRequest("oidc.client_secret is required on creation for " + authMethod);
            }
            // If omitted or null on PATCH, retains existing state.getClientSecret()!
        }

        if (req.getClientSecurity() != null) {
            state.setClientSecurity(new LinkedHashMap<>(req.getClientSecurity()));
        }

        if (req.getScopes() != null) {
            state.setScopes(new ArrayList<>(req.getScopes()));
        } else if (state.getScopes() == null || state.getScopes().isEmpty()) {
            state.setScopes(List.of("openid", "profile", "email"));
        }

        // Resolve endpoints: inline or OIDC discovery from issuer
        if (req.getAuthorizationEndpoint() != null && req.getTokenEndpoint() != null) {
            fetchService.validateHttpsUri(req.getAuthorizationEndpoint(), "oidc.authorization_endpoint", true);
            fetchService.validateHttpsUri(req.getTokenEndpoint(), "oidc.token_endpoint", true);
            state.setAuthorizationEndpoint(req.getAuthorizationEndpoint());
            state.setTokenEndpoint(req.getTokenEndpoint());
            if (req.getJwksUri() != null) {
                fetchService.validateHttpsUri(req.getJwksUri(), "oidc.jwks_uri", true);
                state.setJwksUri(req.getJwksUri());
            }
        } else if (state.getAuthorizationEndpoint() == null || state.getTokenEndpoint() == null) {
            String discoveryUri = issuer.endsWith("/")
                    ? issuer + ".well-known/openid-configuration"
                    : issuer + "/.well-known/openid-configuration";
            try {
                Map<String, Object> discovered = fetchService.fetchOidcProviderMetadata(discoveryUri);
                String discIssuer = requireMetadataString(discovered, "issuer");
                if (!issuer.equals(discIssuer)) {
                    throw FedSetupException.invalidRequest("Discovered OIDC issuer (" + discIssuer + ") does not match oidc.issuer (" + issuer + ")");
                }
                state.setAuthorizationEndpoint(
                        req.getAuthorizationEndpoint() != null
                                ? req.getAuthorizationEndpoint()
                                : requireMetadataString(discovered, "authorization_endpoint"));
                state.setTokenEndpoint(
                        req.getTokenEndpoint() != null
                                ? req.getTokenEndpoint()
                                : requireMetadataString(discovered, "token_endpoint"));
                if (discovered.get("jwks_uri") instanceof String jwks && !jwks.isBlank()) {
                    state.setJwksUri(jwks);
                }
                if (discovered.get("userinfo_endpoint") instanceof String ui && !ui.isBlank()) {
                    state.setUserinfoEndpoint(ui);
                }
                if (discovered.get("end_session_endpoint") instanceof String es && !es.isBlank()) {
                    state.setEndSessionEndpoint(es);
                }
            } catch (FedSetupException e) {
                throw e;
            } catch (Exception e) {
                throw FedSetupException.invalidRequest("Failed to discover OIDC metadata from issuer: " + e.getMessage());
            }
        }

        return new OidcOutcome(state, buildOidcResponse(state, realmBaseUri, connection.getConnectionId()));
    }

    private ConfigurationResponseRepresentation.OidcResponse buildOidcResponse(
            ConnectionRecord.OidcState state,
            String realmBaseUri,
            String connectionId) {
        ConfigurationResponseRepresentation.OidcResponse resp = new ConfigurationResponseRepresentation.OidcResponse();
        if (state.isUseCimd() && state.getAppClientIdMetadataUri() != null) {
            // When CIMD path is used, redirect_uris, jwks_uri, and client_security MUST be absent ({{resp-ok}})
            resp.setClientIdMetadataUri(state.getAppClientIdMetadataUri());
            return resp;
        }
        String idpAlias = "fedsetup-" + connectionId;
        String redirectUri = realmBaseUri + "/broker/" + idpAlias + "/endpoint";
        resp.setRedirectUris(List.of(redirectUri));
        resp.setPostLogoutRedirectUris(List.of(redirectUri + "/logout_response"));
        if ("private_key_jwt".equals(state.getTokenEndpointAuthMethod())) {
            resp.setJwksUri(realmBaseUri + "/" + FedSetupConstants.PROVIDER_ID + "/oidc-jwks/" + connectionId);
        }
        if (state.getClientSecurity() != null) {
            resp.setClientSecurity(state.getClientSecurity());
        }
        return resp;
    }

    private static class SamlOutcome {
        final ConnectionRecord.SamlState state;
        final ConfigurationResponseRepresentation.SamlResponse response;

        SamlOutcome(ConnectionRecord.SamlState state, ConfigurationResponseRepresentation.SamlResponse response) {
            this.state = state;
            this.response = response;
        }
    }

    private SamlOutcome processSaml(
            ConnectionRecord connection,
            ConfigurationRequestRepresentation.SamlRequest req,
            ConnectionRecord.SamlState existing,
            String realmBaseUri,
            String idpAlias) {

        ConnectionRecord.SamlState state = new ConnectionRecord.SamlState();

        if (req.getIdpEntityId() == null || req.getIdpEntityId().isBlank()) {
            throw FedSetupException.invalidRequest("saml.idp_entity_id is required");
        }
        if (req.getIdpSsoUrl() == null || req.getIdpSsoUrl().isBlank()) {
            throw FedSetupException.invalidRequest("saml.idp_sso_url is required");
        }
        fetchService.validateHttpsUri(req.getIdpSsoUrl(), "saml.idp_sso_url", true);
        if (req.getIdpCertificate() == null || req.getIdpCertificate().isBlank()) {
            throw FedSetupException.invalidRequest("saml.idp_certificate is required");
        }

        state.setIdpEntityId(req.getIdpEntityId());
        state.setIdpSsoUrl(req.getIdpSsoUrl());
        state.setIdpCertificate(req.getIdpCertificate());

        if (req.getIdpSloUrl() != null && !req.getIdpSloUrl().isBlank()) {
            fetchService.validateHttpsUri(req.getIdpSloUrl(), "saml.idp_slo_url", true);
            state.setIdpSloUrl(req.getIdpSloUrl());
        }
        if (req.getIdpMetadataUrl() != null && !req.getIdpMetadataUrl().isBlank()) {
            fetchService.validateSameOrigin(connection.getIdpIssuer(), req.getIdpMetadataUrl(), "saml.idp_metadata_url");
            state.setIdpMetadataUrl(req.getIdpMetadataUrl());
        }
        state.setNameIdFormat(
                req.getNameIdFormat() != null && !req.getNameIdFormat().isBlank()
                        ? req.getNameIdFormat()
                        : "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
        if (req.getAttributeMapping() != null) {
            state.setAttributeMapping(new LinkedHashMap<>(req.getAttributeMapping()));
        }

        return new SamlOutcome(state, buildSamlResponse(state, realmBaseUri, idpAlias));
    }

    private ConfigurationResponseRepresentation.SamlResponse buildSamlResponse(
            ConnectionRecord.SamlState state,
            String realmBaseUri,
            String idpAlias) {
        String brokerEndpoint = realmBaseUri + "/broker/" + idpAlias + "/endpoint";
        ConfigurationResponseRepresentation.SamlResponse resp = new ConfigurationResponseRepresentation.SamlResponse();
        resp.setAppAcsUrl(brokerEndpoint);
        resp.setAppEntityId(realmBaseUri);
        return resp;
    }

    private static class ScimOutcome {
        final ConnectionRecord.ScimState state;
        final ConfigurationResponseRepresentation.ScimResponse response;
        final boolean secretIssued;

        ScimOutcome(ConnectionRecord.ScimState state, ConfigurationResponseRepresentation.ScimResponse response, boolean secretIssued) {
            this.state = state;
            this.response = response;
            this.secretIssued = secretIssued;
        }
    }

    private ScimOutcome processScim(
            ConnectionRecord connection,
            ConfigurationRequestRepresentation.ScimRequest req,
            ConnectionRecord.ScimState existing,
            boolean oauthProfileActive,
            boolean staticSecretActive,
            Map<String, Map<String, Object>> activeDelegations,
            String realmBaseUri,
            boolean isCreate,
            boolean validateOnly) {

        boolean isAddedNow = (existing == null);
        ConnectionRecord.ScimState state = existing != null ? existing : new ConnectionRecord.ScimState();

        if (req.getFeatures() == null || req.getFeatures().isEmpty()) {
            throw FedSetupException.invalidRequest("scim.features is required and must be a non-empty array");
        }
        for (String feature : req.getFeatures()) {
            if ("IMPORT_USERS".equals(feature) || "IMPORT_GROUPS".equals(feature)) {
                throw FedSetupException.invalidRequest(
                        "SCIM feature '" + feature + "' requires an authorized Provider Delegation Profile that defines import");
            }
            if (!SUPPORTED_SCIM_FEATURES.contains(feature)) {
                throw FedSetupException.invalidRequest("Unsupported SCIM capability feature: " + feature);
            }
        }
        state.setFeatures(new ArrayList<>(req.getFeatures()));

        boolean rotateRequested = Boolean.TRUE.equals(req.getRotateAccessToken());
        if (isCreate && req.getRotateAccessToken() != null) {
            throw FedSetupException.invalidRequest("scim.rotate_access_token must be absent on POST");
        }
        if (oauthProfileActive && staticSecretActive) {
            throw FedSetupException.invalidRequest(
                    "Connection cannot use both OAuth 2.0 SCIM Client-Credentials Profile and Static Secret Delivery SCIM authorization");
        }

        if (oauthProfileActive) {
            if (rotateRequested) {
                throw FedSetupException.invalidRequest(
                        "scim.rotate_access_token must not be true while OAuth 2.0 SCIM Client-Credentials Profile is active");
            }
            state.setAuthMode("OAUTH2_CLIENT_CREDENTIALS");
            if (state.getKeycloakClientId() == null) {
                state.setKeycloakClientId("scim_client_" + connection.getConnectionId());
            }
            return new ScimOutcome(state, buildScimResponse(state, realmBaseUri, null), false);
        }

        if (staticSecretActive || "STATIC_SECRET".equals(state.getAuthMode())) {
            if (rotateRequested) {
                throw FedSetupException.invalidRequest(
                        "scim.rotate_access_token must not be true when Static Secret Delivery SCIM authorization is active");
            }
            state.setAuthMode("STATIC_SECRET");
            return new ScimOutcome(state, buildScimResponse(state, realmBaseUri, null), false);
        }

        // Core SAAS_ISSUED_BEARER mode
        state.setAuthMode("SAAS_ISSUED_BEARER");
        String issuedToken = null;
        boolean secretIssued = false;
        if (isAddedNow || rotateRequested) {
            if (!validateOnly) {
                issuedToken = FedSetupStore.generateSecureId("scim_tok");
                state.setAccessTokenHash(FedSetupStore.sha256Base64Url(issuedToken));
                secretIssued = true;
            }
        }

        return new ScimOutcome(state, buildScimResponse(state, realmBaseUri, issuedToken), secretIssued);
    }

    private void provisionScimOAuthClient(String clientId, String jwksUri) {
        if (realm == null) {
            return;
        }
        ClientModel client = realm.getClientByClientId(clientId);
        if (client == null) {
            client = realm.addClient(clientId);
        }
        client.setEnabled(true);
        client.setPublicClient(false);
        client.setServiceAccountsEnabled(true);
        client.setStandardFlowEnabled(false);
        client.setDirectAccessGrantsEnabled(false);
        client.setClientAuthenticatorType("client-jwt");
        client.setAttribute("use.jwks.url", "true");
        client.setAttribute("jwks.url", jwksUri);

        ClientModel realmMgmt = realm.getClientByClientId("realm-management");
        if (realmMgmt != null && session != null && session.users() != null) {
            var serviceAccountUser = session.users().getServiceAccount(client);
            if (serviceAccountUser != null) {
                for (String roleName : List.of("manage-users", "view-users", "query-users", "query-groups")) {
                    RoleModel role = realmMgmt.getRole(roleName);
                    if (role != null) {
                        serviceAccountUser.grantRole(role);
                    }
                }
            }
        }
    }

    private ConfigurationResponseRepresentation.ScimResponse buildScimResponse(
            ConnectionRecord.ScimState state,
            String realmBaseUri,
            String newlyIssuedBearerToken) {
        ConfigurationResponseRepresentation.ScimResponse resp = new ConfigurationResponseRepresentation.ScimResponse();
        resp.setProvisioningEndpoint(realmBaseUri + "/scim/v2");
        resp.setFeatures(state.getFeatures());
        if ("SAAS_ISSUED_BEARER".equals(state.getAuthMode())) {
            resp.setTokenType("Bearer");
            if (newlyIssuedBearerToken != null) {
                resp.setAccessToken(newlyIssuedBearerToken);
            }
        } else if ("STATIC_SECRET".equals(state.getAuthMode())) {
            resp.setTokenType("Bearer");
        }
        // When OAUTH2_CLIENT_CREDENTIALS is active, token_type and access_token are omitted ({{ex-scim-oauth}})
        return resp;
    }

    private static class IdJagOutcome {
        final ConnectionRecord.IdJagState state;
        final ConfigurationResponseRepresentation.IdJagResponse response;

        IdJagOutcome(ConnectionRecord.IdJagState state, ConfigurationResponseRepresentation.IdJagResponse response) {
            this.state = state;
            this.response = response;
        }
    }

    @SuppressWarnings("unchecked")
    private IdJagOutcome processIdJag(
            ConnectionRecord connection,
            ConfigurationRequestRepresentation.IdJagRequest req,
            ConnectionRecord.IdJagState existing,
            ConnectionRecord.OidcState oidcState,
            String idpAlias,
            boolean isCreate,
            boolean validateOnly) {

        ConnectionRecord.IdJagState state = existing != null ? existing : new ConnectionRecord.IdJagState();

        String clientId = req.getClientId();
        if (clientId == null || clientId.isBlank()) {
            throw FedSetupException.invalidRequest("id_jag.client_id is required");
        }
        state.setClientId(clientId);

        String requesterType = req.getRequesterType();
        if (requesterType == null || (!"app_instance".equals(requesterType) && !"workload_principal".equals(requesterType))) {
            throw FedSetupException.invalidRequest("id_jag.requester_type must be 'app_instance' or 'workload_principal'");
        }
        state.setRequesterType(requesterType);
        state.setRequesterName(req.getRequesterName());

        String cimdUri = req.getCimdUri();
        String clientSecret = req.getClientSecret();

        if (cimdUri != null) {
            if (!cimdUri.equals(clientId)) {
                throw FedSetupException.invalidRequest("When id_jag.cimd_uri is present, it must equal id_jag.client_id");
            }
            if (clientSecret != null) {
                throw FedSetupException.invalidRequest("id_jag.client_secret must be absent when id_jag.cimd_uri is present");
            }
            // Validate the CIMD document and keys before creating a Connection ({{idjag}})
            fetchService.resolveCimdJwks(cimdUri, false, true);
            state.setCimdUri(cimdUri);
            state.setClientSecretHash(null);
        } else {
            state.setCimdUri(null);
            // CLIENT_SECRET mechanism ({{idjag}})
            if (clientSecret != null) {
                if (clientSecret.isEmpty()) {
                    throw FedSetupException.invalidRequest("id_jag.client_secret must not be an empty string");
                }
                if (oidcState != null && clientSecret.equals(oidcState.getClientSecret())) {
                    throw FedSetupException.invalidRequest("id_jag.client_secret must be distinct from oidc.client_secret");
                }
                state.setClientSecretHash(FedSetupStore.sha256Base64Url(clientSecret));
            } else if (existing == null || state.getClientSecretHash() == null) {
                throw FedSetupException.invalidRequest("id_jag.client_secret is required on creation when cimd_uri is absent");
            }
        }

        boolean requestHadResourceConnections = (req.getResourceConnections() != null);
        if (requestHadResourceConnections) {
            if (req.getResourceConnections().isEmpty()) {
                throw FedSetupException.invalidRequest("id_jag.resource_connections must contain at least one entry when present");
            }
            List<ConfigurationRequestRepresentation.ResourceConnection> validatedList = new ArrayList<>();
            Map<String, String> existingIdsByIssuerAndRes = new LinkedHashMap<>();
            if (state.getResourceConnections() != null) {
                for (ConfigurationRequestRepresentation.ResourceConnection oldRc : state.getResourceConnections()) {
                    String key = oldRc.getResourceIssuer() + "|" + String.join(",", oldRc.getResources());
                    if (oldRc.getResourceConnectionId() != null) {
                        existingIdsByIssuerAndRes.put(key, oldRc.getResourceConnectionId());
                    }
                }
            }

            List<Map<String, Object>> preAuthorizedBindings = getRealmPreAuthorizedResourceBindings();

            for (ConfigurationRequestRepresentation.ResourceConnection rc : req.getResourceConnections()) {
                if (rc.getResourceIssuer() == null || rc.getResourceIssuer().isBlank()) {
                    throw FedSetupException.invalidRequest("id_jag.resource_connections[].resource_issuer is required");
                }
                fetchService.validateHttpsUri(rc.getResourceIssuer(), "resource_issuer", true);
                if (rc.getResources() == null || rc.getResources().isEmpty()) {
                    throw FedSetupException.invalidRequest("id_jag.resource_connections[].resources must be a non-empty array");
                }
                if (rc.getScopes() == null || rc.getScopes().isEmpty()) {
                    throw FedSetupException.invalidRequest("id_jag.resource_connections[].scopes must be a non-empty array");
                }
                if (rc.getConditions() != null && !rc.getConditions().isEmpty()) {
                    throw FedSetupException.invalidRequest("Undefined conditions in id_jag.resource_connections");
                }

                // Check against pre-authorized resource bindings in realm ({{idjag}})
                validateAgainstPreAuthorizedBindings(rc, preAuthorizedBindings);

                String key = rc.getResourceIssuer() + "|" + String.join(",", rc.getResources());
                String rcId = rc.getResourceConnectionId() != null
                        ? rc.getResourceConnectionId()
                        : existingIdsByIssuerAndRes.getOrDefault(key, FedSetupStore.generateSecureId("rc"));

                ConfigurationRequestRepresentation.ResourceConnection copy = new ConfigurationRequestRepresentation.ResourceConnection();
                copy.setResourceConnectionId(rcId);
                copy.setResourceIssuer(rc.getResourceIssuer());
                copy.setResources(new ArrayList<>(rc.getResources()));
                copy.setScopes(new ArrayList<>(rc.getScopes()));
                validatedList.add(copy);
            }
            state.setResourceConnections(validatedList);
        } else {
            state.setResourceConnections(null);
        }

        if (!validateOnly) {
            provisionIdJagClient(clientId, clientSecret, cimdUri, idpAlias, state.getResourceConnections());
        }

        return new IdJagOutcome(state, buildIdJagResponse(state, requestHadResourceConnections));
    }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> getRealmPreAuthorizedResourceBindings() {
        if (realm == null) {
            return Collections.emptyList();
        }
        String json = realm.getAttribute(FedSetupConstants.PREFIX_RESOURCE_BINDING + "all");
        if (json == null || json.isBlank()) {
            return Collections.emptyList();
        }
        try {
            return JsonSerialization.readValue(json, List.class);
        } catch (Exception e) {
            return Collections.emptyList();
        }
    }

    @SuppressWarnings("unchecked")
    private void validateAgainstPreAuthorizedBindings(
            ConfigurationRequestRepresentation.ResourceConnection rc,
            List<Map<String, Object>> preAuthorizedBindings) {
        if (preAuthorizedBindings == null || preAuthorizedBindings.isEmpty()) {
            return;
        }
        for (Map<String, Object> b : preAuthorizedBindings) {
            String authIssuer = (String) b.get("resource_issuer");
            List<String> authResources = (List<String>) b.get("resources");
            List<String> authScopes = (List<String>) b.get("scopes");
            if (rc.getResourceIssuer().equals(authIssuer)
                    && authResources != null && authResources.containsAll(rc.getResources())) {
                if (authScopes == null || !authScopes.containsAll(rc.getScopes())) {
                    throw FedSetupException.invalidRequest(
                            "Requested scopes in id_jag.resource_connections exceed the pre-authorized binding's scope set");
                }
                return;
            }
        }
        throw FedSetupException.invalidRequest(
                "id_jag.resource_connections entry for " + rc.getResourceIssuer() + " does not match any pre-authorized binding");
    }

    private void provisionIdJagClient(
            String clientId,
            String newClientSecret,
            String cimdUri,
            String idpAlias,
            List<ConfigurationRequestRepresentation.ResourceConnection> bindings) {
        if (realm == null) {
            return;
        }
        ClientModel client = realm.getClientByClientId(clientId);
        if (client == null) {
            client = realm.addClient(clientId);
        }
        client.setEnabled(true);
        client.setPublicClient(false);
        if (cimdUri != null) {
            client.setClientAuthenticatorType("client-jwt");
            client.setAttribute("fedsetup.cimd_uri", cimdUri);
        } else if (newClientSecret != null) {
            client.setClientAuthenticatorType("client-secret");
            client.setSecret(newClientSecret);
        }
        client.setAttribute("oauth2.jwt.authorization.grant.enabled", "true");
        client.setAttribute("oauth2.jwt.authorization.grant.idp", idpAlias);
        if (bindings != null && !bindings.isEmpty()) {
            List<String> allResources = new ArrayList<>();
            for (ConfigurationRequestRepresentation.ResourceConnection b : bindings) {
                if (b.getResources() != null) {
                    allResources.addAll(b.getResources());
                }
            }
            client.setAttribute("oauth2.jwt.authorization.grant.audience", String.join("##", allResources));
        }
    }

    private ConfigurationResponseRepresentation.IdJagResponse buildIdJagResponse(
            ConnectionRecord.IdJagState state,
            boolean includeResourceConnections) {
        ConfigurationResponseRepresentation.IdJagResponse resp = new ConfigurationResponseRepresentation.IdJagResponse();
        resp.setClientId(state.getClientId());
        if (state.getCimdUri() != null) {
            resp.setCimdUri(state.getCimdUri());
        }
        resp.setRequesterType(state.getRequesterType());
        if (includeResourceConnections && state.getResourceConnections() != null && !state.getResourceConnections().isEmpty()) {
            resp.setResourceConnections(new ArrayList<>(state.getResourceConnections()));
        }
        return resp;
    }

    private void validateProviderDelegationInput(String profileUri, Map<String, Object> input, String idpIssuer) {
        if (input == null) {
            throw FedSetupException.invalidRequest("provider_delegation value for " + profileUri + " must be an object");
        }
        if ("urn:ietf:params:fedsetup:config-delegate:ssf-stream".equals(profileUri)) {
            Object txIssuer = input.get("transmitter_issuer");
            if (!(txIssuer instanceof String tx) || !idpIssuer.equals(tx)) {
                throw FedSetupException.invalidRequest("ssf-stream transmitter_issuer must equal idp_issuer");
            }
            Object token = input.get("access_token");
            if (!(token instanceof String t) || t.isBlank()) {
                throw FedSetupException.invalidRequest("ssf-stream access_token is required");
            }
            Object events = input.get("events_requested");
            if (!(events instanceof List<?> list) || list.isEmpty()) {
                throw FedSetupException.invalidRequest("ssf-stream events_requested must be a non-empty array");
            }
        } else {
            throw FedSetupException.invalidRequest("Unsupported Provider Delegation Profile: " + profileUri);
        }
    }

    private void syncKeycloakIdentityProvider(ConnectionRecord connection) {
        if (realm == null) {
            return;
        }
        String alias = connection.getKeycloakIdpAlias();
        if (connection.getOidcState() != null || connection.getIdJagState() != null) {
            IdentityProviderModel existing = realm.getIdentityProviderByAlias(alias);
            OIDCIdentityProviderConfig oidcConfig = existing != null
                    ? new OIDCIdentityProviderConfig(existing)
                    : new OIDCIdentityProviderConfig();
            oidcConfig.setAlias(alias);
            oidcConfig.setProviderId("oidc");
            oidcConfig.setEnabled("active".equals(connection.getStatus()));
            oidcConfig.setIssuer(connection.getIdpIssuer());

            ConnectionRecord.OidcState oidc = connection.getOidcState();
            if (oidc != null) {
                oidcConfig.setAuthorizationUrl(oidc.getAuthorizationEndpoint());
                oidcConfig.setTokenUrl(oidc.getTokenEndpoint());
                if (oidc.getJwksUri() != null) {
                    oidcConfig.setJwksUrl(oidc.getJwksUri());
                    oidcConfig.setUseJwksUrl(true);
                }
                if (oidc.getUserinfoEndpoint() != null) {
                    oidcConfig.setUserInfoUrl(oidc.getUserinfoEndpoint());
                }
                if (oidc.getEndSessionEndpoint() != null) {
                    oidcConfig.setLogoutUrl(oidc.getEndSessionEndpoint());
                }
                oidcConfig.setClientId(oidc.getClientId());
                if (oidc.getClientSecret() != null) {
                    oidcConfig.setClientSecret(oidc.getClientSecret());
                }
                oidcConfig.setClientAuthMethod(oidc.getTokenEndpointAuthMethod());
            }

            if (connection.getIdJagState() != null) {
                oidcConfig.getConfig().put("jwtAuthorizationGrantEnabled", "true");
                oidcConfig.setUseJwksUrl(true);
            }

            if (existing == null) {
                realm.addIdentityProvider(oidcConfig);
            } else {
                realm.updateIdentityProvider(oidcConfig);
            }
        } else if (connection.getSamlState() != null) {
            IdentityProviderModel existing = realm.getIdentityProviderByAlias(alias);
            SAMLIdentityProviderConfig samlConfig = existing != null
                    ? new SAMLIdentityProviderConfig(existing)
                    : new SAMLIdentityProviderConfig();
            samlConfig.setAlias(alias);
            samlConfig.setProviderId("saml");
            samlConfig.setEnabled("active".equals(connection.getStatus()));

            ConnectionRecord.SamlState saml = connection.getSamlState();
            samlConfig.setIdpEntityId(saml.getIdpEntityId());
            samlConfig.setSingleSignOnServiceUrl(saml.getIdpSsoUrl());
            if (saml.getIdpSloUrl() != null) {
                samlConfig.setSingleLogoutServiceUrl(saml.getIdpSloUrl());
            }
            if (saml.getIdpCertificate() != null) {
                samlConfig.setSigningCertificate(saml.getIdpCertificate());
                samlConfig.setValidateSignature(true);
            }
            samlConfig.setNameIDPolicyFormat(saml.getNameIdFormat());
            samlConfig.setWantAssertionsSigned(true);

            if (existing == null) {
                realm.addIdentityProvider(samlConfig);
            } else {
                realm.updateIdentityProvider(samlConfig);
            }
        }
    }

    public static String computeConnectionEtag(ConnectionRecord c) {
        return "\"conn-" + c.getConnectionId() + "-v" + c.getVersion() + "\"";
    }

    private static void checkCapabilityAuthorized(String cap, boolean requested, List<String> authorizedCapabilities) {
        if (!requested) {
            return;
        }
        if (authorizedCapabilities == null || !authorizedCapabilities.contains(cap)) {
            throw FedSetupException.invalidRequest(
                    "Capability '" + cap + "' is not in the authenticated client's persisted authorized_capabilities");
        }
    }

    private static void checkDelegationAuthorized(String uri, List<String> authorizedDelegationProfiles) {
        if (authorizedDelegationProfiles == null || !authorizedDelegationProfiles.contains(uri)) {
            throw FedSetupException.invalidRequest(
                    "Provider Delegation Profile '" + uri + "' is not authorized for this trust binding");
        }
    }

    private static void checkExtensionAuthorized(String uri, List<String> authorizedExtensionProfiles) {
        if (authorizedExtensionProfiles == null || !authorizedExtensionProfiles.contains(uri)) {
            throw FedSetupException.invalidRequest(
                    "Federation Extension Profile '" + uri + "' is not authorized for this trust binding");
        }
    }

    private static String requireMetadataString(Map<String, Object> map, String key) {
        Object v = map.get(key);
        if (!(v instanceof String s) || s.isBlank()) {
            throw FedSetupException.invalidRequest("Missing or invalid OIDC metadata field: " + key);
        }
        return s;
    }

    private static ConnectionRecord.OidcState copyOidcState(ConnectionRecord.OidcState src) {
        if (src == null) {
            return null;
        }
        ConnectionRecord.OidcState dst = new ConnectionRecord.OidcState();
        dst.setIssuer(src.getIssuer());
        dst.setClientId(src.getClientId());
        dst.setClientSecret(src.getClientSecret());
        dst.setTokenEndpointAuthMethod(src.getTokenEndpointAuthMethod());
        dst.setClientSecurity(src.getClientSecurity() != null ? new LinkedHashMap<>(src.getClientSecurity()) : null);
        dst.setAuthorizationEndpoint(src.getAuthorizationEndpoint());
        dst.setTokenEndpoint(src.getTokenEndpoint());
        dst.setJwksUri(src.getJwksUri());
        dst.setUserinfoEndpoint(src.getUserinfoEndpoint());
        dst.setEndSessionEndpoint(src.getEndSessionEndpoint());
        dst.setScopes(src.getScopes() != null ? new ArrayList<>(src.getScopes()) : null);
        dst.setUseCimd(src.isUseCimd());
        dst.setAppClientIdMetadataUri(src.getAppClientIdMetadataUri());
        return dst;
    }

    private static ConnectionRecord.SamlState copySamlState(ConnectionRecord.SamlState src) {
        if (src == null) {
            return null;
        }
        ConnectionRecord.SamlState dst = new ConnectionRecord.SamlState();
        dst.setIdpEntityId(src.getIdpEntityId());
        dst.setIdpSsoUrl(src.getIdpSsoUrl());
        dst.setIdpSloUrl(src.getIdpSloUrl());
        dst.setIdpCertificate(src.getIdpCertificate());
        dst.setNameIdFormat(src.getNameIdFormat());
        dst.setAttributeMapping(src.getAttributeMapping() != null ? new LinkedHashMap<>(src.getAttributeMapping()) : null);
        dst.setIdpMetadataUrl(src.getIdpMetadataUrl());
        return dst;
    }

    private static ConnectionRecord.ScimState copyScimState(ConnectionRecord.ScimState src) {
        if (src == null) {
            return null;
        }
        ConnectionRecord.ScimState dst = new ConnectionRecord.ScimState();
        dst.setFeatures(src.getFeatures() != null ? new ArrayList<>(src.getFeatures()) : new ArrayList<>());
        dst.setAuthMode(src.getAuthMode());
        dst.setAccessTokenHash(src.getAccessTokenHash());
        dst.setKeycloakClientId(src.getKeycloakClientId());
        dst.setScimClientJwksUri(src.getScimClientJwksUri());
        return dst;
    }

    private static ConnectionRecord.IdJagState copyIdJagState(ConnectionRecord.IdJagState src) {
        if (src == null) {
            return null;
        }
        ConnectionRecord.IdJagState dst = new ConnectionRecord.IdJagState();
        dst.setClientId(src.getClientId());
        dst.setCimdUri(src.getCimdUri());
        dst.setClientSecretHash(src.getClientSecretHash());
        dst.setRequesterType(src.getRequesterType());
        dst.setRequesterName(src.getRequesterName());
        if (src.getResourceConnections() != null) {
            List<ConfigurationRequestRepresentation.ResourceConnection> list = new ArrayList<>();
            for (ConfigurationRequestRepresentation.ResourceConnection rc : src.getResourceConnections()) {
                ConfigurationRequestRepresentation.ResourceConnection copy = new ConfigurationRequestRepresentation.ResourceConnection();
                copy.setResourceConnectionId(rc.getResourceConnectionId());
                copy.setResourceIssuer(rc.getResourceIssuer());
                copy.setResources(rc.getResources() != null ? new ArrayList<>(rc.getResources()) : null);
                copy.setScopes(rc.getScopes() != null ? new ArrayList<>(rc.getScopes()) : null);
                list.add(copy);
            }
            dst.setResourceConnections(list);
        }
        return dst;
    }
}
