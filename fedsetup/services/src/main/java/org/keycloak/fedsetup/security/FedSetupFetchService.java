package org.keycloak.fedsetup.security;

import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.fedsetup.FedSetupConstants;
import org.keycloak.fedsetup.FedSetupException;
import org.keycloak.fedsetup.representations.CimdDocumentRepresentation;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.util.JsonSerialization;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;

/**
 * Outbound endpoint validation (SSRF protection, HTTPS enforcement, same-origin checks)
 * and metadata/JWKS/CIMD fetching per FedSetup Security Considerations.
 */
public class FedSetupFetchService {

    private static final Map<String, String> MOCK_DOCUMENTS = new ConcurrentHashMap<>();
    private static final Map<String, String> LAST_NOTIFICATION_PAYLOADS = new ConcurrentHashMap<>();
    private static final Map<String, CimdDocumentRepresentation> CIMD_CACHE = new ConcurrentHashMap<>();
    private static final Map<String, JSONWebKeySet> JWKS_CACHE = new ConcurrentHashMap<>();

    private final KeycloakSession session;
    private final RealmModel realm;

    public FedSetupFetchService(KeycloakSession session, RealmModel realm) {
        this.session = session;
        this.realm = realm;
    }

    public static void registerMockDocument(String uri, String content) {
        MOCK_DOCUMENTS.put(uri, content);
    }

    public static void clearMockDocuments() {
        MOCK_DOCUMENTS.clear();
        LAST_NOTIFICATION_PAYLOADS.clear();
        CIMD_CACHE.clear();
        JWKS_CACHE.clear();
    }

    public static String getLastNotificationPayload(String uri) {
        return LAST_NOTIFICATION_PAYLOADS.get(uri);
    }

    public void purgeSigningKeyCache(String cimdOrJwksUri) {
        if (cimdOrJwksUri == null) {
            CIMD_CACHE.clear();
            JWKS_CACHE.clear();
            return;
        }
        CimdDocumentRepresentation removed = CIMD_CACHE.remove(cimdOrJwksUri);
        JWKS_CACHE.remove(cimdOrJwksUri);
        if (removed != null && removed.getJwksUri() != null) {
            JWKS_CACHE.remove(removed.getJwksUri());
        }
    }

    public void purgeCachedKeysForUri(String cimdOrJwksUri) {
        purgeSigningKeyCache(cimdOrJwksUri);
    }

    public boolean isAllowInsecureUrls() {
        return realm != null && Boolean.parseBoolean(realm.getAttribute(FedSetupConstants.ATTR_ALLOW_INSECURE_URLS));
    }

    public URI validateHttpsUri(String uriStr, String fieldName, boolean allowQuery) {
        return validateHttpsUri(uriStr, fieldName, allowQuery, false);
    }

    public URI validateHttpsUri(String uriStr, String fieldName, boolean allowQuery, boolean allowFragment) {
        if (uriStr == null || uriStr.isBlank()) {
            throw FedSetupException.invalidRequest(fieldName + " is required");
        }
        URI uri;
        try {
            uri = new URI(uriStr);
        } catch (URISyntaxException e) {
            throw FedSetupException.invalidRequest(fieldName + " is not a valid URI");
        }
        if (!uri.isAbsolute() || uri.getScheme() == null) {
            throw FedSetupException.invalidRequest(fieldName + " must be an absolute URI");
        }
        if (uri.getRawUserInfo() != null) {
            throw FedSetupException.invalidRequest(fieldName + " must not contain userinfo");
        }
        if (!allowFragment && uri.getRawFragment() != null) {
            throw FedSetupException.invalidRequest(fieldName + " must not contain a fragment");
        }
        if (!allowQuery && uri.getRawQuery() != null) {
            throw FedSetupException.invalidRequest(fieldName + " must not contain a query component");
        }
        String scheme = uri.getScheme();
        boolean allowInsecure = isAllowInsecureUrls();
        if (!"https".equalsIgnoreCase(scheme) && !(allowInsecure && "http".equalsIgnoreCase(scheme))) {
            throw FedSetupException.invalidRequest(fieldName + " must use https scheme");
        }
        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            throw FedSetupException.invalidRequest(fieldName + " must include a host");
        }
        if (!allowInsecure && !MOCK_DOCUMENTS.containsKey(uriStr)) {
            validatePublicHost(host, fieldName);
        }
        return uri;
    }

    public void validateSameOrigin(String referenceUriStr, String targetUriStr, String fieldName) {
        URI ref = validateHttpsUri(referenceUriStr, "idp_issuer", false, false);
        URI target = validateHttpsUri(targetUriStr, fieldName, true, false);
        if (!ref.getScheme().equalsIgnoreCase(target.getScheme())
                || !ref.getHost().equalsIgnoreCase(target.getHost())
                || effectivePort(ref) != effectivePort(target)) {
            throw FedSetupException.invalidRequest(fieldName + " must share scheme, host, and effective port with idp_issuer");
        }
    }

    public static int effectivePort(URI uri) {
        int port = uri.getPort();
        if (port != -1) {
            return port;
        }
        return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
    }

    private void validatePublicHost(String host, String fieldName) {
        InetAddress[] addresses;
        try {
            addresses = InetAddress.getAllByName(host);
        } catch (UnknownHostException e) {
            return;
        }
        for (InetAddress address : addresses) {
            if (isPrivateOrLoopback(address)) {
                throw FedSetupException.invalidRequest(fieldName + " resolves to a loopback, link-local, or private-network address");
            }
        }
    }

    private static boolean isPrivateOrLoopback(InetAddress address) {
        if (address.isLoopbackAddress()
                || address.isAnyLocalAddress()
                || address.isLinkLocalAddress()
                || address.isSiteLocalAddress()
                || address.isMulticastAddress()) {
            return true;
        }
        if (address instanceof Inet6Address) {
            byte[] bytes = address.getAddress();
            return ((byte) (bytes[0] & 0b11111110)) == (byte) 0xFC;
        }
        return false;
    }

    public CimdDocumentRepresentation fetchCimdDocument(String cimdUri, boolean forceRefresh, boolean asCredentialValidationFailure) {
        try {
            URI parsed = validateHttpsUri(cimdUri, "cimd_uri", false, false);
            if (parsed.getPath() == null || parsed.getPath().isEmpty() || "/".equals(parsed.getPath())) {
                throw FedSetupException.invalidRequest("CIMD URI must contain a non-root path component");
            }
            if (!forceRefresh && CIMD_CACHE.containsKey(cimdUri)) {
                return CIMD_CACHE.get(cimdUri);
            }
            String body = fetchStringNoCrossHostRedirect(cimdUri);
            CimdDocumentRepresentation doc = JsonSerialization.readValue(body, CimdDocumentRepresentation.class);
            if (doc.getClientId() == null || !cimdUri.equals(doc.getClientId())) {
                throw new IllegalArgumentException("CIMD client_id does not exactly match CIMD URI");
            }
            CIMD_CACHE.put(cimdUri, doc);
            return doc;
        } catch (FedSetupException e) {
            if (asCredentialValidationFailure) {
                throw FedSetupException.invalidCredential(e.getErrorDescription());
            }
            throw e;
        } catch (Exception e) {
            if (asCredentialValidationFailure) {
                throw FedSetupException.invalidCredential("Failed to resolve or validate CIMD document: " + e.getMessage());
            }
            throw FedSetupException.invalidRequest("Failed to resolve or validate CIMD document: " + e.getMessage());
        }
    }

    public JSONWebKeySet resolveCimdJwks(String cimdUri, boolean forceRefresh, boolean asCredentialValidationFailure) {
        CimdDocumentRepresentation doc = fetchCimdDocument(cimdUri, forceRefresh, asCredentialValidationFailure);
        if (doc.getJwks() != null && doc.getJwks().getKeys() != null && doc.getJwks().getKeys().length > 0) {
            validatePublicJwks(doc.getJwks(), asCredentialValidationFailure);
            return doc.getJwks();
        }
        if (doc.getJwksUri() != null && !doc.getJwksUri().isBlank()) {
            return fetchJwks(doc.getJwksUri(), forceRefresh, asCredentialValidationFailure);
        }
        if (asCredentialValidationFailure) {
            throw FedSetupException.invalidCredential("CIMD document contains neither jwks nor jwks_uri");
        }
        throw FedSetupException.invalidRequest("CIMD document contains neither jwks nor jwks_uri");
    }

    public JSONWebKeySet fetchJwks(String jwksUri, boolean forceRefresh, boolean asCredentialValidationFailure) {
        try {
            validateHttpsUri(jwksUri, "jwks_uri", false, false);
            if (!forceRefresh && JWKS_CACHE.containsKey(jwksUri)) {
                return JWKS_CACHE.get(jwksUri);
            }
            String body = fetchStringNoCrossHostRedirect(jwksUri);
            Map<?, ?> rawMap = JsonSerialization.readValue(body, Map.class);
            validateRawJwksHasNoPrivateMaterial(rawMap);
            JSONWebKeySet jwks = JsonSerialization.readValue(body, JSONWebKeySet.class);
            validatePublicJwks(jwks, asCredentialValidationFailure);
            JWKS_CACHE.put(jwksUri, jwks);
            return jwks;
        } catch (FedSetupException e) {
            if (asCredentialValidationFailure) {
                throw FedSetupException.invalidCredential(e.getErrorDescription());
            }
            throw e;
        } catch (Exception e) {
            if (asCredentialValidationFailure) {
                throw FedSetupException.invalidCredential("Failed to fetch or validate JWK Set: " + e.getMessage());
            }
            throw FedSetupException.invalidRequest("Failed to fetch or validate JWK Set: " + e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    public static void validateRawJwksHasNoPrivateMaterial(Map<?, ?> rawJwks) {
        Object keysObj = rawJwks.get("keys");
        if (!(keysObj instanceof Iterable<?> keys)) {
            throw new IllegalArgumentException("JWK Set is missing 'keys' array");
        }
        Set<String> kids = new HashSet<>();
        int count = 0;
        for (Object item : keys) {
            if (!(item instanceof Map<?, ?> keyMap)) {
                continue;
            }
            count++;
            if (keyMap.containsKey("d") || keyMap.containsKey("p") || keyMap.containsKey("q")
                    || keyMap.containsKey("dp") || keyMap.containsKey("dq") || keyMap.containsKey("qi")
                    || keyMap.containsKey("k")) {
                throw new IllegalArgumentException("JWK Set must not contain private or symmetric key material");
            }
            Object kid = keyMap.get("kid");
            if (kid instanceof String kidStr && !kidStr.isBlank()) {
                if (!kids.add(kidStr)) {
                    throw new IllegalArgumentException("JWK Set reuses kid '" + kidStr + "'");
                }
            }
        }
        if (count == 0) {
            throw new IllegalArgumentException("JWK Set contains no keys");
        }
    }

    public static void validatePublicJwks(JSONWebKeySet jwks, boolean asCredentialValidationFailure) {
        if (jwks == null || jwks.getKeys() == null || jwks.getKeys().length == 0) {
            throw asCredentialValidationFailure
                    ? FedSetupException.invalidCredential("JWK Set contains no keys")
                    : FedSetupException.invalidRequest("JWK Set contains no keys");
        }
        Set<String> kids = new HashSet<>();
        for (JWK jwk : jwks.getKeys()) {
            if (jwk.getOtherClaims() != null && (jwk.getOtherClaims().containsKey("d")
                    || jwk.getOtherClaims().containsKey("p")
                    || jwk.getOtherClaims().containsKey("q")
                    || jwk.getOtherClaims().containsKey("k"))) {
                throw asCredentialValidationFailure
                        ? FedSetupException.invalidCredential("JWK Set contains private key material")
                        : FedSetupException.invalidRequest("JWK Set contains private key material");
            }
            if (jwk.getKeyId() != null && !jwk.getKeyId().isBlank()) {
                if (!kids.add(jwk.getKeyId())) {
                    throw asCredentialValidationFailure
                            ? FedSetupException.invalidCredential("Duplicate kid in JWK Set")
                            : FedSetupException.invalidRequest("Duplicate kid in JWK Set");
                }
            }
        }
    }

    public CimdDocumentRepresentation fetchAndValidateCimd(String cimdUri, boolean asCredentialValidationFailure) {
        return fetchCimdDocument(cimdUri, false, asCredentialValidationFailure);
    }

    public JSONWebKeySet fetchAndValidateJwks(String jwksUri) {
        return fetchJwks(jwksUri, false, false);
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> fetchOidcProviderMetadata(String metadataUri) {
        validateHttpsUri(metadataUri, "metadata_uri", true, false);
        try {
            String body = fetchStringNoCrossHostRedirect(metadataUri);
            return JsonSerialization.readValue(body, Map.class);
        } catch (Exception e) {
            throw FedSetupException.invalidRequest("Failed to fetch or parse OIDC provider metadata: " + e.getMessage());
        }
    }

    public void postApprovalNotification(String endpointUri, String signedJwt) {
        postApprovalNotificationJwt(endpointUri, signedJwt);
    }

    public void postApprovalNotificationJwt(String endpointUri, String signedJwt) {
        validateHttpsUri(endpointUri, "approval_notification_endpoint", true, false);
        if (MOCK_DOCUMENTS.containsKey(endpointUri) || session == null) {
            LAST_NOTIFICATION_PAYLOADS.put(endpointUri, signedJwt);
            return;
        }
        HttpClientProvider httpClientProvider = session.getProvider(HttpClientProvider.class);
        if (httpClientProvider == null) {
            LAST_NOTIFICATION_PAYLOADS.put(endpointUri, signedJwt);
            return;
        }
        try {
            CloseableHttpClient client = httpClientProvider.getHttpClient();
            HttpPost post = new HttpPost(endpointUri);
            post.setHeader("Content-Type", "application/jwt");
            post.setEntity(new StringEntity(signedJwt, ContentType.create("application/jwt", "UTF-8")));
            try (CloseableHttpResponse ignored = client.execute(post)) {
                LAST_NOTIFICATION_PAYLOADS.put(endpointUri, signedJwt);
            }
        } catch (Exception ignored) {
            // Notification delivery failure is non-fatal per draft-tamm-express-configuration-deferred-trust
            LAST_NOTIFICATION_PAYLOADS.put(endpointUri, signedJwt);
        }
    }

    public String fetchStringNoCrossHostRedirect(String uriStr) throws IOException {
        if (MOCK_DOCUMENTS.containsKey(uriStr)) {
            return MOCK_DOCUMENTS.get(uriStr);
        }
        if (session == null) {
            throw new IOException("No mock document registered for " + uriStr);
        }
        HttpClientProvider httpClientProvider = session.getProvider(HttpClientProvider.class);
        if (httpClientProvider == null) {
            throw new IOException("HttpClientProvider not available for " + uriStr);
        }
        URI original = URI.create(uriStr);
        CloseableHttpClient client = httpClientProvider.getHttpClient();
        HttpClientContext context = HttpClientContext.create();
        HttpGet request = new HttpGet(uriStr);
        try (CloseableHttpResponse response = client.execute(request, context)) {
            if (context.getRedirectLocations() != null && !context.getRedirectLocations().isEmpty()) {
                for (URI redirectUri : context.getRedirectLocations()) {
                    if (!original.getScheme().equalsIgnoreCase(redirectUri.getScheme())
                            || !original.getHost().equalsIgnoreCase(redirectUri.getHost())
                            || effectivePort(original) != effectivePort(redirectUri)) {
                        throw new IOException("Cross-origin redirect is forbidden for " + uriStr);
                    }
                    if (!isAllowInsecureUrls()) {
                        validatePublicHost(redirectUri.getHost(), "redirect_target");
                    }
                }
            }
            int status = response.getStatusLine().getStatusCode();
            if (status < 200 || status >= 300) {
                throw new IOException("HTTP " + status + " fetching " + uriStr);
            }
            return EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
        }
    }
}
