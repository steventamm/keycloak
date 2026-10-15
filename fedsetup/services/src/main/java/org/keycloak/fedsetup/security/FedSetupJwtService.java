package org.keycloak.fedsetup.security;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.keycloak.common.util.Time;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.fedsetup.FedSetupConstants;
import org.keycloak.fedsetup.FedSetupException;
import org.keycloak.fedsetup.model.PendingTrustAuthorizationRecord;
import org.keycloak.fedsetup.storage.FedSetupStore;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.util.JsonSerialization;

/**
 * Validates Trust Establishment Authorization JWTs and Signed Trust Pre-Authorization JWTs,
 * and issues Signed Trust Pre-Authorization JWTs and Deferred Approval Notification JWTs.
 */
public class FedSetupJwtService {

    private static final Set<String> PERMITTED_ASYMMETRIC_ALGS = Set.of(
            "RS256", "RS384", "RS512",
            "PS256", "PS384", "PS512",
            "ES256", "ES384", "ES512",
            "EdDSA"
    );
    private static final long MAX_TOKEN_LIFETIME_SECONDS = 300L; // 5 minutes
    private static final long CLOCK_SKEW_SECONDS = 30L;

    private final KeycloakSession session;
    private final RealmModel realm;
    private final FedSetupFetchService fetchService;

    public FedSetupJwtService(KeycloakSession session, RealmModel realm, FedSetupFetchService fetchService) {
        this.session = session;
        this.realm = realm;
        this.fetchService = fetchService;
    }

    public static class ValidatedTrustJwt {
        private final JWSInput jwsInput;
        private final Map<String, Object> claims;
        private final String iss;
        private final String sub;
        private final String aud;
        private final String idpIssuer;
        private final String applicationTenantId;
        private final boolean applicationTenantIdExplicit;
        private final String htm;
        private final String htu;
        private final String requestHash;
        private final String jti;
        private final long iat;
        private final long exp;
        private final List<String> authorizedCapabilities;
        private final boolean authorizedCapabilitiesPresent;
        private final List<String> providerDelegationProfiles;
        private final boolean providerDelegationProfilesPresent;
        private final List<String> federationExtensionProfiles;
        private final boolean federationExtensionProfilesPresent;
        private final String confirmationCode;
        private final String redirectUri;
        private final String trustPreAuthorization;
        private final String pendingId;
        private final String approvalNotificationEndpoint;

        @SuppressWarnings("unchecked")
        public ValidatedTrustJwt(
                JWSInput jwsInput,
                Map<String, Object> claims,
                String iss,
                String sub,
                String aud,
                String idpIssuer,
                String applicationTenantId,
                boolean applicationTenantIdExplicit,
                String htm,
                String htu,
                String requestHash,
                String jti,
                long iat,
                long exp,
                List<String> authorizedCapabilities,
                boolean authorizedCapabilitiesPresent,
                List<String> providerDelegationProfiles,
                boolean providerDelegationProfilesPresent,
                List<String> federationExtensionProfiles,
                boolean federationExtensionProfilesPresent,
                String confirmationCode,
                String redirectUri,
                String trustPreAuthorization,
                String pendingId,
                String approvalNotificationEndpoint) {
            this.jwsInput = jwsInput;
            this.claims = claims;
            this.iss = iss;
            this.sub = sub;
            this.aud = aud;
            this.idpIssuer = idpIssuer;
            this.applicationTenantId = applicationTenantId;
            this.applicationTenantIdExplicit = applicationTenantIdExplicit;
            this.htm = htm;
            this.htu = htu;
            this.requestHash = requestHash;
            this.jti = jti;
            this.iat = iat;
            this.exp = exp;
            this.authorizedCapabilities = authorizedCapabilities;
            this.authorizedCapabilitiesPresent = authorizedCapabilitiesPresent;
            this.providerDelegationProfiles = providerDelegationProfiles;
            this.providerDelegationProfilesPresent = providerDelegationProfilesPresent;
            this.federationExtensionProfiles = federationExtensionProfiles;
            this.federationExtensionProfilesPresent = federationExtensionProfilesPresent;
            this.confirmationCode = confirmationCode;
            this.redirectUri = redirectUri;
            this.trustPreAuthorization = trustPreAuthorization;
            this.pendingId = pendingId;
            this.approvalNotificationEndpoint = approvalNotificationEndpoint;
        }

        public JWSInput getJwsInput() {
            return jwsInput;
        }

        public Map<String, Object> getClaims() {
            return claims;
        }

        public String getIss() {
            return iss;
        }

        public String getSub() {
            return sub;
        }

        public String getAud() {
            return aud;
        }

        public String getIdpIssuer() {
            return idpIssuer;
        }

        public String getApplicationTenantId() {
            return applicationTenantId;
        }

        public boolean isApplicationTenantIdExplicit() {
            return applicationTenantIdExplicit;
        }

        public String getHtm() {
            return htm;
        }

        public String getHtu() {
            return htu;
        }

        public String getRequestHash() {
            return requestHash;
        }

        public String getJti() {
            return jti;
        }

        public long getIat() {
            return iat;
        }

        public long getExp() {
            return exp;
        }

        public List<String> getAuthorizedCapabilities() {
            return authorizedCapabilities;
        }

        public boolean isAuthorizedCapabilitiesPresent() {
            return authorizedCapabilitiesPresent;
        }

        public List<String> getProviderDelegationProfiles() {
            return providerDelegationProfiles;
        }

        public boolean isProviderDelegationProfilesPresent() {
            return providerDelegationProfilesPresent;
        }

        public List<String> getFederationExtensionProfiles() {
            return federationExtensionProfiles;
        }

        public boolean isFederationExtensionProfilesPresent() {
            return federationExtensionProfilesPresent;
        }

        public String getConfirmationCode() {
            return confirmationCode;
        }

        public String getRedirectUri() {
            return redirectUri;
        }

        public String getTrustPreAuthorization() {
            return trustPreAuthorization;
        }

        public String getPendingId() {
            return pendingId;
        }

        public String getApprovalNotificationEndpoint() {
            return approvalNotificationEndpoint;
        }
    }

    public static String extractBearerToken(String authorizationHeader) {
        if (authorizationHeader == null || authorizationHeader.isBlank()) {
            throw FedSetupException.invalidCredential("Missing Authorization header");
        }
        String trimmed = authorizationHeader.trim();
        if (!trimmed.regionMatches(true, 0, "Bearer ", 0, 7)) {
            throw FedSetupException.invalidCredential("Authorization header must use Bearer scheme");
        }
        String token = trimmed.substring(7).trim();
        if (token.isEmpty()) {
            throw FedSetupException.invalidCredential("Empty Bearer token");
        }
        return token;
    }

    @SuppressWarnings("unchecked")
    public ValidatedTrustJwt parseAndValidateClaims(
            String rawJwt,
            String expectedHttpMethod,
            String expectedEndpointUri,
            byte[] rawBodyBytes,
            boolean singleTenantMode,
            String defaultSingleTenantId) {
        JWSInput jws;
        Map<String, Object> claims;
        try {
            jws = new JWSInput(rawJwt);
            claims = JsonSerialization.readValue(jws.getContent(), Map.class);
        } catch (Exception e) {
            throw FedSetupException.invalidCredential("Malformed Trust Establishment Authorization JWT");
        }

        JWSHeader header = jws.getHeader();
        if (header == null || header.getAlgorithm() == null) {
            throw FedSetupException.invalidCredential("Missing JWS algorithm header");
        }
        String alg = header.getAlgorithm().name();
        if (!PERMITTED_ASYMMETRIC_ALGS.contains(alg)) {
            throw FedSetupException.invalidCredential("Unsupported or forbidden JWS algorithm: " + alg);
        }

        String iss = requireStringClaim(claims, "iss");
        String sub = requireStringClaim(claims, "sub");
        if (!iss.equals(sub)) {
            throw FedSetupException.invalidCredential("JWT 'sub' must equal 'iss'");
        }

        String aud = extractSingleAudience(claims.get("aud"));
        String htm = requireStringClaim(claims, "htm");
        String htu = requireStringClaim(claims, "htu");
        if (!expectedHttpMethod.equals(htm)) {
            throw FedSetupException.invalidCredential("JWT 'htm' does not match HTTP method");
        }
        if (!expectedEndpointUri.equals(htu)) {
            throw FedSetupException.invalidCredential("JWT 'htu' does not match request URI");
        }
        if (!expectedEndpointUri.equals(aud)) {
            throw FedSetupException.invalidCredential("JWT 'aud' does not match request endpoint URI");
        }

        String requestHash = requireStringClaim(claims, "request_hash");
        String computedHash = FedSetupStore.sha256Base64Url(rawBodyBytes);
        if (!computedHash.equals(requestHash)) {
            throw FedSetupException.invalidCredential("JWT 'request_hash' does not match request body");
        }

        long iat = requireNumericDateClaim(claims, "iat");
        long exp = requireNumericDateClaim(claims, "exp");
        long now = Time.currentTime();
        if (exp <= iat || (exp - iat) > MAX_TOKEN_LIFETIME_SECONDS) {
            throw FedSetupException.invalidCredential("JWT 'exp' must be after 'iat' and no more than 300 seconds after 'iat'");
        }
        if (exp <= now - CLOCK_SKEW_SECONDS) {
            throw FedSetupException.invalidCredential("JWT has expired");
        }
        if (iat > now + CLOCK_SKEW_SECONDS) {
            throw FedSetupException.invalidCredential("JWT 'iat' is in the future");
        }

        String jti = requireStringClaim(claims, "jti");
        String idpIssuer = requireStringClaim(claims, "idp_issuer");

        String appTenantId = optionalStringClaim(claims, "application_tenant_id");
        boolean explicitTenant = appTenantId != null;
        if (appTenantId == null) {
            if (singleTenantMode) {
                appTenantId = defaultSingleTenantId;
            } else {
                throw FedSetupException.invalidCredential("JWT 'application_tenant_id' claim is required");
            }
        }

        boolean capsPresent = claims.containsKey("authorized_capabilities");
        List<String> caps = extractStringListClaim(claims, "authorized_capabilities");
        boolean delegPresent = claims.containsKey("provider_delegation_profiles");
        List<String> deleg = extractStringListClaim(claims, "provider_delegation_profiles");
        boolean extPresent = claims.containsKey("federation_extension_profiles");
        List<String> ext = extractStringListClaim(claims, "federation_extension_profiles");

        String confirmationCode = optionalStringClaim(claims, "confirmation_code");
        String redirectUri = optionalStringClaim(claims, "redirect_uri");
        String trustPreAuth = optionalStringClaim(claims, "trust_pre_authorization");
        String pendingId = optionalStringClaim(claims, "pending_id");
        String approvalNotificationEndpoint = optionalStringClaim(claims, "approval_notification_endpoint");

        // Enforce claim mutual exclusion per draft-tamm-express-configuration-deferred-trust {{jwt-claims}}
        if (trustPreAuth != null && pendingId != null) {
            throw FedSetupException.invalidRequest("JWT claims 'trust_pre_authorization' and 'pending_id' are mutually exclusive");
        }
        if (approvalNotificationEndpoint != null && (trustPreAuth != null || pendingId != null || confirmationCode != null)) {
            throw FedSetupException.invalidRequest(
                    "JWT claim 'approval_notification_endpoint' may only appear on an initial Deferred Approval proposal");
        }
        if (confirmationCode != null && (trustPreAuth != null || pendingId != null)) {
            throw FedSetupException.invalidRequest(
                    "JWT claim 'confirmation_code' cannot be combined with 'trust_pre_authorization' or 'pending_id'");
        }

        return new ValidatedTrustJwt(
                jws,
                claims,
                iss,
                sub,
                aud,
                idpIssuer,
                appTenantId,
                explicitTenant,
                htm,
                htu,
                requestHash,
                jti,
                iat,
                exp,
                caps,
                capsPresent,
                deleg,
                delegPresent,
                ext,
                extPresent,
                confirmationCode,
                redirectUri,
                trustPreAuth,
                pendingId,
                approvalNotificationEndpoint
        );
    }

    public void verifySignatureWithCimdOrStaticJwks(ValidatedTrustJwt jwt, String cimdUri, String staticJwksJson) {
        if (staticJwksJson != null && !staticJwksJson.isBlank()) {
            try {
                JSONWebKeySet jwks = JsonSerialization.readValue(staticJwksJson, JSONWebKeySet.class);
                if (!verifyJwsWithJwks(jwt.getJwsInput(), jwks)) {
                    throw FedSetupException.invalidCredential("Invalid JWT signature");
                }
                return;
            } catch (FedSetupException e) {
                throw e;
            } catch (Exception e) {
                throw FedSetupException.invalidCredential("Failed to verify JWT signature: " + e.getMessage());
            }
        }

        JSONWebKeySet jwks = fetchService.resolveCimdJwks(cimdUri, false, true);
        String kid = jwt.getJwsInput().getHeader().getKeyId();
        if (jwks.getKeys().length > 1 && (kid == null || kid.isBlank())) {
            throw FedSetupException.invalidCredential("JWS 'kid' header is required when JWK Set has multiple keys");
        }
        if (kid != null && !kid.isBlank() && findJwkByKid(jwks, kid) == null) {
            // Refresh key source once on unrecognized kid per spec {{trust}}
            jwks = fetchService.resolveCimdJwks(cimdUri, true, true);
        }
        if (!verifyJwsWithJwks(jwt.getJwsInput(), jwks)) {
            throw FedSetupException.invalidCredential("JWT signature verification failed");
        }
    }

    public boolean verifyJwsWithJwks(JWSInput jws, JSONWebKeySet jwks) {
        if (jwks == null || jwks.getKeys() == null || jwks.getKeys().length == 0) {
            return false;
        }
        String kid = jws.getHeader().getKeyId();
        if (jwks.getKeys().length > 1 && (kid == null || kid.isBlank())) {
            throw FedSetupException.invalidCredential("JWS 'kid' header is required for multi-key JWK Set");
        }
        JWK selected = null;
        if (kid != null && !kid.isBlank()) {
            selected = findJwkByKid(jwks, kid);
            if (selected == null) {
                return false;
            }
        } else {
            selected = jwks.getKeys()[0];
        }
        return verifySignature(jws, selected);
    }

    private static JWK findJwkByKid(JSONWebKeySet jwks, String kid) {
        for (JWK jwk : jwks.getKeys()) {
            if (kid.equals(jwk.getKeyId())) {
                return jwk;
            }
        }
        return null;
    }

    public static boolean verifySignature(JWSInput jws, JWK jwk) {
        try {
            PublicKey publicKey = JWKParser.create(jwk).toPublicKey();
            return verifySignature(jws, publicKey);
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean verifySignature(JWSInput jws, PublicKey publicKey) {
        try {
            String alg = jws.getHeader().getAlgorithm().name();
            String javaAlg = switch (alg) {
                case "RS256" -> "SHA256withRSA";
                case "RS384" -> "SHA384withRSA";
                case "RS512" -> "SHA512withRSA";
                case "ES256" -> "SHA256withECDSAinP1363Format";
                case "ES384" -> "SHA384withECDSAinP1363Format";
                case "ES512" -> "SHA512withECDSAinP1363Format";
                case "EdDSA" -> "Ed25519";
                default -> null;
            };
            if (javaAlg == null) {
                return false;
            }
            Signature verifier = Signature.getInstance(javaAlg);
            verifier.initVerify(publicKey);
            verifier.update(jws.getEncodedSignatureInput().getBytes(StandardCharsets.US_ASCII));
            return verifier.verify(jws.getSignature());
        } catch (Exception e) {
            return false;
        }
    }

    // ---- Signed Trust Pre-Authorization JWT issuance & validation ----

    public String issueTrustPreAuthorizationJwt(
            PendingTrustAuthorizationRecord record,
            String applicationBaseUri,
            String installationEndpoint) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", applicationBaseUri);
        payload.put("aud", installationEndpoint);
        payload.put("application_tenant_id", record.getApplicationTenantId());
        payload.put("idp_issuer", record.getIdpIssuer());
        payload.put("cimd_uri", record.getCimdUri());
        payload.put("authorized_capabilities", record.getAuthorizedCapabilities());
        payload.put("provider_delegation_profiles", record.getProviderDelegationProfiles());
        payload.put("federation_extension_profiles", record.getFederationExtensionProfiles());
        payload.put("iat", record.getIssuedAt());
        payload.put("exp", record.getExpiresAt());
        payload.put("jti", record.getId());

        return signWithRealmKey(FedSetupConstants.TYP_TRUST_PRE_AUTHORIZATION, payload);
    }

    public String issueApprovalNotificationJwt(
            String applicationBaseUri,
            String approvalNotificationEndpoint,
            String runtimeCimdUri,
            String pendingId,
            String applicationTenantId,
            String idpIssuer) {
        long now = Time.currentTime();
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", applicationBaseUri);
        payload.put("aud", approvalNotificationEndpoint);
        payload.put("pending_id", pendingId);
        payload.put("application_tenant_id", applicationTenantId);
        payload.put("idp_issuer", idpIssuer);
        payload.put("cimd_uri", runtimeCimdUri);
        payload.put("event", "trust-proposal-updated");
        payload.put("iat", now);
        payload.put("exp", now + MAX_TOKEN_LIFETIME_SECONDS);
        payload.put("jti", FedSetupStore.generateSecureId("notif"));

        return signWithRealmKey(FedSetupConstants.TYP_APPROVAL_NOTIFICATION, payload);
    }

    @SuppressWarnings("unchecked")
    public PendingTrustAuthorizationRecord validateTrustPreAuthorizationJwt(
            String rawPreAuthJwt,
            String expectedApplicationBaseUri,
            String expectedInstallationEndpoint,
            ValidatedTrustJwt outerJwt,
            FedSetupStore store) {
        JWSInput jws;
        Map<String, Object> claims;
        try {
            jws = new JWSInput(rawPreAuthJwt);
            claims = JsonSerialization.readValue(jws.getContent(), Map.class);
        } catch (Exception e) {
            throw FedSetupException.invalidCredential("Malformed trust_pre_authorization JWT");
        }

        JWSHeader header = jws.getHeader();
        if (header == null || !FedSetupConstants.TYP_TRUST_PRE_AUTHORIZATION.equals(header.getType())) {
            throw FedSetupException.invalidCredential("trust_pre_authorization JWT must have typ 'fedsetup-trust-pre-authorization+jwt'");
        }
        String kid = header.getKeyId();
        if (kid == null || kid.isBlank()) {
            throw FedSetupException.invalidCredential("trust_pre_authorization JWT is missing 'kid' header");
        }
        String alg = header.getAlgorithm() != null ? header.getAlgorithm().name() : null;
        if (alg == null || !PERMITTED_ASYMMETRIC_ALGS.contains(alg)) {
            throw FedSetupException.invalidCredential("Unsupported algorithm on trust_pre_authorization JWT");
        }

        // Verify signature against realm's active/passive signing keys (published at installation_trust_jwks_uri)
        JSONWebKeySet realmJwks = getRealmTrustJwks();
        if (!verifyJwsWithJwks(jws, realmJwks)) {
            throw FedSetupException.invalidCredential("trust_pre_authorization signature verification failed");
        }

        String iss = requireStringClaim(claims, "iss");
        String aud = extractSingleAudience(claims.get("aud"));
        String appTenantId = requireStringClaim(claims, "application_tenant_id");
        String idpIssuer = requireStringClaim(claims, "idp_issuer");
        String cimdUri = requireStringClaim(claims, "cimd_uri");
        long iat = requireNumericDateClaim(claims, "iat");
        long exp = requireNumericDateClaim(claims, "exp");
        String jti = requireStringClaim(claims, "jti");

        long now = Time.currentTime();
        if (exp <= iat || exp <= now - CLOCK_SKEW_SECONDS || iat > now + CLOCK_SKEW_SECONDS) {
            throw FedSetupException.untrustedIssuer("trust_pre_authorization JWT is expired or has invalid timestamps");
        }

        if (!expectedApplicationBaseUri.equals(iss)) {
            throw FedSetupException.invalidCredential("trust_pre_authorization 'iss' does not match application_base_uri");
        }
        if (!expectedInstallationEndpoint.equals(aud)) {
            throw FedSetupException.invalidCredential("trust_pre_authorization 'aud' does not match installation_endpoint");
        }
        if (!outerJwt.getIss().equals(cimdUri)) {
            throw FedSetupException.untrustedIssuer("trust_pre_authorization 'cimd_uri' does not match installation runtime CIMD URI");
        }
        if (!outerJwt.getApplicationTenantId().equals(appTenantId)) {
            throw FedSetupException.untrustedIssuer("trust_pre_authorization 'application_tenant_id' mismatch");
        }
        if (!outerJwt.getIdpIssuer().equals(idpIssuer)) {
            throw FedSetupException.untrustedIssuer("trust_pre_authorization 'idp_issuer' mismatch");
        }

        // Check revocation or previous consumption -> untrusted_issuer per draft-tamm-express-configuration-deferred-trust {{preauth}}
        if (store.isPreAuthRevoked(jti) || store.isPreAuthConsumed(jti)) {
            throw FedSetupException.untrustedIssuer("Pending Trust Authorization has been revoked or already consumed");
        }

        // If local PendingTrustAuthorizationRecord exists for this jti, verify it hasn't been revoked or expired
        PendingTrustAuthorizationRecord localRecord = store.getPendingTrustAuthorization(jti).orElse(null);
        if (localRecord != null && (localRecord.isRevoked() || localRecord.isConsumed() || localRecord.getExpiresAt() <= now)) {
            throw FedSetupException.untrustedIssuer("Pending Trust Authorization is no longer active");
        }

        PendingTrustAuthorizationRecord resolved = new PendingTrustAuthorizationRecord();
        resolved.setId(jti);
        resolved.setApplicationTenantId(appTenantId);
        resolved.setIdpIssuer(idpIssuer);
        resolved.setCimdUri(cimdUri);
        resolved.setAuthorizedCapabilities(extractStringListClaim(claims, "authorized_capabilities"));
        resolved.setProviderDelegationProfiles(extractStringListClaim(claims, "provider_delegation_profiles"));
        resolved.setFederationExtensionProfiles(extractStringListClaim(claims, "federation_extension_profiles"));
        resolved.setIssuedAt(iat);
        resolved.setExpiresAt(exp);
        return resolved;
    }

    public JSONWebKeySet getRealmTrustJwks() {
        List<JWK> keys = new ArrayList<>();
        if (session != null && realm != null && session.keys() != null) {
            session.keys().getKeysStream(realm)
                    .filter(k -> k.getStatus() != null && (k.getStatus().isActive() || org.keycloak.crypto.KeyStatus.PASSIVE.equals(k.getStatus())))
                    .filter(k -> KeyUse.SIG.equals(k.getUse()) && k.getPublicKey() != null)
                    .forEach(k -> {
                        String alg = k.getAlgorithmOrDefault();
                        if (PERMITTED_ASYMMETRIC_ALGS.contains(alg)) {
                            JWKBuilder b = JWKBuilder.create().kid(k.getKid()).algorithm(alg);
                            if ("RSA".equalsIgnoreCase(k.getType())) {
                                keys.add(b.rsa(k.getPublicKey(), KeyUse.SIG));
                            } else if ("EC".equalsIgnoreCase(k.getType())) {
                                keys.add(b.ec(k.getPublicKey(), KeyUse.SIG));
                            } else if ("OKP".equalsIgnoreCase(k.getType())) {
                                keys.add(b.okp(k.getPublicKey(), KeyUse.SIG));
                            }
                        }
                    });
        }
        JSONWebKeySet keySet = new JSONWebKeySet();
        keySet.setKeys(keys.toArray(new JWK[0]));
        return keySet;
    }

    private String signWithRealmKey(String typ, Map<String, Object> payload) {
        KeyWrapper activeKey = session.keys().getActiveKey(realm, KeyUse.SIG, "RS256");
        if (activeKey == null) {
            throw FedSetupException.serverError("No active signing key available in realm");
        }
        String alg = activeKey.getAlgorithmOrDefault();
        SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, alg);
        SignatureSignerContext signer = signatureProvider.signer(activeKey);
        return new JWSBuilder()
                .type(typ)
                .kid(activeKey.getKid())
                .jsonContent(payload)
                .sign(signer);
    }

    private static String requireStringClaim(Map<String, Object> claims, String name) {
        Object val = claims.get(name);
        if (!(val instanceof String str) || str.isBlank()) {
            throw FedSetupException.invalidCredential("Missing or invalid JWT claim: " + name);
        }
        return str;
    }

    private static String optionalStringClaim(Map<String, Object> claims, String name) {
        if (!claims.containsKey(name) || claims.get(name) == null) {
            return null;
        }
        Object val = claims.get(name);
        if (!(val instanceof String str) || str.isBlank()) {
            throw FedSetupException.invalidCredential("Malformed JWT claim: " + name);
        }
        return str;
    }

    private static long requireNumericDateClaim(Map<String, Object> claims, String name) {
        Object val = claims.get(name);
        if (val instanceof Number num) {
            return num.longValue();
        }
        throw FedSetupException.invalidCredential("Missing or non-numeric JWT claim: " + name);
    }

    private static String extractSingleAudience(Object audClaim) {
        if (audClaim instanceof String s && !s.isBlank()) {
            return s;
        }
        if (audClaim instanceof List<?> list && list.size() == 1 && list.get(0) instanceof String s && !s.isBlank()) {
            return s;
        }
        throw FedSetupException.invalidCredential("JWT 'aud' claim must be a single non-empty URI string");
    }

    private static List<String> extractStringListClaim(Map<String, Object> claims, String name) {
        if (!claims.containsKey(name) || claims.get(name) == null) {
            return Collections.emptyList();
        }
        Object val = claims.get(name);
        if (!(val instanceof List<?> list)) {
            throw FedSetupException.invalidCredential("JWT claim '" + name + "' must be an array of strings");
        }
        List<String> result = new ArrayList<>(list.size());
        for (Object item : list) {
            if (!(item instanceof String str) || str.isBlank()) {
                throw FedSetupException.invalidCredential("JWT claim '" + name + "' must contain non-empty strings");
            }
            result.add(str);
        }
        return result;
    }
}
