package org.keycloak.fedsetup.storage;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.keycloak.common.util.Time;
import org.keycloak.fedsetup.FedSetupConstants;
import org.keycloak.fedsetup.model.ConnectionRecord;
import org.keycloak.fedsetup.model.ConsentCodeRecord;
import org.keycloak.fedsetup.model.DeferredApprovalProposalRecord;
import org.keycloak.fedsetup.model.DirectInstallationTrustRecord;
import org.keycloak.fedsetup.model.PendingTrustAuthorizationRecord;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.util.JsonSerialization;

/**
 * Storage abstraction for FedSetup Express Configuration state in a Keycloak realm.
 */
public class FedSetupStore {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int DEFAULT_IDEMPOTENCY_TTL_SECONDS = 86400; // 24 hours

    private final KeycloakSession session;
    private final RealmModel realm;

    public FedSetupStore(KeycloakSession session, RealmModel realm) {
        this.session = session;
        this.realm = realm;
    }

    public static String generateSecureId(String prefix) {
        byte[] bytes = new byte[24]; // 192 bits (> 128 bits required by spec)
        SECURE_RANDOM.nextBytes(bytes);
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        return prefix != null && !prefix.isEmpty() ? prefix + "_" + encoded : encoded;
    }

    public static String sha256Base64Url(byte[] data) {
        if (data == null || data.length == 0) {
            return FedSetupConstants.EMPTY_BODY_SHA256;
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    public static String sha256Base64Url(String text) {
        if (text == null || text.isEmpty()) {
            return FedSetupConstants.EMPTY_BODY_SHA256;
        }
        return sha256Base64Url(text.getBytes(StandardCharsets.UTF_8));
    }

    // ---- Pending Trust Authorizations ----

    public void savePendingTrustAuthorization(PendingTrustAuthorizationRecord record) {
        try {
            String json = JsonSerialization.writeValueAsString(record);
            realm.setAttribute(FedSetupConstants.PREFIX_PENDING_TRUST + record.getId(), json);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to serialize PendingTrustAuthorizationRecord", e);
        }
    }

    public Optional<PendingTrustAuthorizationRecord> getPendingTrustAuthorization(String id) {
        String json = realm.getAttribute(FedSetupConstants.PREFIX_PENDING_TRUST + id);
        if (json == null) {
            return Optional.empty();
        }
        try {
            return Optional.of(JsonSerialization.readValue(json, PendingTrustAuthorizationRecord.class));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    public List<PendingTrustAuthorizationRecord> listPendingTrustAuthorizations() {
        List<PendingTrustAuthorizationRecord> result = new ArrayList<>();
        for (Map.Entry<String, String> entry : realm.getAttributes().entrySet()) {
            if (entry.getKey().startsWith(FedSetupConstants.PREFIX_PENDING_TRUST)) {
                try {
                    result.add(JsonSerialization.readValue(entry.getValue(), PendingTrustAuthorizationRecord.class));
                } catch (Exception ignored) {
                }
            }
        }
        return result;
    }

    public Optional<PendingTrustAuthorizationRecord> findActivePendingTrustAuthorization(String applicationTenantId, String idpIssuer, String cimdUri) {
        long now = Time.currentTime();
        return listPendingTrustAuthorizations().stream()
                .filter(r -> !r.isRevoked() && !r.isConsumed() && r.getExpiresAt() > now)
                .filter(r -> r.getApplicationTenantId().equals(applicationTenantId)
                        && r.getIdpIssuer().equals(idpIssuer)
                        && r.getCimdUri().equals(cimdUri))
                .findFirst();
    }

    // ---- Pre-Authorization JTI Consumption & Revocation ----

    public boolean isPreAuthConsumed(String preAuthJti) {
        return Boolean.parseBoolean(realm.getAttribute(FedSetupConstants.PREFIX_CONSUME_PREAUTH + preAuthJti));
    }

    public void markPreAuthConsumed(String preAuthJti) {
        realm.setAttribute(FedSetupConstants.PREFIX_CONSUME_PREAUTH + preAuthJti, Boolean.TRUE.toString());
        getPendingTrustAuthorization(preAuthJti).ifPresent(r -> {
            r.setConsumed(true);
            savePendingTrustAuthorization(r);
        });
    }

    public boolean isPreAuthRevoked(String preAuthJti) {
        if (Boolean.parseBoolean(realm.getAttribute(FedSetupConstants.PREFIX_REVOKED_PREAUTH + preAuthJti))) {
            return true;
        }
        return getPendingTrustAuthorization(preAuthJti).map(PendingTrustAuthorizationRecord::isRevoked).orElse(false);
    }

    public void revokePreAuth(String preAuthJti) {
        realm.setAttribute(FedSetupConstants.PREFIX_REVOKED_PREAUTH + preAuthJti, Boolean.TRUE.toString());
        getPendingTrustAuthorization(preAuthJti).ifPresent(r -> {
            r.setRevoked(true);
            savePendingTrustAuthorization(r);
        });
    }

    // ---- Direct Installation Trust Records ----

    public void saveTrustRecord(DirectInstallationTrustRecord record) {
        try {
            String json = JsonSerialization.writeValueAsString(record);
            realm.setAttribute(FedSetupConstants.PREFIX_TRUST + record.getId(), json);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to serialize DirectInstallationTrustRecord", e);
        }
    }

    public Optional<DirectInstallationTrustRecord> getTrustRecord(String id) {
        String json = realm.getAttribute(FedSetupConstants.PREFIX_TRUST + id);
        if (json == null) {
            return Optional.empty();
        }
        try {
            return Optional.of(JsonSerialization.readValue(json, DirectInstallationTrustRecord.class));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    public List<DirectInstallationTrustRecord> listTrustRecords() {
        List<DirectInstallationTrustRecord> result = new ArrayList<>();
        for (Map.Entry<String, String> entry : realm.getAttributes().entrySet()) {
            if (entry.getKey().startsWith(FedSetupConstants.PREFIX_TRUST)) {
                try {
                    result.add(JsonSerialization.readValue(entry.getValue(), DirectInstallationTrustRecord.class));
                } catch (Exception ignored) {
                }
            }
        }
        return result;
    }

    public Optional<DirectInstallationTrustRecord> findActiveTrustRecord(String applicationTenantId, String idpIssuer, String cimdUri) {
        return listTrustRecords().stream()
                .filter(r -> !r.isRevoked())
                .filter(r -> r.getApplicationTenantId().equals(applicationTenantId)
                        && r.getIdpIssuer().equals(idpIssuer)
                        && r.getCimdUri().equals(cimdUri))
                .findFirst();
    }

    public List<DirectInstallationTrustRecord> findActiveTrustRecordsByRuntime(String applicationTenantId, String cimdUri) {
        return listTrustRecords().stream()
                .filter(r -> !r.isRevoked())
                .filter(r -> r.getApplicationTenantId().equals(applicationTenantId)
                        && r.getCimdUri().equals(cimdUri))
                .toList();
    }

    public Optional<DirectInstallationTrustRecord> findActiveTrustRecordByOAuthClient(String oauthClientId) {
        return listTrustRecords().stream()
                .filter(r -> !r.isRevoked())
                .filter(r -> oauthClientId.equals(r.getOauthClientId()))
                .findFirst();
    }

    // ---- Front-Channel Confirmation Codes ----

    public void saveConsentCode(ConsentCodeRecord record) {
        try {
            String json = JsonSerialization.writeValueAsString(record);
            long ttl = Math.max(1L, record.getExpiresAt() - Time.currentTime());
            SingleUseObjectProvider singleUse = session.singleUseObjects();
            if (singleUse != null) {
                singleUse.put(buildConsentCodeKey(record.getCode()), ttl, Map.of("json", json));
            } else {
                realm.setAttribute("fedsetup.consent_code." + record.getCode(), json);
            }
        } catch (Exception e) {
            throw new IllegalStateException("Failed to save ConsentCodeRecord", e);
        }
    }

    public Optional<ConsentCodeRecord> consumeConsentCode(String code) {
        if (code == null || code.isBlank()) {
            return Optional.empty();
        }
        SingleUseObjectProvider singleUse = session.singleUseObjects();
        String json = null;
        if (singleUse != null) {
            Map<String, String> notes = singleUse.remove(buildConsentCodeKey(code));
            if (notes != null) {
                json = notes.get("json");
            }
        } else {
            String attrKey = "fedsetup.consent_code." + code;
            json = realm.getAttribute(attrKey);
            if (json != null) {
                realm.removeAttribute(attrKey);
            }
        }
        if (json == null) {
            return Optional.empty();
        }
        try {
            ConsentCodeRecord record = JsonSerialization.readValue(json, ConsentCodeRecord.class);
            if (record.getExpiresAt() <= Time.currentTime()) {
                return Optional.empty();
            }
            return Optional.of(record);
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    private String buildConsentCodeKey(String code) {
        return FedSetupConstants.CACHE_CONSENT_CODE_PREFIX + realm.getId() + ":" + code;
    }

    // ---- Deferred Approval Proposals ----

    public void saveDeferredProposal(DeferredApprovalProposalRecord record) {
        try {
            String json = JsonSerialization.writeValueAsString(record);
            realm.setAttribute(FedSetupConstants.PREFIX_DEFERRED + record.getPendingId(), json);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to save DeferredApprovalProposalRecord", e);
        }
    }

    public Optional<DeferredApprovalProposalRecord> getDeferredProposal(String pendingId) {
        if (pendingId == null || pendingId.isBlank()) {
            return Optional.empty();
        }
        String json = realm.getAttribute(FedSetupConstants.PREFIX_DEFERRED + pendingId);
        if (json == null) {
            return Optional.empty();
        }
        try {
            return Optional.of(JsonSerialization.readValue(json, DeferredApprovalProposalRecord.class));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    public List<DeferredApprovalProposalRecord> listDeferredProposals() {
        List<DeferredApprovalProposalRecord> result = new ArrayList<>();
        for (Map.Entry<String, String> entry : realm.getAttributes().entrySet()) {
            if (entry.getKey().startsWith(FedSetupConstants.PREFIX_DEFERRED)) {
                try {
                    result.add(JsonSerialization.readValue(entry.getValue(), DeferredApprovalProposalRecord.class));
                } catch (Exception ignored) {
                }
            }
        }
        return result;
    }

    // ---- Connections ----

    public void saveConnection(ConnectionRecord record) {
        try {
            String json = JsonSerialization.writeValueAsString(record);
            realm.setAttribute(FedSetupConstants.PREFIX_CONNECTION + record.getConnectionId(), json);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to serialize ConnectionRecord", e);
        }
    }

    public Optional<ConnectionRecord> getConnection(String connectionId) {
        if (connectionId == null || connectionId.isBlank()) {
            return Optional.empty();
        }
        String json = realm.getAttribute(FedSetupConstants.PREFIX_CONNECTION + connectionId);
        if (json == null) {
            return Optional.empty();
        }
        try {
            return Optional.of(JsonSerialization.readValue(json, ConnectionRecord.class));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    public List<ConnectionRecord> listConnections() {
        List<ConnectionRecord> result = new ArrayList<>();
        for (Map.Entry<String, String> entry : realm.getAttributes().entrySet()) {
            if (entry.getKey().startsWith(FedSetupConstants.PREFIX_CONNECTION)) {
                try {
                    result.add(JsonSerialization.readValue(entry.getValue(), ConnectionRecord.class));
                } catch (Exception ignored) {
                }
            }
        }
        result.sort(Comparator.comparing(ConnectionRecord::getConnectionId));
        return result;
    }

    public List<ConnectionRecord> findActiveSsoConnections(String applicationTenantId, String idpIssuer) {
        return listConnections().stream()
                .filter(c -> "active".equals(c.getStatus()))
                .filter(c -> applicationTenantId.equals(c.getApplicationTenantId()) && idpIssuer.equals(c.getIdpIssuer()))
                .filter(c -> c.getOidcState() != null || c.getSamlState() != null)
                .toList();
    }

    // ---- Single-Use JTI Replay Protection ----

    public boolean checkAndRecordJti(String issuer, String jti, long expEpochSeconds) {
        long ttl = Math.max(1L, expEpochSeconds - Time.currentTime() + 60L);
        String key = FedSetupConstants.CACHE_JTI_PREFIX + realm.getId() + ":" + sha256Base64Url(issuer + "|" + jti);
        SingleUseObjectProvider singleUse = session.singleUseObjects();
        if (singleUse != null) {
            return singleUse.putIfAbsent(key, ttl);
        }
        String attrKey = "fedsetup.jti." + sha256Base64Url(issuer + "|" + jti);
        String existing = realm.getAttribute(attrKey);
        long now = Time.currentTime();
        if (existing != null) {
            try {
                if (Long.parseLong(existing) > now) {
                    return false;
                }
            } catch (NumberFormatException ignored) {
            }
        }
        realm.setAttribute(attrKey, String.valueOf(now + ttl));
        return true;
    }

    // ---- Idempotency-Key Records ----

    public static class IdempotencyRecord {
        private String requestHash;
        private int statusCode;
        private String responseBodyJson;
        private String etag;
        private boolean cacheNoStore;
        private long expiresAt;

        public String getRequestHash() {
            return requestHash;
        }

        public void setRequestHash(String requestHash) {
            this.requestHash = requestHash;
        }

        public int getStatusCode() {
            return statusCode;
        }

        public void setStatusCode(int statusCode) {
            this.statusCode = statusCode;
        }

        public String getResponseBodyJson() {
            return responseBodyJson;
        }

        public void setResponseBodyJson(String responseBodyJson) {
            this.responseBodyJson = responseBodyJson;
        }

        public String getEtag() {
            return etag;
        }

        public void setEtag(String etag) {
            this.etag = etag;
        }

        public boolean isCacheNoStore() {
            return cacheNoStore;
        }

        public void setCacheNoStore(boolean cacheNoStore) {
            this.cacheNoStore = cacheNoStore;
        }

        public long getExpiresAt() {
            return expiresAt;
        }

        public void setExpiresAt(long expiresAt) {
            this.expiresAt = expiresAt;
        }
    }

    public Optional<IdempotencyRecord> getIdempotencyRecord(String authenticatedClientContext, String scopeDiscriminator, String idempotencyKey) {
        if (idempotencyKey == null || idempotencyKey.isBlank()) {
            return Optional.empty();
        }
        String composite = authenticatedClientContext + "|" + (scopeDiscriminator != null ? scopeDiscriminator : "") + "|" + idempotencyKey;
        String hash = sha256Base64Url(composite);
        SingleUseObjectProvider singleUse = session.singleUseObjects();
        String json = null;
        if (singleUse != null) {
            Map<String, String> notes = singleUse.get(FedSetupConstants.CACHE_IDEMPOTENCY_PREFIX + realm.getId() + ":" + hash);
            if (notes != null) {
                json = notes.get("json");
            }
        } else {
            json = realm.getAttribute("fedsetup.idem." + hash);
        }
        if (json == null) {
            return Optional.empty();
        }
        try {
            IdempotencyRecord rec = JsonSerialization.readValue(json, IdempotencyRecord.class);
            if (rec.getExpiresAt() <= Time.currentTime()) {
                return Optional.empty();
            }
            return Optional.of(rec);
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    public void saveIdempotencyRecord(
            String authenticatedClientContext,
            String scopeDiscriminator,
            String idempotencyKey,
            String requestFingerprint,
            int statusCode,
            String responseBodyJson,
            String etag,
            boolean cacheNoStore) {
        if (idempotencyKey == null || idempotencyKey.isBlank()) {
            return;
        }
        String composite = authenticatedClientContext + "|" + (scopeDiscriminator != null ? scopeDiscriminator : "") + "|" + idempotencyKey;
        String hash = sha256Base64Url(composite);
        IdempotencyRecord rec = new IdempotencyRecord();
        rec.setRequestHash(requestFingerprint);
        rec.setStatusCode(statusCode);
        rec.setResponseBodyJson(responseBodyJson);
        rec.setEtag(etag);
        rec.setCacheNoStore(cacheNoStore);
        rec.setExpiresAt(Time.currentTime() + DEFAULT_IDEMPOTENCY_TTL_SECONDS);
        try {
            String json = JsonSerialization.writeValueAsString(rec);
            SingleUseObjectProvider singleUse = session.singleUseObjects();
            if (singleUse != null) {
                Map<String, String> map = new HashMap<>();
                map.put("json", json);
                singleUse.put(FedSetupConstants.CACHE_IDEMPOTENCY_PREFIX + realm.getId() + ":" + hash, DEFAULT_IDEMPOTENCY_TTL_SECONDS, map);
            } else {
                realm.setAttribute("fedsetup.idem." + hash, json);
            }
        } catch (Exception e) {
            throw new IllegalStateException("Failed to save IdempotencyRecord", e);
        }
    }
}
