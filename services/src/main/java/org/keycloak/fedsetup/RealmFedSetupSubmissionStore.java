/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

import org.keycloak.common.util.Time;
import org.keycloak.fedsetup.representation.CatalogSubmission;
import org.keycloak.fedsetup.representation.CatalogTarget;
import org.keycloak.fedsetup.representation.FedSetupSubmissionProfile;
import org.keycloak.models.RealmModel;
import org.keycloak.util.JsonSerialization;

/** Persistent realm-scoped Listing and Catalog Submission state. */
public final class RealmFedSetupSubmissionStore {

    private static final String PREFIX = "fedsetup.submission.";
    private static final String LISTING_PROFILE = PREFIX + "listing-profile";
    private static final String CATALOG_TARGET = PREFIX + "catalog-target.";
    private static final String CATALOG_TARGET_INDEX = PREFIX + "catalog-target.ids";
    private static final String CATALOG_SUBMISSION = PREFIX + "catalog-submission.";
    private static final String CATALOG_SUBMISSION_INDEX = PREFIX + "catalog-submission.ids";

    private final RealmModel realm;

    public RealmFedSetupSubmissionStore(RealmModel realm) {
        this.realm = Objects.requireNonNull(realm, "realm");
    }

    public FedSetupSubmissionProfile getListingProfile() {
        return read(LISTING_PROFILE, FedSetupSubmissionProfile.class);
    }

    public void setListingProfile(FedSetupSubmissionProfile profile) {
        write(LISTING_PROFILE, Objects.requireNonNull(profile, "profile"));
    }

    public CatalogTarget createCatalogTarget(CatalogTarget target) {
        Objects.requireNonNull(target, "target");
        if (target.getId() == null) target.setId(UUID.randomUUID().toString());
        if (getCatalogTarget(target.getId()) != null) throw new FedSetupSubmissionValidationException("Catalog target already exists");
        long now = Time.currentTime();
        target.setVersion(1);
        target.setCreatedAt(now);
        target.setUpdatedAt(now);
        write(CATALOG_TARGET + target.getId(), target);
        addToIndex(CATALOG_TARGET_INDEX, target.getId());
        return copy(target, CatalogTarget.class);
    }

    public CatalogTarget updateCatalogTarget(CatalogTarget target, long expectedVersion) {
        CatalogTarget current = requireCatalogTarget(target.getId());
        requireVersion(current.getVersion(), expectedVersion);
        target.setCreatedAt(current.getCreatedAt());
        target.setVersion(current.getVersion() + 1);
        target.setUpdatedAt(Time.currentTime());
        write(CATALOG_TARGET + target.getId(), target);
        return copy(target, CatalogTarget.class);
    }

    public CatalogTarget getCatalogTarget(String id) {
        return read(CATALOG_TARGET + id, CatalogTarget.class);
    }

    public CatalogTarget requireCatalogTarget(String id) {
        CatalogTarget target = getCatalogTarget(id);
        if (target == null) throw new FedSetupSubmissionValidationException("Unknown Catalog target");
        return target;
    }

    public List<CatalogTarget> getCatalogTargets() {
        return readIndexed(CATALOG_TARGET_INDEX, CATALOG_TARGET, CatalogTarget.class);
    }

    public CatalogSubmission createCatalogSubmission(CatalogSubmission submission) {
        Objects.requireNonNull(submission, "submission");
        if (submission.getId() == null) submission.setId(UUID.randomUUID().toString());
        if (getCatalogSubmission(submission.getId()) != null) throw new FedSetupSubmissionValidationException("Catalog Submission already exists");
        long now = Time.currentTime();
        submission.setVersion(1);
        submission.setCreatedAt(now);
        submission.setUpdatedAt(now);
        write(CATALOG_SUBMISSION + submission.getId(), submission);
        addToIndex(CATALOG_SUBMISSION_INDEX, submission.getId());
        return copy(submission, CatalogSubmission.class);
    }

    public CatalogSubmission updateCatalogSubmission(CatalogSubmission submission, long expectedVersion) {
        CatalogSubmission current = requireCatalogSubmission(submission.getId());
        requireVersion(current.getVersion(), expectedVersion);
        submission.setCreatedAt(current.getCreatedAt());
        submission.setVersion(current.getVersion() + 1);
        submission.setUpdatedAt(Time.currentTime());
        write(CATALOG_SUBMISSION + submission.getId(), submission);
        return copy(submission, CatalogSubmission.class);
    }

    public CatalogSubmission getCatalogSubmission(String id) {
        return read(CATALOG_SUBMISSION + id, CatalogSubmission.class);
    }

    public CatalogSubmission requireCatalogSubmission(String id) {
        CatalogSubmission submission = getCatalogSubmission(id);
        if (submission == null) throw new FedSetupSubmissionValidationException("Unknown Catalog Submission");
        return submission;
    }

    public List<CatalogSubmission> getCatalogSubmissions() {
        return readIndexed(CATALOG_SUBMISSION_INDEX, CATALOG_SUBMISSION, CatalogSubmission.class);
    }

    private void requireVersion(long actual, long expected) {
        if (actual != expected) throw new FedSetupSubmissionValidationException("ETag does not match the current resource version");
    }

    private void addToIndex(String indexKey, String id) {
        Set<String> ids = readIndex(indexKey);
        ids.add(id);
        realm.setAttribute(indexKey, JsonSerialization.valueAsString(ids));
    }

    private Set<String> readIndex(String indexKey) {
        String encoded = realm.getAttribute(indexKey);
        if (encoded == null) return new LinkedHashSet<>();
        try {
            return new LinkedHashSet<>(JsonSerialization.mapper.readValue(encoded, JsonSerialization.mapper.getTypeFactory()
                    .constructCollectionType(Set.class, String.class)));
        } catch (Exception e) {
            throw new IllegalStateException("FedSetup Submission record index is corrupt", e);
        }
    }

    private <T> List<T> readIndexed(String indexKey, String prefix, Class<T> type) {
        List<T> records = new ArrayList<>();
        for (String id : readIndex(indexKey)) {
            T record = read(prefix + id, type);
            if (record != null) records.add(record);
        }
        return records;
    }

    private <T> T read(String key, Class<T> type) {
        String encoded = realm.getAttribute(key);
        if (encoded == null) return null;
        try {
            return JsonSerialization.readValue(encoded, type);
        } catch (Exception e) {
            throw new IllegalStateException("FedSetup Submission record is corrupt", e);
        }
    }

    private void write(String key, Object record) {
        realm.setAttribute(key, JsonSerialization.valueAsString(record));
    }

    private <T> T copy(T record, Class<T> type) {
        return JsonSerialization.valueFromString(JsonSerialization.valueAsString(record), type);
    }
}
