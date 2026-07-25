/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup.representation;

import com.fasterxml.jackson.annotation.JsonInclude;

/** Realm-local Listing metadata returned by a Catalog. It is never runtime trust. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CatalogSubmission {
    private String id;
    private String catalogTargetId;
    private String submissionId;
    private String listingId;
    private String status;
    private String statusUri;
    private String linkStatusUri;
    private String linkStatus;
    private String remoteEtag;
    private String reviewEstimatedCompletion;
    private String reviewerComments;
    private long createdAt;
    private long updatedAt;
    private long version;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getCatalogTargetId() { return catalogTargetId; }
    public void setCatalogTargetId(String catalogTargetId) { this.catalogTargetId = catalogTargetId; }
    public String getSubmissionId() { return submissionId; }
    public void setSubmissionId(String submissionId) { this.submissionId = submissionId; }
    public String getListingId() { return listingId; }
    public void setListingId(String listingId) { this.listingId = listingId; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public String getStatusUri() { return statusUri; }
    public void setStatusUri(String statusUri) { this.statusUri = statusUri; }
    public String getLinkStatusUri() { return linkStatusUri; }
    public void setLinkStatusUri(String linkStatusUri) { this.linkStatusUri = linkStatusUri; }
    public String getLinkStatus() { return linkStatus; }
    public void setLinkStatus(String linkStatus) { this.linkStatus = linkStatus; }
    public String getRemoteEtag() { return remoteEtag; }
    public void setRemoteEtag(String remoteEtag) { this.remoteEtag = remoteEtag; }
    public String getReviewEstimatedCompletion() { return reviewEstimatedCompletion; }
    public void setReviewEstimatedCompletion(String reviewEstimatedCompletion) { this.reviewEstimatedCompletion = reviewEstimatedCompletion; }
    public String getReviewerComments() { return reviewerComments; }
    public void setReviewerComments(String reviewerComments) { this.reviewerComments = reviewerComments; }
    public long getCreatedAt() { return createdAt; }
    public void setCreatedAt(long createdAt) { this.createdAt = createdAt; }
    public long getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(long updatedAt) { this.updatedAt = updatedAt; }
    public long getVersion() { return version; }
    public void setVersion(long version) { this.version = version; }
}
