/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package org.keycloak.fedsetup;

import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.Locale;

/** Canonicalizes absolute HTTPS identifiers before they enter a trust record. */
public final class FedSetupUri {

    private static final String CONNECTION_TEMPLATE_VARIABLE = "{connection_id}";
    private static final String CONNECTION_TEMPLATE_SENTINEL = "fedsetup-connection-id";

    private FedSetupUri() {
    }

    public static String canonicalize(String value) {
        if (value == null || value.isBlank()) {
            throw new FedSetupValidationException("A URI is required");
        }

        try {
            URI uri = new URI(value.trim()).normalize();
            if (!uri.isAbsolute() || !"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
                    || uri.getRawUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null) {
                throw new FedSetupValidationException("URI must be an absolute HTTPS URI without user info, query, or fragment");
            }

            String path = uri.getRawPath();
            if (path == null || path.isEmpty()) {
                path = "/";
            }
            if (path.length() > 1 && path.endsWith("/")) {
                path = path.substring(0, path.length() - 1);
            }
            int port = uri.getPort() == 443 ? -1 : uri.getPort();
            return new URI("https", null, uri.getHost().toLowerCase(Locale.ROOT), port, path, null, null).toASCIIString();
        } catch (URISyntaxException e) {
            throw new FedSetupValidationException("Invalid URI", e);
        }
    }

    /**
     * Normalizes a registered redirect URI while retaining its query component.
     * Redirect comparison is exact after URI normalization; fragments and user
     * information are never accepted.
     */
    public static String canonicalizeRedirectUri(String value) {
        if (value == null || value.isBlank()) {
            throw new FedSetupValidationException("A redirect URI is required");
        }
        try {
            URI uri = new URI(value.trim()).normalize();
            if (!uri.isAbsolute() || !"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
                    || uri.getRawUserInfo() != null || uri.getRawFragment() != null) {
                throw new FedSetupValidationException("Redirect URI must be an absolute HTTPS URI without user info or fragment");
            }
            String path = uri.getRawPath();
            if (path == null || path.isEmpty()) {
                path = "/";
            }
            int port = uri.getPort() == 443 ? -1 : uri.getPort();
            return new URI("https", null, uri.getHost().toLowerCase(Locale.ROOT), port, path, uri.getRawQuery(), null).toASCIIString();
        } catch (URISyntaxException e) {
            throw new FedSetupValidationException("Invalid redirect URI", e);
        }
    }

    /** Canonicalizes the single-variable connection URI template from discovery. */
    public static String canonicalizeConnectionEndpointTemplate(String value) {
        if (value == null || value.isBlank() || value.indexOf(CONNECTION_TEMPLATE_VARIABLE) != value.lastIndexOf(CONNECTION_TEMPLATE_VARIABLE)
                || !value.contains(CONNECTION_TEMPLATE_VARIABLE)
                || value.replace(CONNECTION_TEMPLATE_VARIABLE, "").contains("{")) {
            throw new FedSetupValidationException("connection_endpoint_template must contain exactly one {connection_id} variable and no others");
        }
        String canonical = canonicalize(value.replace(CONNECTION_TEMPLATE_VARIABLE, CONNECTION_TEMPLATE_SENTINEL));
        int sentinel = canonical.indexOf(CONNECTION_TEMPLATE_SENTINEL);
        if (sentinel < 0 || canonical.indexOf(CONNECTION_TEMPLATE_SENTINEL, sentinel + 1) >= 0) {
            throw new FedSetupValidationException("connection_endpoint_template is invalid");
        }
        return canonical.substring(0, sentinel) + CONNECTION_TEMPLATE_VARIABLE
                + canonical.substring(sentinel + CONNECTION_TEMPLATE_SENTINEL.length());
    }

    /** Compares HTTPS origins after the canonicalization required for trust-bound endpoints. */
    public static boolean sameOrigin(String first, String second) {
        URI left = URI.create(canonicalize(first));
        URI right = URI.create(canonicalize(second));
        return left.getScheme().equals(right.getScheme()) && left.getHost().equals(right.getHost())
                && effectivePort(left) == effectivePort(right);
    }

    private static int effectivePort(URI uri) {
        return uri.getPort() == -1 ? 443 : uri.getPort();
    }

    // Reject non-public addresses resolved at validation time. This is not address pinning.
    public static void requirePublicAddress(String uri, String label) {
        URI parsed = URI.create(uri);
        try {
            for (InetAddress address : InetAddress.getAllByName(parsed.getHost())) {
                if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress()
                        || address.isSiteLocalAddress() || address.isMulticastAddress() || isIpv6UniqueLocal(address)) {
                    throw new FedSetupValidationException(label + " resolves to a prohibited network address");
                }
            }
        } catch (UnknownHostException e) {
            throw new FedSetupValidationException(label + " host cannot be resolved", e);
        }
    }

    // isSiteLocalAddress does not recognize RFC 4193's fc00::/7 ULA range.
    private static boolean isIpv6UniqueLocal(InetAddress address) {
        byte[] bytes = address.getAddress();
        return bytes.length == 16 && (bytes[0] & 0xFE) == 0xFC;
    }
}
