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
public final class FedSetupSubmissionUri {

    private FedSetupSubmissionUri() {
    }

    public static String canonicalize(String value) {
        if (value == null || value.isBlank()) {
            throw new FedSetupSubmissionValidationException("A URI is required");
        }

        try {
            URI uri = new URI(value.trim()).normalize();
            if (!uri.isAbsolute() || !"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
                    || uri.getRawUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null) {
                throw new FedSetupSubmissionValidationException("URI must be an absolute HTTPS URI without user info, query, or fragment");
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
            throw new FedSetupSubmissionValidationException("Invalid URI", e);
        }
    }

    // Reject non-public addresses resolved at validation time. This is not address pinning.
    public static void requirePublicAddress(String uri, String label) {
        URI parsed = URI.create(uri);
        try {
            for (InetAddress address : InetAddress.getAllByName(parsed.getHost())) {
                if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress()
                        || address.isSiteLocalAddress() || address.isMulticastAddress() || isIpv6UniqueLocal(address)) {
                    throw new FedSetupSubmissionValidationException(label + " resolves to a prohibited network address");
                }
            }
        } catch (UnknownHostException e) {
            throw new FedSetupSubmissionValidationException(label + " host cannot be resolved", e);
        }
    }

    // isSiteLocalAddress does not recognize RFC 4193's fc00::/7 ULA range.
    private static boolean isIpv6UniqueLocal(InetAddress address) {
        byte[] bytes = address.getAddress();
        return bytes.length == 16 && (bytes[0] & 0xFE) == 0xFC;
    }
}
