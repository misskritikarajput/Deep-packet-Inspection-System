package com.dpi.parser;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Extracts the {@code Host:} header value from a plaintext HTTP request.
 * Mirrors {@code HTTPHostExtractor} from the original C++ project.
 */
public final class HTTPHostExtractor {

    private static final String[] HTTP_METHODS = {
            "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT "
    };

    private HTTPHostExtractor() { }

    public static Optional<String> extract(byte[] payload, int length) {
        if (payload == null || length < 16) {
            return Optional.empty();
        }

        int usable = Math.min(length, payload.length);
        String text = new String(payload, 0, usable, StandardCharsets.US_ASCII);

        boolean looksLikeHttp = false;
        for (String method : HTTP_METHODS) {
            if (text.startsWith(method)) {
                looksLikeHttp = true;
                break;
            }
        }
        if (!looksLikeHttp) {
            return Optional.empty();
        }

        // Header names are case-insensitive; search line by line.
        String lower = text.toLowerCase();
        int idx = lower.indexOf("\r\nhost:");
        int skip = 7;
        if (idx < 0) {
            idx = lower.indexOf("\nhost:");
            skip = 6;
        }
        if (idx < 0) {
            return Optional.empty();
        }

        int start = idx + skip;
        int end = text.indexOf('\r', start);
        if (end < 0) end = text.indexOf('\n', start);
        if (end < 0) end = text.length();

        String host = text.substring(start, end).trim();
        // Strip an explicit port, if present (e.g. "example.com:8080").
        int colon = host.indexOf(':');
        if (colon >= 0) {
            host = host.substring(0, colon);
        }
        return host.isEmpty() ? Optional.empty() : Optional.of(host);
    }
}
