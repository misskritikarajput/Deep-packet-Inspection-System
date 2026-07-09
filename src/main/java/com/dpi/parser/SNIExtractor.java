package com.dpi.parser;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Extracts the Server Name Indication (SNI) hostname from a TLS
 * "Client Hello" handshake message. This is possible because, even
 * though HTTPS traffic is encrypted, the SNI extension of the Client
 * Hello is sent in plaintext so the server knows which certificate
 * to present.
 *
 * Mirrors {@code sni_extractor.cpp} from the original C++ project.
 */
public final class SNIExtractor {

    private static final int CONTENT_TYPE_HANDSHAKE = 0x16;
    private static final int HANDSHAKE_TYPE_CLIENT_HELLO = 0x01;
    private static final int EXTENSION_TYPE_SNI = 0x0000;
    private static final int SNI_TYPE_HOSTNAME = 0x00;

    private SNIExtractor() { }

    /**
     * Attempts to extract the SNI hostname from a TLS record.
     *
     * @param payload the TCP payload bytes (should start at the TLS record layer)
     * @param length  number of valid bytes in {@code payload}
     * @return the hostname, or empty if this isn't a Client Hello / no SNI present
     */
    public static Optional<String> extract(byte[] payload, int length) {
        if (payload == null || length < 6) {
            return Optional.empty();
        }

        // TLS record header: [0]=ContentType [1-2]=Version [3-4]=Length
        int contentType = u8(payload, 0);
        if (contentType != CONTENT_TYPE_HANDSHAKE) {
            return Optional.empty();
        }

        // Handshake header starts at byte 5: [5]=HandshakeType [6-8]=Length
        int handshakeType = u8(payload, 5);
        if (handshakeType != HANDSHAKE_TYPE_CLIENT_HELLO) {
            return Optional.empty();
        }

        try {
            int offset = 9; // skip record header(5) + handshake header(4)
            offset += 2;    // Client Version (2 bytes)
            offset += 32;   // Random (32 bytes)

            // Session ID
            int sessionIdLen = u8(payload, offset);
            offset += 1 + sessionIdLen;

            // Cipher Suites
            int cipherSuitesLen = u16(payload, offset);
            offset += 2 + cipherSuitesLen;

            // Compression Methods
            int compressionLen = u8(payload, offset);
            offset += 1 + compressionLen;

            if (offset + 2 > length) {
                return Optional.empty(); // no extensions present
            }

            // Extensions
            int extensionsLen = u16(payload, offset);
            offset += 2;
            int extensionsEnd = Math.min(offset + extensionsLen, length);

            while (offset + 4 <= extensionsEnd) {
                int extType = u16(payload, offset);
                int extDataLen = u16(payload, offset + 2);
                int extDataStart = offset + 4;

                if (extType == EXTENSION_TYPE_SNI) {
                    Optional<String> sni = parseSniExtension(payload, extDataStart, extDataLen, length);
                    if (sni.isPresent()) {
                        return sni;
                    }
                }

                offset = extDataStart + extDataLen;
            }
        } catch (ArrayIndexOutOfBoundsException | IllegalArgumentException e) {
            // Malformed / truncated Client Hello - not fatal, just no SNI found.
            return Optional.empty();
        }

        return Optional.empty();
    }

    private static Optional<String> parseSniExtension(byte[] payload, int start, int extDataLen, int length) {
        if (start + 5 > length) {
            return Optional.empty();
        }
        // Server Name List: [0-1]=ListLength [2]=Type [3-4]=NameLength [5..]=Name
        int listLen = u16(payload, start);
        int nameType = u8(payload, start + 2);
        int nameLen = u16(payload, start + 3);

        if (nameType != SNI_TYPE_HOSTNAME) {
            return Optional.empty();
        }
        int nameStart = start + 5;
        if (nameStart + nameLen > length || nameLen <= 0 || nameLen > 255) {
            return Optional.empty();
        }
        String hostname = new String(payload, nameStart, nameLen, StandardCharsets.US_ASCII);
        return Optional.of(hostname);
    }

    private static int u8(byte[] b, int offset) {
        if (offset < 0 || offset >= b.length) throw new ArrayIndexOutOfBoundsException(offset);
        return b[offset] & 0xFF;
    }

    private static int u16(byte[] b, int offset) {
        if (offset < 0 || offset + 1 >= b.length) throw new ArrayIndexOutOfBoundsException(offset);
        return ((b[offset] & 0xFF) << 8) | (b[offset + 1] & 0xFF);
    }
}
