package com.dpi.types;

public final class IpUtils {

    private IpUtils() { }

    /** Converts a 32-bit IPv4 address (host order) into "a.b.c.d" form. */
    public static String toDottedDecimal(int ip) {
        return ((ip >>> 24) & 0xFF) + "."
                + ((ip >>> 16) & 0xFF) + "."
                + ((ip >>> 8) & 0xFF) + "."
                + (ip & 0xFF);
    }

    /** Parses "a.b.c.d" into a 32-bit int (host order). */
    public static int fromDottedDecimal(String s) {
        String[] parts = s.trim().split("\\.");
        if (parts.length != 4) {
            throw new IllegalArgumentException("Invalid IPv4 address: " + s);
        }
        int value = 0;
        for (String part : parts) {
            value = (value << 8) | (Integer.parseInt(part) & 0xFF);
        }
        return value;
    }
}
