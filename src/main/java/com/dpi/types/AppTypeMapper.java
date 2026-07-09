package com.dpi.types;

/**
 * Maps an extracted SNI / HTTP Host string to an {@link AppType}.
 * Matching is done with simple substring checks, mirroring the
 * original C++ {@code sniToAppType()} implementation.
 */
public final class AppTypeMapper {

    private AppTypeMapper() { }

    public static AppType sniToAppType(String sniRaw) {
        if (sniRaw == null || sniRaw.isEmpty()) {
            return AppType.UNKNOWN;
        }
        String sni = sniRaw.toLowerCase();

        if (sni.contains("youtube") || sni.contains("ytimg") || sni.contains("googlevideo")) {
            return AppType.YOUTUBE;
        }
        if (sni.contains("facebook") || sni.contains("fbcdn")) {
            return AppType.FACEBOOK;
        }
        if (sni.contains("instagram") || sni.contains("cdninstagram")) {
            return AppType.INSTAGRAM;
        }
        if (sni.contains("tiktok") || sni.contains("tiktokcdn") || sni.contains("bytedance")) {
            return AppType.TIKTOK;
        }
        if (sni.contains("twitter") || sni.contains("x.com") || sni.contains("twimg")) {
            return AppType.TWITTER;
        }
        if (sni.contains("netflix") || sni.contains("nflxvideo")) {
            return AppType.NETFLIX;
        }
        if (sni.contains("amazon") || sni.contains("amazonaws")) {
            return AppType.AMAZON;
        }
        if (sni.contains("twitch") || sni.contains("ttvnw")) {
            return AppType.TWITCH;
        }
        if (sni.contains("github")) {
            return AppType.GITHUB;
        }
        if (sni.contains("whatsapp")) {
            return AppType.WHATSAPP;
        }
        if (sni.contains("telegram") || sni.contains("t.me")) {
            return AppType.TELEGRAM;
        }
        if (sni.contains("microsoft") || sni.contains("office365") || sni.contains("live.com")
                || sni.contains("windows")) {
            return AppType.MICROSOFT;
        }
        if (sni.contains("apple") || sni.contains("icloud")) {
            return AppType.APPLE;
        }
        if (sni.contains("google") || sni.contains("gstatic") || sni.contains("googleapis")) {
            return AppType.GOOGLE;
        }
        return AppType.UNKNOWN;
    }

    /** Fallback classification based on transport-layer port, used when no SNI was found. */
    public static AppType portToAppType(int dstPort, int protocol) {
        if (dstPort == 443) {
            return AppType.HTTPS;
        }
        if (dstPort == 80) {
            return AppType.HTTP;
        }
        if (dstPort == 53) {
            return AppType.DNS;
        }
        return AppType.UNKNOWN;
    }
}
