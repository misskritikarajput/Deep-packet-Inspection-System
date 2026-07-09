package com.dpi.types;

/**
 * Enumerates the application / traffic categories the DPI engine can
 * recognize. New signatures can be added in {@link AppTypeMapper}.
 */
public enum AppType {
    UNKNOWN,
    HTTP,
    HTTPS,
    DNS,
    GOOGLE,
    YOUTUBE,
    FACEBOOK,
    INSTAGRAM,
    TIKTOK,
    TWITTER,
    NETFLIX,
    AMAZON,
    TWITCH,
    GITHUB,
    WHATSAPP,
    TELEGRAM,
    MICROSOFT,
    APPLE;

    /** Pretty name used in reports (e.g. "YouTube" instead of "YOUTUBE"). */
    public String displayName() {
        switch (this) {
            case HTTP: return "HTTP";
            case HTTPS: return "HTTPS";
            case DNS: return "DNS";
            case GOOGLE: return "Google";
            case YOUTUBE: return "YouTube";
            case FACEBOOK: return "Facebook";
            case INSTAGRAM: return "Instagram";
            case TIKTOK: return "TikTok";
            case TWITTER: return "Twitter/X";
            case NETFLIX: return "Netflix";
            case AMAZON: return "Amazon";
            case TWITCH: return "Twitch";
            case GITHUB: return "GitHub";
            case WHATSAPP: return "WhatsApp";
            case TELEGRAM: return "Telegram";
            case MICROSOFT: return "Microsoft";
            case APPLE: return "Apple";
            default: return "Unknown";
        }
    }
}
