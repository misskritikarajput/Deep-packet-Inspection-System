package com.dpi.rules;

import com.dpi.types.AppType;
import com.dpi.types.IpUtils;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Holds the active blocking rules and decides whether a given flow should
 * be blocked. Three independent rule types are supported, evaluated in
 * this order: source IP, application type, then domain (SNI) substring.
 * Thread-safe: rules are read-mostly and stored in concurrent sets so the
 * multi-threaded engine can share a single instance across Fast Path threads.
 */
public final class RuleManager {

    private final Set<Integer> blockedIps = ConcurrentHashMap.newKeySet();
    private final Set<AppType> blockedApps = ConcurrentHashMap.newKeySet();
    private final Set<String> blockedDomains = ConcurrentHashMap.newKeySet();

    public void blockIp(String dottedDecimal) {
        blockedIps.add(IpUtils.fromDottedDecimal(dottedDecimal));
        System.out.println("[Rules] Blocked IP: " + dottedDecimal);
    }

    public void blockApp(AppType app) {
        blockedApps.add(app);
        System.out.println("[Rules] Blocked app: " + app.displayName());
    }

    /** @param app case-insensitive display or enum name, e.g. "YouTube" or "YOUTUBE" */
    public void blockApp(String app) {
        AppType type = resolveAppType(app);
        if (type == null) {
            System.out.println("[Rules] Warning: unknown app '" + app + "', ignoring rule");
            return;
        }
        blockApp(type);
    }

    public void blockDomain(String domainSubstring) {
        blockedDomains.add(domainSubstring.toLowerCase());
        System.out.println("[Rules] Blocked domain: " + domainSubstring);
    }

    public boolean isBlocked(int srcIp, AppType appType, String sni) {
        if (blockedIps.contains(srcIp)) {
            return true;
        }
        if (appType != null && blockedApps.contains(appType)) {
            return true;
        }
        if (sni != null && !sni.isEmpty()) {
            String lower = sni.toLowerCase();
            for (String domain : blockedDomains) {
                if (lower.contains(domain)) {
                    return true;
                }
            }
        }
        return false;
    }

    public boolean hasAnyRules() {
        return !blockedIps.isEmpty() || !blockedApps.isEmpty() || !blockedDomains.isEmpty();
    }

    private static AppType resolveAppType(String name) {
        for (AppType t : AppType.values()) {
            if (t.name().equalsIgnoreCase(name) || t.displayName().equalsIgnoreCase(name)) {
                return t;
            }
        }
        return null;
    }
}
