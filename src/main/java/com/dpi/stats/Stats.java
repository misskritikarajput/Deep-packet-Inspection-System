package com.dpi.stats;

import com.dpi.types.AppType;
import com.dpi.types.Flow;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;

/** Thread-safe counters accumulated while processing a capture, plus report printing. */
public final class Stats {

    public final LongAdder totalPackets = new LongAdder();
    public final LongAdder totalBytes = new LongAdder();
    public final LongAdder tcpPackets = new LongAdder();
    public final LongAdder udpPackets = new LongAdder();
    public final LongAdder otherPackets = new LongAdder();
    public final LongAdder forwarded = new LongAdder();
    public final LongAdder dropped = new LongAdder();

    private final Map<AppType, LongAdder> appCounts = new ConcurrentHashMap<>();
    private final Map<AppType, LongAdder> blockedAppCounts = new ConcurrentHashMap<>();

    /** Per-thread dispatch/process counters, keyed by thread label (e.g. "LB0", "FP2"). */
    private final Map<String, AtomicLong> threadCounters = new ConcurrentSkipListMap<>();

    public void recordAppPacket(AppType type, boolean blocked) {
        appCounts.computeIfAbsent(type, k -> new LongAdder()).increment();
        if (blocked) {
            blockedAppCounts.computeIfAbsent(type, k -> new LongAdder()).increment();
        }
    }

    public void incrementThreadCounter(String label) {
        threadCounters.computeIfAbsent(label, k -> new AtomicLong(0)).incrementAndGet();
    }

    public long getThreadCounter(String label) {
        AtomicLong c = threadCounters.get(label);
        return c == null ? 0 : c.get();
    }

    public Map<String, AtomicLong> threadCounters() {
        return threadCounters;
    }

    public void printReport(String title, Map<String, Long> extraConfigLines) {
        long total = totalPackets.sum();
        StringBuilder sb = new StringBuilder();
        String bar = "\u2550".repeat(64);

        sb.append('\n').append('\u2554').append(bar).append('\u2557').append('\n');
        sb.append(centered(title, 64)).append('\n');
        sb.append('\u2560').append(bar).append('\u2563').append('\n');

        if (extraConfigLines != null && !extraConfigLines.isEmpty()) {
            StringBuilder cfg = new StringBuilder();
            for (Map.Entry<String, Long> e : extraConfigLines.entrySet()) {
                cfg.append(e.getKey()).append(": ").append(e.getValue()).append("   ");
            }
            sb.append(row(cfg.toString().trim())).append('\n');
            sb.append('\u2560').append(bar).append('\u2563').append('\n');
        }

        sb.append(row(String.format("%-22s %10d", "Total Packets:", total))).append('\n');
        sb.append(row(String.format("%-22s %10d", "Total Bytes:", totalBytes.sum()))).append('\n');
        sb.append(row(String.format("%-22s %10d", "TCP Packets:", tcpPackets.sum()))).append('\n');
        sb.append(row(String.format("%-22s %10d", "UDP Packets:", udpPackets.sum()))).append('\n');
        sb.append('\u2560').append(bar).append('\u2563').append('\n');
        sb.append(row(String.format("%-22s %10d", "Forwarded:", forwarded.sum()))).append('\n');
        sb.append(row(String.format("%-22s %10d", "Dropped:", dropped.sum()))).append('\n');

        if (!threadCounters.isEmpty()) {
            sb.append('\u2560').append(bar).append('\u2563').append('\n');
            sb.append(row("THREAD STATISTICS")).append('\n');
            for (Map.Entry<String, AtomicLong> e : threadCounters.entrySet()) {
                sb.append(row(String.format("  %-20s %10d", e.getKey() + ":", e.getValue().get()))).append('\n');
            }
        }

        sb.append('\u2560').append(bar).append('\u2563').append('\n');
        sb.append(row("APPLICATION BREAKDOWN")).append('\n');
        sb.append('\u2560').append(bar).append('\u2563').append('\n');

        appCounts.entrySet().stream()
                .sorted((a, b) -> Long.compare(b.getValue().sum(), a.getValue().sum()))
                .forEach(e -> {
                    long count = e.getValue().sum();
                    double pct = total == 0 ? 0.0 : (100.0 * count / total);
                    long blockedCount = blockedAppCounts.containsKey(e.getKey())
                            ? blockedAppCounts.get(e.getKey()).sum() : 0;
                    String hashes = "#".repeat((int) Math.round(pct / 5));
                    String suffix = blockedCount > 0 ? " (BLOCKED)" : "";
                    sb.append(row(String.format("%-18s %6d  %5.1f%% %-14s%s",
                            e.getKey().displayName(), count, pct, hashes, suffix))).append('\n');
                });

        sb.append('\u255A').append(bar).append('\u255D');
        System.out.println(sb);
    }

    private static String row(String content) {
        return "\u2551 " + padRight(content, 62) + " \u2551";
    }

    private static String centered(String s, int width) {
        int pad = Math.max(0, (width - s.length()) / 2);
        return "\u2551" + " ".repeat(pad) + s + " ".repeat(Math.max(0, width - s.length() - pad)) + "\u2551";
    }

    private static String padRight(String s, int width) {
        if (s.length() >= width) return s.substring(0, width);
        return s + " ".repeat(width - s.length());
    }

    public Map<AppType, Long> snapshotAppCounts() {
        Map<AppType, Long> m = new LinkedHashMap<>();
        appCounts.forEach((k, v) -> m.put(k, v.sum()));
        return m;
    }
}
