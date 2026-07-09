package com.dpi.types;

import java.util.concurrent.atomic.AtomicLong;

/** Mutable, per-connection state tracked across the life of a flow. */
public final class Flow {

    public final FiveTuple tuple;
    public volatile String sni = null;
    public volatile AppType appType = AppType.UNKNOWN;
    public volatile boolean blocked = false;
    public volatile boolean classified = false;

    public final AtomicLong packetCount = new AtomicLong(0);
    public final AtomicLong byteCount = new AtomicLong(0);
    public volatile long firstSeenMillis;
    public volatile long lastSeenMillis;

    public Flow(FiveTuple tuple) {
        this.tuple = tuple;
        this.firstSeenMillis = System.currentTimeMillis();
        this.lastSeenMillis = this.firstSeenMillis;
    }

    public void touch(int bytes) {
        packetCount.incrementAndGet();
        byteCount.addAndGet(bytes);
        lastSeenMillis = System.currentTimeMillis();
    }
}
