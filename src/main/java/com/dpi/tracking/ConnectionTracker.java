package com.dpi.tracking;

import com.dpi.types.FiveTuple;
import com.dpi.types.Flow;

import java.util.Collection;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tracks per-connection ("flow") state, keyed by five-tuple.
 * In the multi-threaded engine, each Fast Path thread owns its own
 * ConnectionTracker instance, since a consistent hash guarantees every
 * packet of a given flow always lands on the same Fast Path.
 */
public final class ConnectionTracker {

    private final ConcurrentHashMap<FiveTuple, Flow> flows = new ConcurrentHashMap<>();

    /** Returns the existing flow for this tuple, creating one if necessary. */
    public Flow getOrCreate(FiveTuple tuple) {
        return flows.computeIfAbsent(tuple, Flow::new);
    }

    public Flow get(FiveTuple tuple) {
        return flows.get(tuple);
    }

    public int size() {
        return flows.size();
    }

    public Collection<Flow> allFlows() {
        return flows.values();
    }
}
