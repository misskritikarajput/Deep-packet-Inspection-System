package com.dpi.engine;

import com.dpi.stats.Stats;
import com.dpi.types.ParsedPacket;

import java.util.List;

/**
 * A "Load Balancer" worker: pops parsed packets from its own input queue
 * and dispatches each one to a Fast Path, chosen by a consistent hash of
 * the packet's five-tuple. Because the hash is deterministic, every
 * packet of a given connection always reaches the same Fast Path.
 */
public final class LoadBalancer implements Runnable {

    private final String label;
    private final ThreadSafeQueue<ParsedPacket> inputQueue;
    private final List<ThreadSafeQueue<ParsedPacket>> fastPathQueues;
    private final Stats stats;

    public LoadBalancer(String label,
                         ThreadSafeQueue<ParsedPacket> inputQueue,
                         List<ThreadSafeQueue<ParsedPacket>> fastPathQueues,
                         Stats stats) {
        this.label = label;
        this.inputQueue = inputQueue;
        this.fastPathQueues = fastPathQueues;
        this.stats = stats;
    }

    @Override
    public void run() {
        try {
            ParsedPacket pkt;
            while ((pkt = inputQueue.pop()) != null) {
                int fpIndex = Math.floorMod(pkt.tuple.hashCode(), fastPathQueues.size());
                fastPathQueues.get(fpIndex).push(pkt);
                stats.incrementThreadCounter(label + " dispatched");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
