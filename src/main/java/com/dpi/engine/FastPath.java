package com.dpi.engine;

import com.dpi.parser.HTTPHostExtractor;
import com.dpi.parser.SNIExtractor;
import com.dpi.rules.RuleManager;
import com.dpi.stats.Stats;
import com.dpi.tracking.ConnectionTracker;
import com.dpi.types.AppType;
import com.dpi.types.AppTypeMapper;
import com.dpi.types.Flow;
import com.dpi.types.ParsedPacket;

import java.util.Optional;

/**
 * A "Fast Path" worker: pops packets from its own input queue, looks up
 * (or creates) the flow in its own private flow table, performs DPI
 * classification (SNI/Host extraction), applies blocking rules, and
 * pushes the result to the shared output queue.
 *
 * Because packets are routed to Fast Paths by a consistent hash of the
 * five-tuple, every packet belonging to a given connection always lands
 * on the same Fast Path -- so each FP can safely keep its own flow table
 * without any locking or cross-thread coordination.
 */
public final class FastPath implements Runnable {

    private final String label;
    private final ThreadSafeQueue<ParsedPacket> inputQueue;
    private final ThreadSafeQueue<PacketResult> outputQueue;
    private final RuleManager rules;
    private final Stats stats;
    private final ConnectionTracker tracker = new ConnectionTracker();

    public FastPath(String label,
                     ThreadSafeQueue<ParsedPacket> inputQueue,
                     ThreadSafeQueue<PacketResult> outputQueue,
                     RuleManager rules,
                     Stats stats) {
        this.label = label;
        this.inputQueue = inputQueue;
        this.outputQueue = outputQueue;
        this.rules = rules;
        this.stats = stats;
    }

    @Override
    public void run() {
        try {
            ParsedPacket pkt;
            while ((pkt = inputQueue.pop()) != null) {
                process(pkt);
                stats.incrementThreadCounter(label + " processed");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            // Signal to the output stage that this FP is done, by closing
            // is handled centrally by the orchestrator (see DPIMultiThreaded).
        }
    }

    private void process(ParsedPacket parsed) throws InterruptedException {
        Flow flow = tracker.getOrCreate(parsed.tuple);
        flow.touch(parsed.raw.data.length);

        classify(parsed, flow);

        boolean blocked = flow.blocked || rules.isBlocked(parsed.srcIp, flow.appType, flow.sni);
        if (blocked) {
            flow.blocked = true;
        }

        stats.recordAppPacket(flow.appType, blocked);

        if (blocked) {
            stats.dropped.increment();
        } else {
            stats.forwarded.increment();
            outputQueue.push(new PacketResult(parsed.raw));
        }
    }

    private void classify(ParsedPacket parsed, Flow flow) {
        if (flow.sni != null || parsed.payloadLength <= 5) {
            assignFallback(parsed, flow);
            return;
        }

        byte[] payload = slicePayload(parsed);

        if (parsed.dstPort == 443 || parsed.srcPort == 443) {
            Optional<String> sni = SNIExtractor.extract(payload, payload.length);
            if (sni.isPresent()) {
                flow.sni = sni.get();
                flow.appType = AppTypeMapper.sniToAppType(flow.sni);
                flow.classified = true;
                return;
            }
        }

        if (parsed.dstPort == 80 || parsed.srcPort == 80) {
            Optional<String> host = HTTPHostExtractor.extract(payload, payload.length);
            if (host.isPresent()) {
                flow.sni = host.get();
                flow.appType = AppTypeMapper.sniToAppType(flow.sni);
                flow.classified = true;
                return;
            }
        }

        assignFallback(parsed, flow);
    }

    private void assignFallback(ParsedPacket parsed, Flow flow) {
        if (!flow.classified) {
            AppType fallback = AppTypeMapper.portToAppType(parsed.dstPort, parsed.protocol);
            if (fallback != AppType.UNKNOWN) {
                flow.appType = fallback;
            }
        }
    }

    private byte[] slicePayload(ParsedPacket parsed) {
        byte[] full = parsed.raw.data;
        int len = Math.min(parsed.payloadLength, full.length - parsed.payloadOffset);
        if (len <= 0) return new byte[0];
        byte[] out = new byte[len];
        System.arraycopy(full, parsed.payloadOffset, out, 0, len);
        return out;
    }

    public ConnectionTracker getTracker() {
        return tracker;
    }
}
