package com.dpi.engine;

import com.dpi.io.PcapReader;
import com.dpi.io.PcapWriter;
import com.dpi.parser.HTTPHostExtractor;
import com.dpi.parser.PacketParser;
import com.dpi.parser.SNIExtractor;
import com.dpi.rules.RuleManager;
import com.dpi.stats.Stats;
import com.dpi.tracking.ConnectionTracker;
import com.dpi.types.AppType;
import com.dpi.types.AppTypeMapper;
import com.dpi.types.Flow;
import com.dpi.types.ParsedPacket;
import com.dpi.types.RawPacket;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Simple, single-threaded DPI engine. Reads a PCAP file packet by packet,
 * classifies each flow, applies blocking rules, and writes non-blocked
 * packets to an output PCAP file. This is the easiest version to read and
 * understand -- start here before looking at the multi-threaded engine.
 *
 * Java port of {@code main_working.cpp}.
 */
public final class DPISimple {

    private final RuleManager rules;
    private final ConnectionTracker tracker = new ConnectionTracker();
    private final Stats stats = new Stats();

    public DPISimple(RuleManager rules) {
        this.rules = rules;
    }

    public void run(String inputPath, String outputPath) throws IOException {
        System.out.println("\n=== DPI Engine (Simple / Single-threaded) ===");
        System.out.println("Input:  " + inputPath);
        System.out.println("Output: " + outputPath);
        if (rules.hasAnyRules()) {
            System.out.println();
        }

        try (PcapReader reader = new PcapReader(inputPath)) {
            try (PcapWriter writer = new PcapWriter(outputPath, reader.getSnaplen(), reader.getNetwork())) {
                System.out.println("\n[Reader] Processing packets...");
                long count = 0;
                RawPacket raw;
                while ((raw = reader.readNextPacket()) != null) {
                    count++;
                    processPacket(raw, writer);
                }
                System.out.println("[Reader] Done reading " + count + " packets");
            }
        }

        stats.printReport("DPI ENGINE v1.0 (Single-threaded)", new LinkedHashMap<>());
        printDetectedDomains();
    }

    private void processPacket(RawPacket raw, PcapWriter writer) throws IOException {
        ParsedPacket parsed = PacketParser.parse(raw);
        stats.totalPackets.increment();
        stats.totalBytes.add(raw.data.length);

        if (parsed == null || !parsed.isIPv4) {
            stats.otherPackets.increment();
            writer.writePacket(raw); // pass through anything we can't classify
            stats.forwarded.increment();
            return;
        }

        if (parsed.hasTcp) {
            stats.tcpPackets.increment();
        } else if (parsed.hasUdp) {
            stats.udpPackets.increment();
        } else {
            stats.otherPackets.increment();
        }

        Flow flow = tracker.getOrCreate(parsed.tuple);
        flow.touch(raw.data.length);

        classify(parsed, flow);

        boolean blocked = flow.blocked
                || rules.isBlocked(parsed.srcIp, flow.appType, flow.sni);
        if (blocked) {
            flow.blocked = true;
        }

        stats.recordAppPacket(flow.appType, blocked);

        if (blocked) {
            stats.dropped.increment();
        } else {
            writer.writePacket(raw);
            stats.forwarded.increment();
        }
    }

    /** Attempts SNI/Host extraction and assigns an AppType to the flow. */
    private void classify(ParsedPacket parsed, Flow flow) {
        if (flow.sni != null || parsed.payloadLength <= 5) {
            if (!flow.classified) {
                AppType fallback = AppTypeMapper.portToAppType(parsed.dstPort, parsed.protocol);
                if (fallback != AppType.UNKNOWN) {
                    flow.appType = fallback;
                }
            }
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

    private void printDetectedDomains() {
        System.out.println("\n[Detected Domains/SNIs]");
        tracker.allFlows().stream()
                .filter(f -> f.sni != null)
                .distinct()
                .forEach(f -> System.out.println("  - " + f.sni + " -> " + f.appType.displayName()));
    }
}
