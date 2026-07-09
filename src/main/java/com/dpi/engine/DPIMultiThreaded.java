package com.dpi.engine;

import com.dpi.io.PcapReader;
import com.dpi.io.PcapWriter;
import com.dpi.parser.PacketParser;
import com.dpi.rules.RuleManager;
import com.dpi.stats.Stats;
import com.dpi.types.ParsedPacket;
import com.dpi.types.RawPacket;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Multi-threaded DPI engine. Reads packets on the main ("Reader") thread
 * and fans them out through a Load-Balancer -> Fast-Path -> Output-Writer
 * pipeline, mirroring the architecture documented for {@code dpi_mt.cpp}:
 *
 * <pre>
 *                     Reader Thread
 *                          |
 *          hash(5-tuple) % numLbs
 *            /                    \
 *        LB0 Thread             LB1 Thread   ...
 *            |                       |
 *   hash(5-tuple) % numFps  (same hash space for all LBs)
 *      /         \                /        \
 *   FP0         FP1             FP2        FP3   ...
 *      \          \               /         /
 *                  Output Queue
 *                       |
 *              Output Writer Thread
 * </pre>
 *
 * Consistent hashing (the same hash function / modulus used everywhere)
 * guarantees every packet of a given five-tuple always reaches the same
 * Fast Path thread, so each FP can keep a private, lock-free flow table.
 */
public final class DPIMultiThreaded {

    private final RuleManager rules;
    private final int numLbs;
    private final int numFps;
    private final Stats stats = new Stats();

    public DPIMultiThreaded(RuleManager rules, int numLbs, int numFps) {
        this.rules = rules;
        this.numLbs = Math.max(1, numLbs);
        this.numFps = Math.max(1, numFps);
    }

    public void run(String inputPath, String outputPath) throws IOException, InterruptedException {
        System.out.println("\n\u2554" + "\u2550".repeat(64) + "\u2557");
        System.out.println("\u2551          DPI ENGINE v2.0 (Multi-threaded, Java)              \u2551");
        System.out.println("\u2560" + "\u2550".repeat(64) + "\u2563");
        System.out.printf("\u2551 Load Balancers: %-3d  Fast Paths: %-3d                             \u2551%n",
                numLbs, numFps);
        System.out.println("\u255A" + "\u2550".repeat(64) + "\u255D");

        // --- Build the pipeline ---
        List<ThreadSafeQueue<ParsedPacket>> lbQueues = new ArrayList<>();
        for (int i = 0; i < numLbs; i++) {
            lbQueues.add(new ThreadSafeQueue<>());
        }
        List<ThreadSafeQueue<ParsedPacket>> fpQueues = new ArrayList<>();
        for (int i = 0; i < numFps; i++) {
            fpQueues.add(new ThreadSafeQueue<>());
        }
        ThreadSafeQueue<PacketResult> outputQueue = new ThreadSafeQueue<>();

        List<Thread> lbThreads = new ArrayList<>();
        for (int i = 0; i < numLbs; i++) {
            LoadBalancer lb = new LoadBalancer("LB" + i, lbQueues.get(i), fpQueues, stats);
            Thread t = new Thread(lb, "LB-" + i);
            lbThreads.add(t);
        }

        List<FastPath> fastPaths = new ArrayList<>();
        List<Thread> fpThreads = new ArrayList<>();
        for (int i = 0; i < numFps; i++) {
            FastPath fp = new FastPath("FP" + i, fpQueues.get(i), outputQueue, rules, stats);
            fastPaths.add(fp);
            Thread t = new Thread(fp, "FP-" + i);
            fpThreads.add(t);
        }

        int snaplen;
        int network;
        try (PcapReader probe = new PcapReader(inputPath)) {
            snaplen = probe.getSnaplen();
            network = probe.getNetwork();
        }

        PcapWriter writer = new PcapWriter(outputPath, snaplen, network);
        OutputWriterThread outputWriter = new OutputWriterThread(outputQueue, writer);
        Thread outputThread = new Thread(outputWriter, "OutputWriter");

        // --- Start all worker threads ---
        outputThread.start();
        for (Thread t : fpThreads) t.start();
        for (Thread t : lbThreads) t.start();

        // --- Reader (runs on the calling / main thread) ---
        long readCount = 0;
        System.out.println("\n[Reader] Processing packets...");
        try (PcapReader reader = new PcapReader(inputPath)) {
            RawPacket raw;
            while ((raw = reader.readNextPacket()) != null) {
                readCount++;
                stats.totalPackets.increment();
                stats.totalBytes.add(raw.data.length);

                ParsedPacket parsed = PacketParser.parse(raw);
                if (parsed == null || !parsed.isIPv4) {
                    // Can't classify -> forward straight to the output stage.
                    stats.otherPackets.increment();
                    stats.forwarded.increment();
                    outputQueue.push(new PacketResult(raw));
                    continue;
                }

                if (parsed.hasTcp) {
                    stats.tcpPackets.increment();
                } else if (parsed.hasUdp) {
                    stats.udpPackets.increment();
                } else {
                    stats.otherPackets.increment();
                }

                int lbIndex = Math.floorMod(parsed.tuple.hashCode(), numLbs);
                lbQueues.get(lbIndex).push(parsed);
            }
        }
        System.out.println("[Reader] Done reading " + readCount + " packets");

        // --- Orderly shutdown, cascading down the pipeline ---
        for (ThreadSafeQueue<ParsedPacket> q : lbQueues) q.close();
        for (Thread t : lbThreads) t.join();

        for (ThreadSafeQueue<ParsedPacket> q : fpQueues) q.close();
        for (Thread t : fpThreads) t.join();

        outputQueue.close();
        outputThread.join();
        writer.close();

        Map<String, Long> config = new LinkedHashMap<>();
        config.put("LBs", (long) numLbs);
        config.put("FPs", (long) numFps);
        stats.printReport("DPI ENGINE v2.0 (Multi-threaded)", config);
        printDetectedDomains(fastPaths);
    }

    private void printDetectedDomains(List<FastPath> fastPaths) {
        System.out.println("\n[Detected Domains/SNIs]");
        for (FastPath fp : fastPaths) {
            fp.getTracker().allFlows().stream()
                    .filter(f -> f.sni != null)
                    .forEach(f -> System.out.println("  - " + f.sni + " -> " + f.appType.displayName()));
        }
    }
}
