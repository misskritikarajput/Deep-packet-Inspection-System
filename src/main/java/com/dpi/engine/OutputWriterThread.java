package com.dpi.engine;

import com.dpi.io.PcapWriter;

import java.io.IOException;
import java.io.UncheckedIOException;

/**
 * Drains the shared output queue and writes each surviving packet to the
 * output PCAP file, in whatever order packets happen to arrive from the
 * Fast Path threads (ordering across flows is not preserved; ordering
 * within a single flow is, since a flow is always handled by one FP).
 */
public final class OutputWriterThread implements Runnable {

    private final ThreadSafeQueue<PacketResult> outputQueue;
    private final PcapWriter writer;
    private volatile long written = 0;

    public OutputWriterThread(ThreadSafeQueue<PacketResult> outputQueue, PcapWriter writer) {
        this.outputQueue = outputQueue;
        this.writer = writer;
    }

    @Override
    public void run() {
        try {
            PacketResult result;
            while ((result = outputQueue.pop()) != null) {
                writer.writePacket(result.raw);
                written++;
            }
            writer.flush();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public long getWrittenCount() {
        return written;
    }
}
