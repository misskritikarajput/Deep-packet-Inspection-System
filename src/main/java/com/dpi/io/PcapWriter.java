package com.dpi.io;

import com.dpi.types.RawPacket;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Paths;

/** Writes packets to a standard little-endian, microsecond-resolution PCAP file. */
public final class PcapWriter implements AutoCloseable {

    private static final int MAGIC_LE = 0xa1b2c3d4;

    private final OutputStream out;
    private final Object lock = new Object();

    public PcapWriter(String path, int snaplen, int network) throws IOException {
        this.out = new BufferedOutputStream(Files.newOutputStream(Paths.get(path)), 1 << 20);
        writeGlobalHeader(snaplen, network);
    }

    private void writeGlobalHeader(int snaplen, int network) throws IOException {
        ByteBuffer buf = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(MAGIC_LE);
        buf.putShort((short) 2);   // version_major
        buf.putShort((short) 4);   // version_minor
        buf.putInt(0);             // thiszone
        buf.putInt(0);             // sigfigs
        buf.putInt(snaplen);
        buf.putInt(network);       // 1 = Ethernet
        out.write(buf.array());
    }

    /** Writes a single packet record (header + data). Thread-safe. */
    public void writePacket(RawPacket pkt) throws IOException {
        synchronized (lock) {
            ByteBuffer header = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
            header.putInt((int) pkt.tsSec);
            header.putInt((int) pkt.tsUsec);
            header.putInt(pkt.data.length);
            header.putInt((int) pkt.origLen);
            out.write(header.array());
            out.write(pkt.data);
        }
    }

    public void flush() throws IOException {
        synchronized (lock) {
            out.flush();
        }
    }

    @Override
    public void close() throws IOException {
        synchronized (lock) {
            out.flush();
            out.close();
        }
    }
}
