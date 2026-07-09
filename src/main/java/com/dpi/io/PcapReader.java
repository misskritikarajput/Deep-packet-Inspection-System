package com.dpi.io;

import com.dpi.types.RawPacket;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * Reads packets from a classic PCAP (libpcap) capture file.
 *
 * File layout:
 *   Global Header (24 bytes)  - magic number, version, snaplen, network type
 *   Packet Header (16 bytes)  - ts_sec, ts_usec, incl_len, orig_len   -\
 *   Packet Data   (incl_len)                                          |-- repeated
 */
public final class PcapReader implements AutoCloseable {

    private static final int MAGIC_LE = 0xa1b2c3d4;
    private static final int MAGIC_LE_NS = 0xa1b23c4d; // nanosecond-resolution variant
    private static final int MAGIC_BE = 0xd4c3b2a1;
    private static final int MAGIC_BE_NS = 0x4d3cb2a1;

    private final DataInputStream in;
    private ByteOrder byteOrder;
    private boolean nanoSeconds;

    private int versionMajor;
    private int versionMinor;
    private int snaplen;
    private int network;

    public PcapReader(String path) throws IOException {
        InputStream fis = Files.newInputStream(Paths.get(path));
        this.in = new DataInputStream(new BufferedInputStream(fis, 1 << 20));
        readGlobalHeader();
    }

    private int readIntRaw() throws IOException {
        byte[] b = new byte[4];
        in.readFully(b);
        ByteBuffer buf = ByteBuffer.wrap(b);
        buf.order(byteOrder == null ? ByteOrder.BIG_ENDIAN : byteOrder);
        return buf.getInt();
    }

    private void readGlobalHeader() throws IOException {
        byte[] magicBytes = new byte[4];
        in.readFully(magicBytes);

        // Interpret the 4 magic bytes both ways to detect endianness/resolution.
        int asBE = ByteBuffer.wrap(magicBytes).order(ByteOrder.BIG_ENDIAN).getInt();
        int asLE = ByteBuffer.wrap(magicBytes).order(ByteOrder.LITTLE_ENDIAN).getInt();

        if (asLE == MAGIC_LE) {
            byteOrder = ByteOrder.LITTLE_ENDIAN;
            nanoSeconds = false;
        } else if (asLE == MAGIC_LE_NS) {
            byteOrder = ByteOrder.LITTLE_ENDIAN;
            nanoSeconds = true;
        } else if (asBE == MAGIC_LE) {
            byteOrder = ByteOrder.BIG_ENDIAN;
            nanoSeconds = false;
        } else if (asBE == MAGIC_LE_NS) {
            byteOrder = ByteOrder.BIG_ENDIAN;
            nanoSeconds = true;
        } else {
            throw new IOException("Not a valid PCAP file (bad magic number)");
        }

        versionMajor = readUnsignedShort();
        versionMinor = readUnsignedShort();
        skip(4); // thiszone
        skip(4); // sigfigs
        snaplen = readIntRaw();
        network = readIntRaw();
    }

    private int readUnsignedShort() throws IOException {
        byte[] b = new byte[2];
        in.readFully(b);
        ByteBuffer buf = ByteBuffer.wrap(b);
        buf.order(byteOrder);
        return buf.getShort() & 0xFFFF;
    }

    private void skip(int n) throws IOException {
        in.skipBytes(n);
    }

    /**
     * Reads the next packet.
     * @return the packet, or {@code null} if end-of-file has been reached.
     */
    public RawPacket readNextPacket() throws IOException {
        long tsSec;
        long tsUsec;
        long inclLen;
        long origLen;
        try {
            tsSec = readIntRaw() & 0xFFFFFFFFL;
            tsUsec = readIntRaw() & 0xFFFFFFFFL;
            inclLen = readIntRaw() & 0xFFFFFFFFL;
            origLen = readIntRaw() & 0xFFFFFFFFL;
        } catch (EOFException eof) {
            return null;
        }

        if (inclLen > 262144) { // sanity guard against corrupt files (256 KB cap)
            throw new IOException("Suspiciously large packet length: " + inclLen);
        }

        byte[] data = new byte[(int) inclLen];
        in.readFully(data);

        return new RawPacket(data, tsSec, tsUsec, inclLen, origLen);
    }

    public int getSnaplen() { return snaplen; }
    public int getNetwork() { return network; }
    public int getVersionMajor() { return versionMajor; }
    public int getVersionMinor() { return versionMinor; }
    public boolean isNanoSecondResolution() { return nanoSeconds; }

    @Override
    public void close() throws IOException {
        in.close();
    }
}
