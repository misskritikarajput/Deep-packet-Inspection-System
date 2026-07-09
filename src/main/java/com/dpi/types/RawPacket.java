package com.dpi.types;

/** The raw bytes of a single captured packet, plus its PCAP record header fields. */
public final class RawPacket {

    public final byte[] data;
    public final long tsSec;
    public final long tsUsec;
    public final long inclLen;
    public final long origLen;

    public RawPacket(byte[] data, long tsSec, long tsUsec, long inclLen, long origLen) {
        this.data = data;
        this.tsSec = tsSec;
        this.tsUsec = tsUsec;
        this.inclLen = inclLen;
        this.origLen = origLen;
    }
}
