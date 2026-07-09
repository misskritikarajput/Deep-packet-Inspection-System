package com.dpi.types;

/** Decoded protocol fields extracted from a {@link RawPacket} by the PacketParser. */
public final class ParsedPacket {

    public String srcMac = "00:00:00:00:00:00";
    public String dstMac = "00:00:00:00:00:00";

    public boolean isIPv4 = false;
    public int srcIp = 0;
    public int dstIp = 0;
    public int protocol = 0; // 6 = TCP, 17 = UDP
    public int ttl = 0;

    public boolean hasTcp = false;
    public boolean hasUdp = false;
    public int srcPort = 0;
    public int dstPort = 0;
    public int tcpFlags = 0;
    public long seqNumber = 0;
    public long ackNumber = 0;

    /** Offset (in the original raw packet buffer) where the L7 payload begins. */
    public int payloadOffset = 0;
    /** Number of payload bytes available. */
    public int payloadLength = 0;

    public RawPacket raw;
    public FiveTuple tuple;

    public boolean isSyn() { return (tcpFlags & 0x02) != 0; }
    public boolean isAck() { return (tcpFlags & 0x10) != 0; }
    public boolean isFin() { return (tcpFlags & 0x01) != 0; }
    public boolean isRst() { return (tcpFlags & 0x04) != 0; }
}
