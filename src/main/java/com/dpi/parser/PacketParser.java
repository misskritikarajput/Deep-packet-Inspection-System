package com.dpi.parser;

import com.dpi.types.FiveTuple;
import com.dpi.types.ParsedPacket;
import com.dpi.types.RawPacket;

/**
 * Extracts Ethernet, IPv4 and TCP/UDP header fields from a raw packet buffer.
 * Mirrors {@code packet_parser.cpp} from the original C++ project.
 */
public final class PacketParser {

    private static final int ETH_HEADER_LEN = 14;
    private static final int ETHERTYPE_IPV4 = 0x0800;

    private PacketParser() { }

    /**
     * Parses a raw packet.
     * @return a populated ParsedPacket, or {@code null} if the packet is too
     *         short or not an Ethernet/IPv4 frame we understand.
     */
    public static ParsedPacket parse(RawPacket raw) {
        byte[] d = raw.data;
        if (d.length < ETH_HEADER_LEN) {
            return null;
        }

        ParsedPacket p = new ParsedPacket();
        p.raw = raw;

        parseEthernet(d, p);

        if (p.isIPv4) {
            int ipHeaderLen = parseIPv4(d, p);
            if (ipHeaderLen < 0) {
                return p; // malformed IP header; still return what we have
            }
            int l4Offset = ETH_HEADER_LEN + ipHeaderLen;

            if (p.protocol == 6) { // TCP
                parseTcp(d, l4Offset, p);
            } else if (p.protocol == 17) { // UDP
                parseUdp(d, l4Offset, p);
            } else {
                p.payloadOffset = l4Offset;
                p.payloadLength = Math.max(0, d.length - l4Offset);
            }

            p.tuple = new FiveTuple(p.srcIp, p.dstIp, p.srcPort, p.dstPort, p.protocol);
        }

        return p;
    }

    private static void parseEthernet(byte[] d, ParsedPacket p) {
        p.dstMac = macToString(d, 0);
        p.srcMac = macToString(d, 6);
        int etherType = ((d[12] & 0xFF) << 8) | (d[13] & 0xFF);
        p.isIPv4 = (etherType == ETHERTYPE_IPV4);
    }

    private static String macToString(byte[] d, int offset) {
        StringBuilder sb = new StringBuilder(17);
        for (int i = 0; i < 6; i++) {
            if (i > 0) sb.append(':');
            sb.append(String.format("%02x", d[offset + i] & 0xFF));
        }
        return sb.toString();
    }

    /** @return the IPv4 header length in bytes, or -1 if the buffer is too short. */
    private static int parseIPv4(byte[] d, ParsedPacket p) {
        int base = ETH_HEADER_LEN;
        if (d.length < base + 20) {
            return -1;
        }
        int versionIhl = d[base] & 0xFF;
        int ihl = (versionIhl & 0x0F) * 4; // header length in 32-bit words -> bytes
        if (ihl < 20 || d.length < base + ihl) {
            return -1;
        }
        p.ttl = d[base + 8] & 0xFF;
        p.protocol = d[base + 9] & 0xFF;
        p.srcIp = readInt(d, base + 12);
        p.dstIp = readInt(d, base + 16);
        return ihl;
    }

    private static void parseTcp(byte[] d, int offset, ParsedPacket p) {
        if (d.length < offset + 20) {
            p.payloadOffset = d.length;
            p.payloadLength = 0;
            return;
        }
        p.hasTcp = true;
        p.srcPort = readUnsignedShort(d, offset);
        p.dstPort = readUnsignedShort(d, offset + 2);
        p.seqNumber = readInt(d, offset + 4) & 0xFFFFFFFFL;
        p.ackNumber = readInt(d, offset + 8) & 0xFFFFFFFFL;
        int dataOffsetWords = (d[offset + 12] & 0xFF) >> 4;
        int tcpHeaderLen = dataOffsetWords * 4;
        p.tcpFlags = d[offset + 13] & 0x3F;

        int payloadOffset = offset + Math.max(tcpHeaderLen, 20);
        p.payloadOffset = payloadOffset;
        p.payloadLength = Math.max(0, d.length - payloadOffset);
    }

    private static void parseUdp(byte[] d, int offset, ParsedPacket p) {
        if (d.length < offset + 8) {
            p.payloadOffset = d.length;
            p.payloadLength = 0;
            return;
        }
        p.hasUdp = true;
        p.srcPort = readUnsignedShort(d, offset);
        p.dstPort = readUnsignedShort(d, offset + 2);
        int udpLen = readUnsignedShort(d, offset + 4);
        int payloadOffset = offset + 8;
        p.payloadOffset = payloadOffset;
        p.payloadLength = Math.max(0, Math.min(d.length, offset + udpLen) - payloadOffset);
    }

    private static int readInt(byte[] d, int offset) {
        return ((d[offset] & 0xFF) << 24) | ((d[offset + 1] & 0xFF) << 16)
                | ((d[offset + 2] & 0xFF) << 8) | (d[offset + 3] & 0xFF);
    }

    private static int readUnsignedShort(byte[] d, int offset) {
        return ((d[offset] & 0xFF) << 8) | (d[offset + 1] & 0xFF);
    }
}
