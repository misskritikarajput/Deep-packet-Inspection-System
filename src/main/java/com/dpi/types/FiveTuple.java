package com.dpi.types;

import java.util.Objects;

/**
 * A connection ("flow") is uniquely identified by five values:
 * source IP, destination IP, source port, destination port and protocol.
 * All packets sharing the same five-tuple belong to the same flow.
 */
public final class FiveTuple {

    public final int srcIp;
    public final int dstIp;
    public final int srcPort;
    public final int dstPort;
    public final int protocol; // 6 = TCP, 17 = UDP

    public FiveTuple(int srcIp, int dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocol = protocol;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof FiveTuple)) return false;
        FiveTuple t = (FiveTuple) o;
        return srcIp == t.srcIp && dstIp == t.dstIp && srcPort == t.srcPort
                && dstPort == t.dstPort && protocol == t.protocol;
    }

    @Override
    public int hashCode() {
        return Objects.hash(srcIp, dstIp, srcPort, dstPort, protocol);
    }

    @Override
    public String toString() {
        return IpUtils.toDottedDecimal(srcIp) + ":" + srcPort + " -> "
                + IpUtils.toDottedDecimal(dstIp) + ":" + dstPort
                + " (" + (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "proto" + protocol) + ")";
    }
}
