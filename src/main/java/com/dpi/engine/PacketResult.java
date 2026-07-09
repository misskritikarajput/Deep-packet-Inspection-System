package com.dpi.engine;

import com.dpi.types.RawPacket;

/** A packet that survived DPI + rule checks and is ready to be written to output. */
public final class PacketResult {
    public final RawPacket raw;

    public PacketResult(RawPacket raw) {
        this.raw = raw;
    }
}
