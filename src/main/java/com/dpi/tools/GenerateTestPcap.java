package com.dpi.tools;

import com.dpi.io.PcapWriter;
import com.dpi.types.RawPacket;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Random;

/**
 * Builds a synthetic PCAP file containing a mix of TLS (with SNI),
 * plain HTTP, and DNS traffic so the DPI engine has something realistic
 * to classify and block. Java port of {@code generate_test_pcap.py}.
 *
 * Usage: java -cp target/classes com.dpi.tools.GenerateTestPcap [output.pcap]
 */
public final class GenerateTestPcap {

    private static final String[] TLS_SNIS = {
            "www.youtube.com", "www.facebook.com", "www.google.com", "github.com",
            "www.tiktok.com", "www.twitch.tv", "www.instagram.com", "www.netflix.com",
            "api.whatsapp.com", "example.com", "www.wikipedia.org"
    };

    private static final String[] HTTP_HOSTS = {
            "neverssl.com", "example.com", "www.wikipedia.org"
    };

    private final Random rnd = new Random(42); // deterministic output
    private int seq = 1;
    private long tsSec = 1_700_000_000L;
    private long tsUsec = 0;

    public static void main(String[] args) throws IOException {
        String outPath = args.length > 0 ? args[0] : "test_dpi.pcap";
        new GenerateTestPcap().generate(outPath);
        System.out.println("Wrote synthetic capture to " + outPath);
    }

    public void generate(String outPath) throws IOException {
        try (PcapWriter writer = new PcapWriter(outPath, 65535, 1 /* Ethernet */)) {
            int clientIp = ip(192, 168, 1, 100);

            for (String sni : TLS_SNIS) {
                int serverIp = ip(93, 184, rnd.nextInt(255), rnd.nextInt(255));
                emitTcpHandshakeWithClientHello(writer, clientIp, serverIp, 443, sni);
            }

            for (String host : HTTP_HOSTS) {
                int serverIp = ip(203, 0, 113, rnd.nextInt(255));
                emitTcpHandshakeWithHttpGet(writer, clientIp, serverIp, 80, host);
            }

            for (int i = 0; i < 4; i++) {
                emitDnsQuery(writer, clientIp, ip(8, 8, 8, 8), "example" + i + ".com");
            }

            // A couple of extra plain SYNs with no identifiable payload (Unknown).
            for (int i = 0; i < 3; i++) {
                emitSyn(writer, clientIp, ip(198, 51, 100, i + 1), 5000 + i);
            }
        }
    }

    // ---- Traffic builders -------------------------------------------------

    private void emitTcpHandshakeWithClientHello(PcapWriter writer, int clientIp, int serverIp,
                                                  int serverPort, String sni) throws IOException {
        int clientPort = 40000 + rnd.nextInt(20000);
        long seqC = 1000, seqS = 5000;

        write(writer, ethIpTcp(clientIp, serverIp, clientPort, serverPort, seqC, seqS, TcpFlags.SYN, new byte[0]));
        seqS++;
        write(writer, ethIpTcp(serverIp, clientIp, serverPort, clientPort, seqS, seqC + 1, TcpFlags.SYN_ACK, new byte[0]));
        seqC++;
        write(writer, ethIpTcp(clientIp, serverIp, clientPort, serverPort, seqC, seqS + 1, TcpFlags.ACK, new byte[0]));

        byte[] clientHello = buildTlsClientHello(sni);
        write(writer, ethIpTcp(clientIp, serverIp, clientPort, serverPort, seqC, seqS + 1, TcpFlags.PSH_ACK, clientHello));
    }

    private void emitTcpHandshakeWithHttpGet(PcapWriter writer, int clientIp, int serverIp,
                                              int serverPort, String host) throws IOException {
        int clientPort = 40000 + rnd.nextInt(20000);
        long seqC = 2000, seqS = 9000;

        write(writer, ethIpTcp(clientIp, serverIp, clientPort, serverPort, seqC, seqS, TcpFlags.SYN, new byte[0]));
        seqS++;
        write(writer, ethIpTcp(serverIp, clientIp, serverPort, clientPort, seqS, seqC + 1, TcpFlags.SYN_ACK, new byte[0]));
        seqC++;
        write(writer, ethIpTcp(clientIp, serverIp, clientPort, serverPort, seqC, seqS + 1, TcpFlags.ACK, new byte[0]));

        String request = "GET / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: dpi-test\r\nConnection: close\r\n\r\n";
        write(writer, ethIpTcp(clientIp, serverIp, clientPort, serverPort, seqC, seqS + 1, TcpFlags.PSH_ACK,
                request.getBytes(StandardCharsets.US_ASCII)));
    }

    private void emitDnsQuery(PcapWriter writer, int clientIp, int serverIp, String domain) throws IOException {
        int clientPort = 50000 + rnd.nextInt(10000);
        byte[] dnsPayload = buildDnsQuery(domain);
        write(writer, ethIpUdp(clientIp, serverIp, clientPort, 53, dnsPayload));
    }

    private void emitSyn(PcapWriter writer, int clientIp, int serverIp, int serverPort) throws IOException {
        int clientPort = 40000 + rnd.nextInt(20000);
        write(writer, ethIpTcp(clientIp, serverIp, clientPort, serverPort, 1, 0, TcpFlags.SYN, new byte[0]));
    }

    private void write(PcapWriter writer, byte[] packet) throws IOException {
        tsUsec += 1000;
        if (tsUsec >= 1_000_000) {
            tsUsec -= 1_000_000;
            tsSec += 1;
        }
        writer.writePacket(new RawPacket(packet, tsSec, tsUsec, packet.length, packet.length));
        seq++;
    }

    // ---- Packet builders ---------------------------------------------------

    private static final class TcpFlags {
        static final int SYN = 0x02;
        static final int ACK = 0x10;
        static final int PSH_ACK = 0x18;
        static final int SYN_ACK = 0x12;
    }

    private byte[] ethIpTcp(int srcIp, int dstIp, int srcPort, int dstPort,
                             long seqNum, long ackNum, int flags, byte[] payload) {
        ByteArrayOutputStream tcp = new ByteArrayOutputStream();
        putU16(tcp, srcPort);
        putU16(tcp, dstPort);
        putU32(tcp, seqNum);
        putU32(tcp, ackNum);
        tcp.write(0x50); // data offset = 5 words (20 bytes), no options
        tcp.write(flags & 0xFF);
        putU16(tcp, 64240); // window
        putU16(tcp, 0);     // checksum (unused by this reader/writer)
        putU16(tcp, 0);     // urgent pointer
        byte[] tcpBytes = tcp.toByteArray();

        return ethIp(srcIp, dstIp, 6, concat(tcpBytes, payload));
    }

    private byte[] ethIpUdp(int srcIp, int dstIp, int srcPort, int dstPort, byte[] payload) {
        ByteArrayOutputStream udp = new ByteArrayOutputStream();
        putU16(udp, srcPort);
        putU16(udp, dstPort);
        putU16(udp, 8 + payload.length);
        putU16(udp, 0); // checksum
        byte[] udpBytes = concat(udp.toByteArray(), payload);
        return ethIp(srcIp, dstIp, 17, udpBytes);
    }

    private byte[] ethIp(int srcIp, int dstIp, int protocol, byte[] l4) {
        ByteArrayOutputStream ip = new ByteArrayOutputStream();
        ip.write(0x45); // version 4, IHL 5
        ip.write(0x00); // DSCP/ECN
        putU16(ip, 20 + l4.length);
        putU16(ip, seq & 0xFFFF); // identification
        putU16(ip, 0); // flags/fragment offset
        ip.write(64); // TTL
        ip.write(protocol);
        putU16(ip, 0); // checksum (unused)
        putU32(ip, srcIp);
        putU32(ip, dstIp);
        byte[] ipBytes = concat(ip.toByteArray(), l4);

        ByteArrayOutputStream eth = new ByteArrayOutputStream();
        eth.writeBytes(mac(0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x02)); // dst mac
        eth.writeBytes(mac(0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01)); // src mac
        putU16(eth, 0x0800); // EtherType IPv4
        return concat(eth.toByteArray(), ipBytes);
    }

    private byte[] buildDnsQuery(String domain) {
        ByteArrayOutputStream dns = new ByteArrayOutputStream();
        putU16(dns, 0x1234); // transaction id
        putU16(dns, 0x0100); // flags: standard query, recursion desired
        putU16(dns, 1);      // questions
        putU16(dns, 0);      // answer RRs
        putU16(dns, 0);      // authority RRs
        putU16(dns, 0);      // additional RRs
        for (String label : domain.split("\\.")) {
            byte[] l = label.getBytes(StandardCharsets.US_ASCII);
            dns.write(l.length);
            dns.writeBytes(l);
        }
        dns.write(0); // root label
        putU16(dns, 1); // QTYPE = A
        putU16(dns, 1); // QCLASS = IN
        return dns.toByteArray();
    }

    /** Builds a minimal but structurally valid TLS 1.2 Client Hello containing an SNI extension. */
    private byte[] buildTlsClientHello(String sni) {
        byte[] sniBytes = sni.getBytes(StandardCharsets.US_ASCII);

        ByteArrayOutputStream sniExtData = new ByteArrayOutputStream();
        putU16(sniExtData, 3 + sniBytes.length); // server name list length
        sniExtData.write(0x00); // name type = hostname
        putU16(sniExtData, sniBytes.length);
        sniExtData.writeBytes(sniBytes);
        byte[] sniExtDataBytes = sniExtData.toByteArray();

        ByteArrayOutputStream extensions = new ByteArrayOutputStream();
        putU16(extensions, 0x0000); // extension type = server_name
        putU16(extensions, sniExtDataBytes.length);
        extensions.writeBytes(sniExtDataBytes);
        byte[] extensionsBytes = extensions.toByteArray();

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        putU16(body, 0x0303); // client version TLS 1.2
        for (int i = 0; i < 32; i++) body.write(rnd.nextInt(256)); // random
        body.write(0); // session id length = 0
        putU16(body, 2); // cipher suites length
        putU16(body, 0x1301); // TLS_AES_128_GCM_SHA256
        body.write(1); // compression methods length
        body.write(0); // null compression
        putU16(body, extensionsBytes.length);
        body.writeBytes(extensionsBytes);
        byte[] bodyBytes = body.toByteArray();

        ByteArrayOutputStream handshake = new ByteArrayOutputStream();
        handshake.write(0x01); // handshake type = client hello
        putU24(handshake, bodyBytes.length);
        handshake.writeBytes(bodyBytes);
        byte[] handshakeBytes = handshake.toByteArray();

        ByteArrayOutputStream record = new ByteArrayOutputStream();
        record.write(0x16); // content type = handshake
        putU16(record, 0x0301); // record version TLS 1.0 (as commonly sent)
        putU16(record, handshakeBytes.length);
        record.writeBytes(handshakeBytes);
        return record.toByteArray();
    }

    // ---- Byte helpers -------------------------------------------------------

    private static void putU16(ByteArrayOutputStream out, int value) {
        out.write((value >> 8) & 0xFF);
        out.write(value & 0xFF);
    }

    private static void putU24(ByteArrayOutputStream out, int value) {
        out.write((value >> 16) & 0xFF);
        out.write((value >> 8) & 0xFF);
        out.write(value & 0xFF);
    }

    private static void putU32(ByteArrayOutputStream out, long value) {
        out.write((int) ((value >> 24) & 0xFF));
        out.write((int) ((value >> 16) & 0xFF));
        out.write((int) ((value >> 8) & 0xFF));
        out.write((int) (value & 0xFF));
    }

    private static byte[] mac(int... bytes) {
        byte[] out = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) out[i] = (byte) bytes[i];
        return out;
    }

    private static int ip(int a, int b, int c, int d) {
        return ((a & 0xFF) << 24) | ((b & 0xFF) << 16) | ((c & 0xFF) << 8) | (d & 0xFF);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
