<<<<<<< HEAD
# DPI Engine (Java) - Deep Packet Inspection System

This is a **Java port** of the original C++ [`Packet_analyzer`](https://github.com/perryvegehan/Packet_analyzer)
DPI engine. It re-implements every feature described in that project's README —
PCAP parsing, protocol decoding, TLS SNI / HTTP Host extraction, flow tracking,
IP/app/domain blocking rules, a single-threaded engine, and a multi-threaded
Load-Balancer → Fast-Path pipeline — using only the Java standard library
(no external dependencies).

This document explains **everything**: networking background, the file
structure, how a packet flows through the system, and how to build and run it.

---

## Table of Contents

1. [What is DPI?](#1-what-is-dpi)
2. [Networking Background](#2-networking-background)
3. [Project Overview](#3-project-overview)
4. [File Structure](#4-file-structure)
5. [The Journey of a Packet (Simple Version)](#5-the-journey-of-a-packet-simple-version)
6. [The Journey of a Packet (Multi-threaded Version)](#6-the-journey-of-a-packet-multi-threaded-version)
7. [Deep Dive: Each Component](#7-deep-dive-each-component)
8. [How SNI Extraction Works](#8-how-sni-extraction-works)
9. [How Blocking Works](#9-how-blocking-works)
10. [Building and Running](#10-building-and-running)
11. [Understanding the Output](#11-understanding-the-output)
12. [Differences from the C++ Version](#12-differences-from-the-c-version)
13. [Extending the Project](#13-extending-the-project)

---

## 1. What is DPI?

**Deep Packet Inspection (DPI)** examines the contents of network packets as
they pass through a checkpoint. Unlike simple firewalls that only look at
packet headers (source/destination IP), DPI looks *inside* the packet
payload.

### Real-World Uses

- **ISPs**: Throttle or block certain applications (e.g., BitTorrent)
- **Enterprises**: Block social media on office networks
- **Parental Controls**: Block inappropriate websites
- **Security**: Detect malware or intrusion attempts

### What This Engine Does

```
User Traffic (PCAP) → [DPI Engine] → Filtered Traffic (PCAP)
                           |
                    - Identifies apps (YouTube, Facebook, etc.)
                    - Blocks based on rules
                    - Generates a report
```

---

## 2. Networking Background

### The Network Stack (Layers)

```
+-----------------------------------------------------------+
| Layer 7: Application    | HTTP, TLS, DNS                  |
+-----------------------------------------------------------+
| Layer 4: Transport      | TCP (reliable), UDP (fast)      |
+-----------------------------------------------------------+
| Layer 3: Network        | IP addresses (routing)          |
+-----------------------------------------------------------+
| Layer 2: Data Link      | MAC addresses (local network)   |
+-----------------------------------------------------------+
```

### A Packet's Structure

Every network packet is a **Russian nesting doll** — headers wrapped inside headers:

```
Ethernet Header (14 bytes)
  IP Header (20+ bytes)
    TCP/UDP Header (20 / 8 bytes)
      Payload (Application Data)
        e.g. TLS Client Hello with SNI
```

### The Five-Tuple

A **connection** ("flow") is uniquely identified by 5 values:

| Field            | Example        | Purpose                              |
|-------------------|----------------|---------------------------------------|
| Source IP        | 192.168.1.100  | Who is sending                       |
| Destination IP   | 172.217.14.206 | Where it's going                     |
| Source Port      | 54321          | Sender's application identifier      |
| Destination Port | 443            | Service being accessed (443 = HTTPS) |
| Protocol         | TCP (6)        | TCP or UDP                           |

All packets with the same 5-tuple belong to the same connection: if we block
one packet of a flow, we mark the whole flow blocked and drop every packet
after it.

### What is SNI?

**Server Name Indication (SNI)** is part of the TLS/HTTPS handshake. When you
visit `https://www.youtube.com`, your browser's "Client Hello" message
includes the domain name **in plaintext** so the server knows which
certificate to present — even though everything after the handshake is
encrypted.

```
TLS Client Hello:
├── Version: TLS 1.2
├── Random: [32 bytes]
├── Cipher Suites: [list]
└── Extensions:
    └── SNI Extension:
        └── Server Name: "www.youtube.com"  <- We extract THIS!
```

**This is the key to DPI**: even HTTPS traffic leaks the destination domain
in its very first packet.

---

## 3. Project Overview

```
+-------------+     +-------------+     +-------------+
| Wireshark   |     | DPI Engine  |     | Output      |
| Capture     | --> |             | --> | PCAP        |
| (input.pcap)|     | - Parse     |     | (filtered)  |
+-------------+     | - Classify  |     +-------------+
                     | - Block     |
                     | - Report    |
                     +-------------+
```

### Two Versions

| Version                  | Class                              | Use Case                   |
|---------------------------|-------------------------------------|-----------------------------|
| Simple (Single-threaded) | `com.dpi.engine.DPISimple`         | Learning, small captures   |
| Multi-threaded           | `com.dpi.engine.DPIMultiThreaded`  | Production, large captures |

Both share the same parsing, classification and rule-checking code
(`PacketParser`, `SNIExtractor`, `HTTPHostExtractor`, `AppTypeMapper`,
`RuleManager`) — only the concurrency model differs.

---

## 4. File Structure

```
dpi-engine-java/
├── pom.xml                          # Optional Maven build file
├── build.sh                         # Plain javac build script (no Maven needed)
├── run.sh                           # Convenience run wrapper
├── README.md                        # This file
└── src/main/java/com/dpi/
    ├── Main.java                    # CLI entry point
    ├── types/
    │   ├── AppType.java             # Enum of recognized applications
    │   ├── AppTypeMapper.java       # SNI/Host -> AppType, port -> AppType
    │   ├── FiveTuple.java           # Flow key (src/dst ip+port, protocol)
    │   ├── IpUtils.java             # int <-> "a.b.c.d" conversions
    │   ├── ParsedPacket.java        # Decoded Ethernet/IP/TCP/UDP fields
    │   ├── RawPacket.java           # Raw bytes + PCAP record header
    │   └── Flow.java                # Per-connection tracked state
    ├── io/
    │   ├── PcapReader.java          # PCAP file reading (endianness-aware)
    │   └── PcapWriter.java          # PCAP file writing
    ├── parser/
    │   ├── PacketParser.java        # Ethernet/IPv4/TCP/UDP header parsing
    │   ├── SNIExtractor.java        # TLS Client Hello -> SNI hostname
    │   └── HTTPHostExtractor.java   # Plaintext HTTP -> Host header
    ├── rules/
    │   └── RuleManager.java         # IP / App / Domain blocking rules
    ├── tracking/
    │   └── ConnectionTracker.java   # Five-tuple -> Flow table
    ├── stats/
    │   └── Stats.java               # Counters + report printing
    ├── engine/
    │   ├── CliOptions.java          # Argument parsing
    │   ├── DPISimple.java           # ★ SIMPLE (single-threaded) VERSION ★
    │   ├── DPIMultiThreaded.java    # ★ MULTI-THREADED VERSION ★ (orchestrator)
    │   ├── ThreadSafeQueue.java     # Blocking producer/consumer queue
    │   ├── LoadBalancer.java        # LB worker thread
    │   ├── FastPath.java            # FP worker thread
    │   ├── OutputWriterThread.java  # Writes surviving packets to output.pcap
    │   └── PacketResult.java        # A packet that passed DPI + rule checks
    └── tools/
        └── GenerateTestPcap.java    # Creates a synthetic test capture
```

---

## 5. The Journey of a Packet (Simple Version)

Let's trace a single packet through `DPISimple.run()`.

### Step 1: Read the PCAP File

```java
PcapReader reader = new PcapReader("capture.pcap");
```

- Opens the file, reads the 24-byte global header (magic number, version,
  snaplen, link type)
- Auto-detects byte order from the magic number (`0xa1b2c3d4` little-endian
  is the common case; big-endian and nanosecond-resolution variants are
  also handled)

**PCAP File Format:**

```
+-----------------------------+
| Global Header (24 bytes)   |  <- read once at start
+-----------------------------+
| Packet Header (16 bytes)   |  <- timestamp, length
| Packet Data (variable)     |  <- actual network bytes
+-----------------------------+
| Packet Header (16 bytes)   |
| Packet Data (variable)     |
+-----------------------------+
| ... more packets ...       |
+-----------------------------+
```

### Step 2: Read Each Packet

```java
RawPacket raw;
while ((raw = reader.readNextPacket()) != null) {
    // raw.data contains the packet bytes
    // raw.tsSec / raw.tsUsec / raw.origLen are the header fields
}
```

- Reads the 16-byte packet header, then `incl_len` bytes of packet data
- Returns `null` at end-of-file

### Step 3: Parse Protocol Headers

```java
ParsedPacket parsed = PacketParser.parse(raw);
```

```
raw.data bytes:
[0-13]   Ethernet Header
[14-33]  IP Header
[34-53]  TCP Header
[54+]    Payload

After parsing:
parsed.srcMac    = "00:11:22:33:44:55"
parsed.dstMac    = "aa:bb:cc:dd:ee:ff"
parsed.srcIp     = 3232235876          (192.168.1.100, packed int)
parsed.dstIp     = 2899903182          (172.217.14.206, packed int)
parsed.srcPort   = 54321
parsed.dstPort   = 443
parsed.protocol  = 6                   (TCP)
parsed.hasTcp    = true
```

**Ethernet Header (14 bytes):** bytes 0-5 dest MAC, 6-11 src MAC, 12-13
EtherType (`0x0800` = IPv4).

**IPv4 Header (20+ bytes):** byte 0 version+IHL, byte 8 TTL, byte 9 protocol
(6=TCP, 17=UDP), bytes 12-15 source IP, bytes 16-19 destination IP.

**TCP Header (20+ bytes):** bytes 0-1 source port, 2-3 dest port, 4-7 sequence
number, 8-11 ack number, byte 12 data offset, byte 13 flags (SYN/ACK/FIN/...).

### Step 4: Create a Five-Tuple and Look Up the Flow

```java
Flow flow = tracker.getOrCreate(parsed.tuple);
```

- The flow table is a `ConcurrentHashMap<FiveTuple, Flow>`
- If this five-tuple already exists we get the existing `Flow`; otherwise a
  new one is created
- All packets with the same five-tuple share the same `Flow` object

### Step 5: Extract SNI / HTTP Host (Deep Packet Inspection)

```java
if (parsed.dstPort == 443 || parsed.srcPort == 443) {
    Optional<String> sni = SNIExtractor.extract(payload, payload.length);
    if (sni.isPresent()) {
        flow.sni = sni.get();
        flow.appType = AppTypeMapper.sniToAppType(flow.sni); // e.g. AppType.YOUTUBE
    }
}
```

See [Section 8](#8-how-sni-extraction-works) for the full byte-level breakdown.

### Step 6: Check Blocking Rules

```java
boolean blocked = flow.blocked || rules.isBlocked(parsed.srcIp, flow.appType, flow.sni);
```

```java
// Inside RuleManager.isBlocked():
if (blockedIps.contains(srcIp))               return true;
if (blockedApps.contains(appType))             return true;
for (String domain : blockedDomains) {
    if (sni.toLowerCase().contains(domain))    return true;
}
return false;
```

### Step 7: Forward or Drop

```java
if (blocked) {
    stats.dropped.increment();
} else {
    writer.writePacket(raw);
    stats.forwarded.increment();
}
```

### Step 8: Generate the Report

After all packets are processed, `Stats.printReport(...)` tallies packets
per `AppType` and prints a formatted summary box (see [Section 11](#11-understanding-the-output)).

---

## 6. The Journey of a Packet (Multi-threaded Version)

`DPIMultiThreaded` adds **parallelism** for high-throughput processing of
large captures.

### Architecture Overview

```
                     Reader Thread (main thread)
                                |
                 hash(5-tuple) % numLbs
                 /                          \
           LB0 Thread                   LB1 Thread   ...
                |                              |
     hash(5-tuple) % numFps        (same hash space for every LB)
        /            \                  /            \
     FP0            FP1              FP2            FP3   ...
        \              \              /              /
                        Output Queue
                             |
                   Output Writer Thread
                             |
                        output.pcap
```

### Why This Design?

1. **Load Balancers (LBs)** distribute work across Fast Paths
2. **Fast Paths (FPs)** do the actual DPI processing (classification + rules)
3. **Consistent hashing** guarantees the same five-tuple always lands on the
   same Fast Path, so each FP can keep a **private, lock-free flow table**

```
Connection: 192.168.1.100:54321 -> 142.250.185.206:443

Packet 1 (SYN):          hash -> FP2
Packet 2 (SYN-ACK):      hash -> FP2  (same FP!)
Packet 3 (Client Hello): hash -> FP2  (same FP!)
Packet 4 (Data):         hash -> FP2  (same FP!)

All packets of this connection go to FP2, so FP2 can track the flow's
state (SNI, app type, blocked?) correctly without locking.
```

### Detailed Flow

#### Step 1 — Reader Thread (`DPIMultiThreaded.run`, main thread)

```java
while ((raw = reader.readNextPacket()) != null) {
    ParsedPacket parsed = PacketParser.parse(raw);
    int lbIndex = Math.floorMod(parsed.tuple.hashCode(), numLbs);
    lbQueues.get(lbIndex).push(parsed);
}
```

#### Step 2 — Load Balancer Thread (`LoadBalancer.run`)

```java
while ((pkt = inputQueue.pop()) != null) {
    int fpIndex = Math.floorMod(pkt.tuple.hashCode(), fastPathQueues.size());
    fastPathQueues.get(fpIndex).push(pkt);
}
```

#### Step 3 — Fast Path Thread (`FastPath.run`)

```java
while ((pkt = inputQueue.pop()) != null) {
    Flow flow = tracker.getOrCreate(pkt.tuple);   // this FP's own flow table
    classify(pkt, flow);                          // SNI / Host extraction
    boolean blocked = rules.isBlocked(pkt.srcIp, flow.appType, flow.sni);
    if (!blocked) outputQueue.push(new PacketResult(pkt.raw));
}
```

#### Step 4 — Output Writer Thread (`OutputWriterThread.run`)

```java
while ((result = outputQueue.pop()) != null) {
    writer.writePacket(result.raw);
}
```

### Thread-Safe Queue

`ThreadSafeQueue<T>` is a bounded, blocking producer/consumer queue built
from a `ReentrantLock` and two `Condition`s (not-empty / not-full) — the
Java equivalent of the mutex + `std::condition_variable` pattern:

```java
public void push(T item) throws InterruptedException {
    lock.lock();
    try {
        while (queue.size() >= capacity && !closed) notFull.await();
        queue.addLast(item);
        notEmpty.signal();
    } finally { lock.unlock(); }
}

public T pop() throws InterruptedException {
    lock.lock();
    try {
        while (queue.isEmpty() && !closed) notEmpty.await();
        if (queue.isEmpty()) return null; // closed and drained
        T item = queue.removeFirst();
        notFull.signal();
        return item;
    } finally { lock.unlock(); }
}
```

`close()` marks the queue closed and wakes every waiting thread so the
pipeline can shut down cleanly, stage by stage, once the reader has
finished (LB queues close → LB threads finish and join → FP queues close →
FP threads finish and join → output queue closes → writer thread finishes).

---

## 7. Deep Dive: Each Component

### `PcapReader` / `PcapWriter`

**Purpose:** Read/write network captures compatible with Wireshark / tcpdump.

**Key fields (global header):** `magic_number` (endianness/resolution
detection), `version_major`/`version_minor`, `snaplen`, `network` (1 =
Ethernet).

**Key fields (per-packet header):** `ts_sec`, `ts_usec`, `incl_len`,
`orig_len`.

### `PacketParser`

**Purpose:** Extract protocol fields from raw bytes.

```java
ParsedPacket parse(RawPacket raw) {
    parseEthernet(...);  // MACs, EtherType
    parseIPv4(...);      // IPs, protocol, TTL, header length (IHL)
    parseTcp(...);       // ports, flags, seq/ack numbers, payload offset
    // OR
    parseUdp(...);       // ports, payload offset
}
```

Multi-byte header fields are big-endian ("network byte order"); the parser
reads them by hand with explicit shifts (`(b[0]&0xFF)<<8 | (b[1]&0xFF)`)
rather than relying on platform-dependent primitive byte order.

### `SNIExtractor`

**Purpose:** Extract the domain name from a TLS Client Hello.

```java
Optional<String> extract(byte[] payload, int length) {
    // 1. Verify TLS record header (content type = handshake)
    // 2. Verify Client Hello handshake type
    // 3. Skip Version, Random, Session ID, Cipher Suites, Compression
    // 4. Walk the Extensions list looking for type 0x0000 (SNI)
    // 5. Return the hostname string
}
```

### `HTTPHostExtractor`

**Purpose:** Extract the `Host:` header from a plaintext HTTP request
(port 80 traffic).

### `AppType` / `AppTypeMapper`

**Purpose:** Define the set of recognized applications and map an
SNI/Host string (or, as a fallback, a well-known port) to one of them.

```java
enum AppType { UNKNOWN, HTTP, HTTPS, DNS, GOOGLE, YOUTUBE, FACEBOOK,
               INSTAGRAM, TIKTOK, TWITTER, NETFLIX, AMAZON, TWITCH,
               GITHUB, WHATSAPP, TELEGRAM, MICROSOFT, APPLE }
```

```java
static AppType sniToAppType(String sni) {
    if (sni.contains("youtube"))  return AppType.YOUTUBE;
    if (sni.contains("facebook")) return AppType.FACEBOOK;
    // ... more patterns
}
```

### `FiveTuple`

```java
final class FiveTuple {
    final int srcIp, dstIp, srcPort, dstPort, protocol;
    // equals()/hashCode() based on all five fields
}
```

### `RuleManager`

Three independent, thread-safe rule sets (`ConcurrentHashMap.newKeySet()`):
blocked IPs, blocked `AppType`s, blocked domain substrings.

---

## 8. How SNI Extraction Works

### The TLS Handshake

```
  Browser                                    Server
     |                                          |
     |---- Client Hello ---------------------->|
     |     (includes SNI: www.youtube.com)     |
     |                                          |
     |<--- Server Hello ------------------------|
     |     (includes certificate)               |
     |                                          |
     |---- Key Exchange ----------------------->|
     |                                          |
     |<=== Encrypted Data ======================>|
     |     (from here on, everything is         |
     |      encrypted - we can't see it)        |
```

**We can only extract SNI from the Client Hello** — the very first packet
of the handshake, which is not yet encrypted.

### TLS Client Hello Structure

```
Byte 0:      Content Type = 0x16 (Handshake)
Bytes 1-2:   Version = 0x0301
Bytes 3-4:   Record Length

-- Handshake Layer --
Byte 5:      Handshake Type = 0x01 (Client Hello)
Bytes 6-8:   Handshake Length

-- Client Hello Body --
Bytes 9-10:  Client Version
Bytes 11-42: Random (32 bytes)
Byte 43:     Session ID Length (N)
Bytes 44..44+N: Session ID
... Cipher Suites ...
... Compression Methods ...

-- Extensions --
Extensions Length (2 bytes)
For each extension:
    Extension Type (2 bytes)
    Extension Length (2 bytes)
    Extension Data

-- SNI Extension (Type 0x0000) --
  Server Name List Length (2 bytes)
  Name Type = 0x00 (hostname)          (1 byte)
  Name Length (2 bytes)
  Name Value: "www.youtube.com"  <- THE GOAL!
```

### Our Extraction Code (`SNIExtractor.extract`, simplified)

```java
if (u8(payload, 0) != 0x16) return Optional.empty();   // not Handshake
if (u8(payload, 5) != 0x01) return Optional.empty();   // not Client Hello

int offset = 9 + 2 + 32;                 // record+handshake headers, version, random
int sessionIdLen = u8(payload, offset);
offset += 1 + sessionIdLen;

int cipherSuitesLen = u16(payload, offset);
offset += 2 + cipherSuitesLen;

int compressionLen = u8(payload, offset);
offset += 1 + compressionLen;

int extensionsLen = u16(payload, offset);
offset += 2;
int extensionsEnd = offset + extensionsLen;

while (offset + 4 <= extensionsEnd) {
    int extType = u16(payload, offset);
    int extDataLen = u16(payload, offset + 2);
    if (extType == 0x0000) {              // SNI!
        int listLen  = u16(payload, offset + 4);
        int nameType = u8(payload, offset + 6);
        int nameLen  = u16(payload, offset + 7);
        return Optional.of(new String(payload, offset + 9, nameLen, US_ASCII));
    }
    offset += 4 + extDataLen;
}
return Optional.empty();  // SNI not found
```

All array reads go through bounds-checked `u8()`/`u16()` helpers, so a
truncated or malformed Client Hello simply results in "no SNI found"
instead of an exception propagating out of the engine.

---

## 9. How Blocking Works

### Rule Types

| Rule Type | Example        | What it Blocks                |
|-----------|-----------------|--------------------------------|
| IP        | `192.168.1.50` | All traffic from this source  |
| App       | `YouTube`      | All YouTube connections       |
| Domain    | `tiktok`       | Any SNI/Host containing "tiktok" |

### The Blocking Flow

```
Packet arrives
      |
      v
Is source IP in blocked list? --Yes--> DROP
      |No
      v
Is app type in blocked list? --Yes--> DROP
      |No
      v
Does SNI/Host match blocked domain? --Yes--> DROP
      |No
      v
   FORWARD
```

### Flow-Based Blocking

We block at the **flow** level, not the packet level:

```
Connection to YouTube:
  Packet 1 (SYN)           -> No SNI yet, FORWARD
  Packet 2 (SYN-ACK)       -> No SNI yet, FORWARD
  Packet 3 (ACK)           -> No SNI yet, FORWARD
  Packet 4 (Client Hello)  -> SNI: www.youtube.com
                            -> App: YOUTUBE (blocked!)
                            -> Mark flow as BLOCKED, DROP this packet
  Packet 5 (Data)          -> Flow is BLOCKED -> DROP
  Packet 6 (Data)          -> Flow is BLOCKED -> DROP
  ...all subsequent packets -> DROP
```

We can't identify the application until we see the Client Hello. Once
identified, `flow.blocked` is latched `true` and every future packet of
that flow is dropped — the connection fails or times out on the client.

---

## 10. Building and Running

### Prerequisites

- **JDK 11 or newer** (no external libraries needed — pure Java standard library)

### Build

**Option A — plain `javac` (no Maven required):**

```bash
./build.sh
```

This compiles everything into `target/classes` and also packages a
runnable `target/dpi-engine.jar`.

**Option B — Maven:**

```bash
mvn package
# produces target/dpi-engine.jar
```

### Generate Test Data

```bash
java -cp target/classes com.dpi.tools.GenerateTestPcap test_dpi.pcap
```

This creates a synthetic capture containing TLS Client Hellos (YouTube,
Facebook, TikTok, Twitch, Instagram, Netflix, GitHub, WhatsApp, Google,
Wikipedia, example.com), plaintext HTTP requests, DNS queries, and a few
unclassifiable bare SYN packets — enough variety to exercise every code
path.

### Running

**Basic usage (multi-threaded engine, the default):**

```bash
java -jar target/dpi-engine.jar test_dpi.pcap output.pcap
```

**Single-threaded engine:**

```bash
java -jar target/dpi-engine.jar test_dpi.pcap output.pcap --simple
```

**With blocking rules:**

```bash
java -jar target/dpi-engine.jar test_dpi.pcap output.pcap \
    --block-app YouTube \
    --block-app TikTok \
    --block-ip 192.168.1.50 \
    --block-domain facebook
```

**Configure thread counts (multi-threaded only):**

```bash
java -jar target/dpi-engine.jar test_dpi.pcap output.pcap --lbs 4 --fps 8
# 4 Load Balancer threads feeding 8 Fast Path threads, plus 1 output writer
```

**Full option list:**

```bash
java -jar target/dpi-engine.jar --help
```

---

## 11. Understanding the Output

### Sample Output

```
╔════════════════════════════════════════════════════════════╗
║          DPI ENGINE v2.0 (Multi-threaded, Java)             ║
╠════════════════════════════════════════════════════════════╣
║ Load Balancers: 2    Fast Paths: 4                           ║
╚════════════════════════════════════════════════════════════╝

[Rules] Blocked app: YouTube
[Rules] Blocked IP: 192.168.1.50

[Reader] Processing packets...
[Reader] Done reading 42 packets

╔════════════════════════════════════════════════════════════╗
║               DPI ENGINE v2.0 (Multi-threaded)               ║
╠════════════════════════════════════════════════════════════╣
║ LBs: 2   FPs: 4                                               ║
╠════════════════════════════════════════════════════════════╣
║ Total Packets:                42                              ║
║ Total Bytes:                 6821                              ║
║ TCP Packets:                  38                              ║
║ UDP Packets:                   4                              ║
╠════════════════════════════════════════════════════════════╣
║ Forwarded:                    35                              ║
║ Dropped:                       7                              ║
╠════════════════════════════════════════════════════════════╣
║ THREAD STATISTICS                                             ║
║   FP0 processed:              12                              ║
║   FP1 processed:               9                              ║
║   FP2 processed:              11                              ║
║   FP3 processed:              10                              ║
║   LB0 dispatched:             22                               ║
║   LB1 dispatched:             20                               ║
╠════════════════════════════════════════════════════════════╣
║ APPLICATION BREAKDOWN                                         ║
╠════════════════════════════════════════════════════════════╣
║ HTTPS               14   33.3% #######                        ║
║ Unknown               9   21.4% ####                          ║
║ YouTube                4    9.5% ##  (BLOCKED)                ║
║ DNS                    4    9.5% ##                            ║
║ ...                                                            ║
╚════════════════════════════════════════════════════════════╝

[Detected Domains/SNIs]
  - www.youtube.com -> YouTube
  - www.facebook.com -> Facebook
  - www.google.com -> Google
  - github.com -> GitHub
  ...
```

### What Each Section Means

| Section               | Meaning                          |
|------------------------|-----------------------------------|
| Configuration          | Number of threads created        |
| Rules                  | Which blocking rules are active  |
| Total Packets          | Packets read from input file     |
| Forwarded              | Packets written to output file   |
| Dropped                | Packets blocked (not written)    |
| Thread Statistics      | Work distribution across threads |
| Application Breakdown  | Traffic classification results   |
| Detected SNIs          | Actual domain names found        |

---

## 12. Differences from the C++ Version

This is a faithful port, not a line-for-line translation. A few things were
adapted to fit Java idioms and to keep the codebase dependency-free:

- **Concurrency primitives**: `std::mutex` + `std::condition_variable` →
  `java.util.concurrent.locks.ReentrantLock` + `Condition`
  (`ThreadSafeQueue`); flow tables use `ConcurrentHashMap`.
- **Optional values**: `std::optional<std::string>` → `java.util.Optional<String>`.
  in `SNIExtractor` and `HTTPHostExtractor`.
  Java strings are always UTF-16 internally; hostnames are decoded as
  US-ASCII, which is what the TLS/HTTP specs require for SNI/Host values.
- **IP addresses**: represented as packed 32-bit `int`s (network byte
  order semantics preserved manually) rather than raw byte arrays, to keep
  `FiveTuple.equals()`/`hashCode()` cheap.
- **Hashing for load distribution**: uses `FiveTuple.hashCode()` combined
  with `Math.floorMod` instead of a custom C++ hash functor — functionally
  equivalent (deterministic, uniform enough for demo/production traffic
  distribution).
- **HTTP/2 and QUIC** are out of scope in both versions (see "Extending"
  below).
- Everything else — the algorithms, the pipeline architecture, the
  blocking semantics, the report format — is a direct translation.

---

## 13. Extending the Project

1. **Add More App Signatures**

   ```java
   // In AppTypeMapper.sniToAppType()
   if (sni.contains("twitch")) return AppType.TWITCH;
   ```

2. **Add Bandwidth Throttling**

   ```java
   if (shouldThrottle(flow)) {
       Thread.sleep(10);
   }
   ```

3. **Add a Live Statistics Dashboard**

   Spin up a daemon thread that calls `stats.printReport(...)` (or a
   lighter-weight summary) once per second while the engine runs.

4. **Add QUIC/HTTP-3 Support**

   QUIC runs over UDP on port 443; its SNI equivalent lives in the
   (differently-encrypted) Initial packet — would need its own extractor.

5. **Add Persistent Rules**

   Serialize `RuleManager`'s three sets to a properties/JSON file on exit,
   and load them back on startup.

---

## Summary

This DPI engine demonstrates:

1. **Network Protocol Parsing** — understanding raw packet structure
2. **Deep Packet Inspection** — looking inside "encrypted" connections via
   the plaintext TLS handshake
3. **Flow Tracking** — managing stateful connections with a five-tuple key
4. **Multi-threaded Architecture** — scaling with a Load-Balancer /
   Fast-Path thread pool and consistent hashing
5. **Producer-Consumer Pattern** — thread-safe blocking queues connecting
   pipeline stages

The key insight is that even HTTPS traffic leaks the destination domain in
the TLS handshake, allowing network operators to identify and control
application usage — this project shows exactly how, byte by byte.
=======
# DPI Engine (Java) – Deep Packet Inspection System

## Overview

This project is a **Deep Packet Inspection (DPI) Engine** developed in **Java** to analyze network traffic captured in PCAP files. The application inspects packet contents, identifies network protocols and applications, tracks network flows, and filters traffic based on configurable security rules.

The project demonstrates low-level networking concepts, protocol parsing, concurrent programming, and efficient packet processing using only the **Java Standard Library**, without any external dependencies.

---

## Key Features

- PCAP file parsing and processing
- Ethernet, IPv4, TCP, and UDP packet decoding
- TLS Client Hello inspection for SNI extraction
- HTTP Host header extraction
- Network flow tracking using Five-Tuple identification
- Application detection (YouTube, Facebook, GitHub, Netflix, WhatsApp, etc.)
- IP, domain, and application-based traffic blocking
- Single-threaded DPI engine
- High-performance multi-threaded processing pipeline
- Thread-safe producer-consumer architecture
- Packet filtering with output PCAP generation
- Detailed traffic statistics and reporting

---

## Technologies Used

- Java 11+
- Java Collections Framework
- ConcurrentHashMap
- ReentrantLock & Condition
- Multithreading
- PCAP File Processing
- TCP/IP Networking
- Git
- GitHub

---

## Project Architecture

```
Input PCAP
     │
     ▼
Packet Parser
     │
     ▼
Protocol Decoder
     │
     ▼
Flow Tracker
     │
     ▼
Application Detection
     │
     ▼
Rule Engine
     │
     ▼
Filtered Output PCAP
```

For improved performance, the project also includes a multi-threaded pipeline consisting of:

- Load Balancer Threads
- Fast Path Worker Threads
- Output Writer Thread

allowing packets to be processed concurrently while preserving connection state.

---

## What I Learned

Building this project helped me gain practical experience with:

- Computer Networking fundamentals
- TCP/IP protocol stack
- Deep Packet Inspection concepts
- TLS handshake and SNI extraction
- HTTP protocol analysis
- Packet parsing from raw binary data
- Stateful flow tracking
- Concurrent programming in Java
- Producer-Consumer design pattern
- Thread synchronization using locks and condition variables
- High-performance application design

---

## Future Improvements

- HTTP/3 and QUIC support
- IPv6 packet parsing
- Live packet capture support
- Web-based monitoring dashboard
- Advanced intrusion detection rules
- Performance optimization for very large captures

---

## Conclusion

This project showcases my understanding of network programming, protocol analysis, multithreading, and system design by implementing a complete Deep Packet Inspection engine capable of analyzing, classifying, and filtering network traffic efficiently.

It represents one of my strongest backend and networking projects and demonstrates my ability to build complex systems using core Java without relying on third-party libraries.
>>>>>>> f38c313fa2d53a8f9992e4b51ae43a5b45e46592
