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
