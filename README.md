# DPI Engine (Python)

A deep packet inspection tool that reads a `.pcap` capture, classifies each
flow (TLS SNI / HTTP Host / DNS query), applies IP/app/domain/port blocking
rules, and writes the surviving traffic back out to a new `.pcap`.


## Quick start

```bash
python3 generate_test_pcap.py          # creates test_dpi.pcap
python3 main.py test_dpi.pcap out.pcap --block-app YouTube --block-ip 192.168.1.50
```

```
Options:
  --block-ip IP           Block a source IP (repeatable)
  --block-app APP         Block an app by name, e.g. YouTube (repeatable)
  --block-domain DOMAIN   Block by substring match on the detected hostname (repeatable)
  --block-port PORT       Block a destination port (repeatable)
  --workers N             Number of worker processes (default: 4)
```

No third-party dependencies — pcap parsing, TLS/HTTP/DNS extraction, and the
worker pool are all standard library (`struct`, `multiprocessing`).

## How it works

```
pcap file → [main process: read + parse + hash-dispatch] → worker pool → output pcap
                                                                  │
                                                     each worker owns its own
                                                     flow table (no shared locks) —
                                                     a five-tuple always hashes to
                                                     the same worker
```

1. **Read & parse** (main process) — pull packets from the pcap, parse
   Ethernet/IPv4/TCP/UDP headers by hand (`dpi/parser.py`), and hash each
   packet's five-tuple to pick a worker.
2. **Classify** (worker) — try TLS ClientHello SNI (port 443), then HTTP
   `Host:` header (port 80), then DNS query name (port 53), then fall back
   to a port-based guess. Every extractor bounds-checks each offset against
   the payload length before reading it (`dpi/extractors.py`).
3. **Apply rules** (worker) — block by source IP, classified app, domain
   substring, or port (`dpi/rules.py`).
4. **Report** — forwarded packets are written to the output pcap in
   original packet order; a text report summarizes totals, per-worker load,
   and the application breakdown.

## Tests

```bash
pip install pytest
pytest tests/ -v
```

20 tests covering the TLS/HTTP/DNS extractors (including truncated and
malformed input — they must return `None`, never raise or over-read), the
pcap reader/writer round-trip, the packet parser, and app classification
(including regression tests for the two bugs below).

## Known limitations

- **Ordering buffers forwarded packets in memory** before writing the
  output file, so very large captures (multi-GB) would need a streaming,
  order-preserving writer instead.
- **QUIC isn't handled.** Real QUIC SNI extraction requires decrypting the
  Initial packet's CRYPTO frame (RFC 9001) — worth doing properly rather
  than the pattern-matching heuristic the earlier version used.
- **Domain blocking is a plain substring match** against the detected
  hostname (matches the original engine's behavior) — a `--block-domain
  face` would also match `facecraft.io`. Fine for a lab tool, not for
  production.
---------------------------------------------------------------------------------
# DPI Engine — Deep Packet Inspection System

This document explains everything about this project - from basic networking concepts to the complete code architecture. After reading this, you should understand exactly how packets flow through the system without needing to read the code.

A Python-based Deep Packet Inspection (DPI) engine for analyzing network traffic captured in PCAP files.

The project parses packets, tracks network flows, extracts application-level information such as TLS SNI, HTTP Host, and DNS queries, classifies traffic, applies configurable blocking rules, and writes filtered traffic to an output PCAP.

The system also supports parallel packet processing using Python multiprocessing while preserving flow affinity so that packets belonging to the same connection can be processed by the same worker.

---

# Table of Contents

1. [What is DPI?](#1-what-is-dpi)
2. [Networking Background](#2-networking-background)
3. [Project Overview](#3-project-overview)
4. [Python Architecture](#4-python-architecture)
5. [The Journey of a Packet](#5-the-journey-of-a-packet)
6. [Parallel Processing Architecture](#6-parallel-processing-architecture)
7. [Deep Dive: Project Components](#7-deep-dive-project-components)
8. [How TLS SNI Extraction Works](#8-how-tls-sni-extraction-works)
9. [How Application Classification Works](#9-how-application-classification-works)
10. [How Blocking Works](#10-how-blocking-works)
11. [Flow Tracking](#11-flow-tracking)
12. [Testing and Error Handling](#12-testing-and-error-handling)
13. [Running the Project](#13-running-the-project)
14. [Understanding the Output](#14-understanding-the-output)
15. [Limitations and Future Improvements](#15-limitations-and-future-improvements)
16. [Summary](#16-summary)

---

# 1. What is DPI?

**Deep Packet Inspection (DPI)** is a technique used to inspect network traffic beyond basic packet headers.

A traditional firewall may primarily use information such as:

* Source IP
* Destination IP
* Source port
* Destination port
* Protocol

DPI goes deeper by inspecting packet payloads and application-layer information.

### Real-World Uses

DPI can be used for:

* Network monitoring
* Application identification
* Traffic filtering
* Security analysis
* Enterprise network controls
* Detecting suspicious traffic
* Network policy enforcement

### What This DPI Engine Does

```text
                Input PCAP
                    │
                    ▼
            ┌─────────────────┐
            │    DPI Engine   │
            │                 │
            │  Parse packets  │
            │       ↓         │
            │  Track flows    │
            │       ↓         │
            │ Inspect payload │
            │       ↓         │
            │ Classify traffic│
            │       ↓         │
            │ Apply rules     │
            └────────┬────────┘
                     │
              ┌──────┴──────┐
              ▼             ▼
           Forward        Drop
              │
              ▼
         Output PCAP
```

The engine can identify applications and domains from network traffic and apply rules to determine whether traffic should be forwarded or dropped.

---

# 2. Networking Background

To understand the DPI engine, it helps to understand how network packets are structured.

## 2.1 Network Layers

The project primarily works across several layers of the network stack:

```text
┌─────────────────────────────────────────────┐
│ Layer 7: Application                        │
│ HTTP, TLS, DNS                              │
├─────────────────────────────────────────────┤
│ Layer 4: Transport                          │
│ TCP, UDP                                    │
├─────────────────────────────────────────────┤
│ Layer 3: Network                            │
│ IPv4                                        │
├─────────────────────────────────────────────┤
│ Layer 2: Data Link                          │
│ Ethernet                                    │
└─────────────────────────────────────────────┘
```

The DPI engine starts with raw packet bytes and progressively extracts information from these layers.

---

## 2.2 Packet Structure

A packet can be viewed as nested headers:

```text
┌───────────────────────────────────────────────┐
│ Ethernet Header                               │
│                                               │
│  ┌─────────────────────────────────────────┐  │
│  │ IPv4 Header                             │  │
│  │                                         │  │
│  │  ┌───────────────────────────────────┐  │  │
│  │  │ TCP / UDP Header                  │  │  │
│  │  │                                   │  │  │
│  │  │  ┌─────────────────────────────┐  │  │  │
│  │  │  │ Application Payload         │  │  │  │
│  │  │  │ TLS / HTTP / DNS / etc.     │  │  │  │
│  │  │  └─────────────────────────────┘  │  │  │
│  │  └───────────────────────────────────┘  │  │
│  └─────────────────────────────────────────┘  │
└───────────────────────────────────────────────┘
```

The parser processes these layers in order.

---

# 3. Project Overview

The Python DPI engine follows this general pipeline:

```text
PCAP
 │
 ▼
Read Packet
 │
 ▼
Parse Ethernet
 │
 ▼
Parse IPv4
 │
 ▼
Parse TCP / UDP
 │
 ▼
Create Five-Tuple
 │
 ▼
Find / Create Flow
 │
 ▼
Inspect Application Data
 │
 ├── TLS → Extract SNI
 │
 ├── HTTP → Extract Host
 │
 └── DNS → Extract Query
 │
 ▼
Classify Application
 │
 ▼
Apply Blocking Rules
 │
 ├── Block → Drop
 │
 └── Allow → Forward
 │
 ▼
Output PCAP + Statistics
```

The project is implemented in Python and uses a modular architecture to separate packet parsing, protocol inspection, flow tracking, classification, rule processing, multiprocessing, and reporting.

---

# 4. Python Architecture

Unlike the original C++ implementation, the Python implementation uses Python modules, classes, dataclasses, enums, and multiprocessing components.

The main architectural idea is:

```text
                   PCAP Input
                       │
                       ▼
                ┌─────────────┐
                │ Packet Read │
                └──────┬──────┘
                       │
                       ▼
                Parse Packet
                       │
                       ▼
                 Five-Tuple
                       │
              ┌────────┴────────┐
              │                 │
              ▼                 ▼
          Worker 0           Worker N
              │                 │
              ▼                 ▼
        Flow State          Flow State
              │                 │
              └────────┬────────┘
                       │
                       ▼
                 Classification
                       │
                       ▼
                  Rule Check
                       │
                ┌──────┴──────┐
                ▼             ▼
             Forward        Drop
                │
                ▼
             Output
```

## Why multiprocessing?

Python has a Global Interpreter Lock (GIL), which limits CPU-bound execution when using multiple threads.

For CPU-intensive packet processing, the implementation therefore uses **multiple processes**.

Conceptually:

```text
Main Process
     │
     ├── Worker Process 0
     │
     ├── Worker Process 1
     │
     ├── Worker Process 2
     │
     └── Worker Process N
```

Each worker can process packets independently.

---

# 5. The Journey of a Packet

Let's follow a packet from the input PCAP to the final decision.

## Step 1 — Read the PCAP

The engine receives a PCAP file containing captured network packets.

Conceptually:

```text
input.pcap
    │
    ├── Packet 1
    ├── Packet 2
    ├── Packet 3
    └── ...
```

Each packet contains:

* Timestamp information
* Captured packet length
* Raw packet bytes

The reader extracts these packets so that they can be analyzed.

---

## Step 2 — Parse the Ethernet Header

The first layer contains Ethernet information.

Important fields include:

```text
Destination MAC
Source MAC
EtherType
```

For IPv4 traffic:

```text
EtherType = 0x0800
```

The parser uses this information to determine whether the packet contains an IPv4 network layer.

---

## Step 3 — Parse IPv4

The IPv4 header provides information such as:

```text
Source IP
Destination IP
Protocol
TTL
Header Length
```

The protocol field determines the transport protocol.

Common values:

```text
TCP = 6
UDP = 17
```

---

## Step 4 — Parse TCP or UDP

For TCP traffic, the parser extracts fields such as:

```text
Source Port
Destination Port
Sequence Number
Acknowledgment Number
Flags
Header Length
```

For UDP:

```text
Source Port
Destination Port
Length
```

This information is used to construct the flow identifier.

---

# 6. The Five-Tuple

A network flow is identified using five values:

| Field            | Example           |
| ---------------- | ----------------- |
| Source IP        | `192.168.1.100`   |
| Destination IP   | `142.250.185.206` |
| Source Port      | `54321`           |
| Destination Port | `443`             |
| Protocol         | `TCP`             |

Together:

```text
192.168.1.100:54321
        ↓
142.250.185.206:443
        ↓
TCP
```

This combination is called the **five-tuple**.

The five-tuple is important because packets belonging to the same connection need to share the same flow state.

---

# 7. Flow Tracking

The engine maintains state for network flows.

Conceptually:

```text
Five-Tuple
    │
    ▼
Flow State
    │
    ├── Application
    ├── SNI / Domain
    ├── Classification
    ├── Blocked / Allowed
    └── Other flow information
```

When a packet arrives:

```text
Does this five-tuple already exist?
       │
   ┌───┴───┐
   │       │
  Yes      No
   │       │
   ▼       ▼
Existing   Create
 Flow       Flow
```

This allows information discovered in one packet to be reused for subsequent packets.

For example:

```text
Packet 1 → TLS Client Hello
             │
             ▼
       SNI discovered
             │
             ▼
        Flow classified
             │
             ▼
        Flow marked blocked
             │
             ▼
Packet 2 → Same flow → DROP
Packet 3 → Same flow → DROP
```

---

# 8. Deep Packet Inspection

After the network headers have been parsed, the engine can inspect application-level payloads.

The implementation supports inspection of traffic such as:

* TLS
* HTTP
* DNS

The goal is to extract useful information from the payload rather than relying only on IP addresses and ports.

---

# 9. How TLS SNI Extraction Works

One of the important DPI features is extracting the **Server Name Indication (SNI)** from a TLS Client Hello.

When a client connects to a website using HTTPS, the initial TLS handshake can contain the hostname requested by the client.

For example:

```text
Client
   │
   │ TLS Client Hello
   │ SNI = www.youtube.com
   ▼
Server
```

The DPI engine inspects the Client Hello and attempts to extract:

```text
www.youtube.com
```

---

## TLS Client Hello

Conceptually:

```text
TLS Record
    │
    └── Handshake
          │
          └── Client Hello
                 │
                 ├── Version
                 ├── Random
                 ├── Session ID
                 ├── Cipher Suites
                 ├── Compression Methods
                 └── Extensions
                        │
                        └── SNI
                              │
                              └── www.youtube.com
```

The parser searches the TLS extensions for the SNI extension.

The relevant extension type is:

```text
0x0000
```

Once the hostname is found, it can be stored in the corresponding flow.

---

## Why SNI Matters

Even when the application data is encrypted, information exposed during the TLS handshake can provide a useful signal for traffic classification.

For example:

```text
SNI:
    www.youtube.com
         │
         ▼
Application:
    YouTube
```

This allows the DPI engine to classify traffic based on the hostname.

---

# 10. HTTP Host Extraction

For HTTP traffic, the engine can inspect HTTP request data.

A request may contain:

```text
GET /index.html HTTP/1.1
Host: example.com
```

The engine can extract:

```text
example.com
```

This hostname can then be used for application classification and domain-based rules.

---

# 11. DNS Inspection

DNS traffic can also provide application-level information.

A DNS request may contain:

```text
Query:
    www.example.com
```

The engine can extract the requested domain and include it in traffic analysis.

---

# 12. Application Classification

Once the engine obtains information such as:

* Destination IP
* Destination port
* TLS SNI
* HTTP Host
* DNS query

it can classify traffic.

Conceptually:

```text
www.youtube.com
       │
       ▼
   YouTube

www.facebook.com
       │
       ▼
   Facebook

github.com
       │
       ▼
    GitHub
```

The project uses application signatures/patterns to map observed domains to application categories.

If no matching signature is found:

```text
Unknown
```

---

# 13. How Blocking Works

The engine supports rule-based traffic filtering.

Typical rule categories include:

| Rule        | Example        | Purpose                         |
| ----------- | -------------- | ------------------------------- |
| IP          | `192.168.1.50` | Block traffic from an IP        |
| Application | `YouTube`      | Block an identified application |
| Domain      | `facebook`     | Block matching domains          |

The decision process is conceptually:

```text
Packet
  │
  ▼
Source IP blocked?
  │
 ┌┴──────────────┐
Yes              No
 │                │
 ▼                ▼
DROP          App blocked?
                  │
               ┌──┴──────┐
              Yes        No
               │          │
               ▼          ▼
             DROP     Domain blocked?
                           │
                       ┌───┴────┐
                      Yes       No
                       │         │
                       ▼         ▼
                     DROP     FORWARD
```

---

# 14. Flow-Based Blocking

The engine operates with flow state rather than treating every packet as completely independent.

Example:

```text
Packet 1
SYN
    ↓
No application information yet
    ↓
FORWARD

Packet 2
SYN-ACK
    ↓
FORWARD

Packet 3
Client Hello
    ↓
SNI = www.youtube.com
    ↓
Application = YouTube
    ↓
YouTube is blocked
    ↓
Flow marked BLOCKED

Packet 4
Same flow
    ↓
BLOCKED
    ↓
DROP

Packet 5
Same flow
    ↓
BLOCKED
    ↓
DROP
```

This prevents the engine from needing to rediscover the application's identity for every packet.

---

# 15. Parallel Processing Architecture

For larger packet captures, the project can distribute packet processing across multiple worker processes.

The important design principle is **flow affinity**.

A packet's five-tuple is used to determine its worker:

```text
Five-Tuple
    │
    ▼
Hash
    │
    ▼
Worker Index
    │
    ▼
Worker Process
```

For example:

```text
Connection A
    │
    └── hash → Worker 0

Connection B
    │
    └── hash → Worker 2

Connection C
    │
    └── hash → Worker 1
```

Packets belonging to the same connection are routed to the same worker.

This is important because flow state is maintained by the worker processing that flow.

---

## Why Flow Affinity Matters

Consider:

```text
Packet 1 → Worker 2
Packet 2 → Worker 2
Packet 3 → Worker 2
Packet 4 → Worker 2
```

All packets belong to the same five-tuple.

Worker 2 can therefore maintain:

```text
Flow State
    │
    ├── SNI
    ├── Application
    ├── Classification
    └── Blocked state
```

Without flow affinity, packets from the same connection could be distributed between different workers, making state management more difficult.

---

# 16. Inter-Process Communication

The multiprocessing architecture uses queues to move work between processes.

Conceptually:

```text
                Main Process
                     │
                     ▼
                Input Queue
                     │
       ┌─────────────┼─────────────┐
       ▼             ▼             ▼
   Worker 0       Worker 1       Worker 2
       │             │             │
       └─────────────┼─────────────┘
                     ▼
               Result Collection
                     │
                     ▼
                Output PCAP
```

The queue provides a way for the main process and workers to exchange packets/results without sharing the same in-memory flow state.

---

# 17. Per-Worker Flow State

Each worker maintains the state for the flows assigned to it.

Conceptually:

```text
Worker 0
 ├── Flow A
 ├── Flow D
 └── Flow F

Worker 1
 ├── Flow B
 └── Flow E

Worker 2
 ├── Flow C
 └── Flow G
```

This design reduces the need for multiple workers to modify the same flow object concurrently.

---

# 18. Packet Output

Packets that pass the filtering rules are forwarded to the output path.

```text
Input PCAP
    │
    ▼
Process
    │
 ┌──┴──┐
 │     │
DROP  ALLOW
 │     │
 X     ▼
      Output PCAP
```

Dropped packets are excluded from the filtered output.

The engine can also collect statistics about:

* Total packets
* Forwarded packets
* Dropped packets
* TCP packets
* UDP packets
* Application classifications
* Detected domains
* Worker processing

---

# 19. Testing and Error Handling

The Python implementation includes automated tests covering important parsing and inspection behavior.

Testing is particularly important for a packet parser because network data cannot always be assumed to be valid.

The test suite includes cases involving malformed or truncated packets.

Examples of situations the parser should handle safely include:

```text
Missing Ethernet header
        ↓
Invalid packet

Truncated IPv4 header
        ↓
Invalid packet

Truncated TCP header
        ↓
Invalid packet

Incomplete TLS data
        ↓
No SNI extracted
```

Instead of crashing, the parser should safely reject or skip invalid input.

This defensive behavior is important for processing real-world network captures.

---

# 20. Defensive Parsing

Network packet data should always be treated as untrusted input.

Before reading fields, the parser needs to ensure enough bytes are available.

Conceptually:

```text
Is enough data available?
       │
   ┌───┴───┐
  Yes      No
   │        │
   ▼        ▼
Parse     Reject
```

This prevents out-of-bounds access and makes the engine more robust when processing incomplete or malformed PCAP data.

---

# 21. Running the Project

The original README contains C++ compilation commands, so those commands should **not** be used for the Python implementation.

The Python project should be run using the Python entry point provided by the project.

Typical Python usage follows the pattern:

```bash
python3 <entry_point>.py <input.pcap> <output.pcap>
```

If the project is packaged as a Python module, the equivalent form can be:

```bash
python3 -m <package> <input.pcap> <output.pcap>
```

The exact command should match the project's actual entry-point file.

---

# 22. Generating Test Traffic

The project can use PCAP test data to validate packet parsing and DPI behavior.

A test PCAP can contain traffic such as:

```text
TCP
UDP
HTTP
HTTPS / TLS
DNS
```

This allows different components of the DPI engine to be tested independently.

---

# 23. Understanding the Processing Report

A processing report can summarize what happened during execution.

Conceptually:

```text
========================================
           DPI ENGINE REPORT
========================================

Total Packets:       1000
TCP Packets:          850
UDP Packets:          150

Forwarded:            920
Dropped:               80

Applications:
    HTTPS              600
    DNS                 80
    YouTube             40
    Facebook             25
    Unknown             255

Detected Domains:
    www.youtube.com
    www.facebook.com
    github.com
    www.google.com
```

---

# 24. Application Statistics

Application statistics help understand what type of traffic was present in the capture.

For example:

```text
Application        Packets
---------------------------
HTTPS                 600
DNS                    80
YouTube                40
Facebook               25
Unknown               255
```

These statistics are useful for debugging, traffic analysis, and demonstrating the effectiveness of the classification logic.

---

# 25. Worker Statistics

The multiprocessing architecture can also provide information about worker utilization.

Conceptually:

```text
Worker 0 → 350 packets
Worker 1 → 320 packets
Worker 2 → 330 packets
```

This provides visibility into how packet-processing work is distributed.

---

# 26. Project Design Principles

The project is built around several important software engineering principles.

## Separation of Responsibilities

Different components handle different responsibilities:

```text
PCAP Reading
     │
     ▼
Packet Parsing
     │
     ▼
Protocol Inspection
     │
     ▼
Flow Tracking
     │
     ▼
Classification
     │
     ▼
Rule Processing
     │
     ▼
Output / Reporting
```

This makes individual components easier to understand and test.

---

## Stateful Processing

The engine does not treat every packet as completely independent.

Instead:

```text
Packet
  ↓
Five-Tuple
  ↓
Flow
  ↓
Flow State
```

This allows information discovered earlier in a connection to influence later packets.

---

## Parallelism

The project uses multiprocessing to allow multiple workers to process traffic in parallel.

```text
Input
  │
  ├──── Worker 1
  ├──── Worker 2
  ├──── Worker 3
  └──── Worker N
```

Flow affinity ensures packets belonging to the same connection remain associated with the same worker.

---

# 27. Current Scope

The project currently focuses on:

* PCAP-based traffic processing
* Ethernet parsing
* IPv4 parsing
* TCP parsing
* UDP parsing
* Five-tuple flow tracking
* TLS Client Hello inspection
* TLS SNI extraction
* HTTP Host extraction
* DNS query extraction
* Application classification
* IP-based filtering
* Application-based filtering
* Domain-based filtering
* Multiprocessing
* Worker-based flow affinity
* Per-worker flow state
* Packet statistics
* Defensive handling of malformed packets
* Automated testing

---

# 28. Limitations

The current implementation has several areas that can be improved.

### IPv6

The current implementation primarily focuses on IPv4 traffic.

Future work could add:

```text
IPv6 packet parsing
IPv6 flow tracking
IPv6 rule support
```

### Application Signatures

Application classification currently relies on identifiable traffic information such as domains and signatures.

A larger signature database could improve classification coverage.

### Domain Matching

Domain-based rules can be improved from simple substring matching to proper hostname/domain-boundary matching.

For example:

```text
youtube.com
```

should match appropriate subdomains without accidentally matching unrelated domains containing the same string.

### QUIC / HTTP/3

Modern HTTPS traffic increasingly uses QUIC over UDP.

Future work could include:

```text
UDP 443
   ↓
QUIC
   ↓
HTTP/3
```

The original project identifies QUIC/HTTP3 support as a future extension.

---

# 29. Future Improvements

Possible extensions include:

## 1. More Application Signatures

Add additional recognizable domains and traffic signatures.

```text
Netflix
Twitch
Spotify
Discord
Amazon
Microsoft
...
```

---

## 2. IPv6 Support

Extend packet parsing and flow tracking to IPv6.

---

## 3. QUIC / HTTP3 Inspection

Support modern encrypted traffic transported over UDP.

---

## 4. Persistent Rules

Instead of specifying rules every time the application runs:

```text
rules.json
```

could store:

```text
Blocked IPs
Blocked Domains
Blocked Applications
```

The engine could load these rules during startup.

---

## 5. Live Statistics

A future version could periodically display:

```text
Packets processed
Packets dropped
Packets forwarded
Current flows
Applications detected
Worker utilization
```

The original README also proposes live statistics as a future extension.

---

## 6. Performance Benchmarking

Future testing could measure:

```text
Packets / second
Processing time
CPU utilization
Memory usage
Worker scaling
```

This would make it easier to evaluate how performance changes as the number of worker processes increases.

---

## 7. Streaming Output

The processing pipeline can be further optimized so that packets do not need to remain buffered unnecessarily before being written.

This can reduce memory usage when processing large PCAP files.

---

# 30. Why This Project Is Interesting

This project combines several areas of software engineering:

```text
Python
   +
Networking
   +
Packet Parsing
   +
State Management
   +
Concurrency / Multiprocessing
   +
Inter-Process Communication
   +
Testing
   +
System Design
```

It demonstrates more than a simple Python application because the program has to deal with:

* Binary packet data
* Network protocols
* Stateful connections
* Encrypted application traffic
* Parallel processing
* Inter-process communication
* Rule evaluation
* Error handling
* Performance considerations

---

# 31. Summary

This Python DPI engine demonstrates:

1. **Network Protocol Parsing**
   Extracting information from Ethernet, IPv4, TCP, and UDP packets.

2. **Deep Packet Inspection**
   Inspecting application-layer payloads such as TLS, HTTP, and DNS.

3. **TLS SNI Extraction**
   Extracting hostnames from TLS Client Hello messages when available.

4. **Application Classification**
   Mapping observed domains and protocol information to application types.

5. **Flow Tracking**
   Using five-tuples to maintain state across packets belonging to the same connection.

6. **Rule-Based Filtering**
   Blocking traffic based on IP addresses, applications, and domains.

7. **Multiprocessing**
   Using multiple worker processes for parallel packet processing.

8. **Flow Affinity**
   Keeping packets from the same connection associated with the same worker.

9. **Defensive Parsing**
   Handling malformed and truncated network packets safely.

10. **Automated Testing**
    Verifying parser and inspection behavior with test cases.

The central idea of the project is:

```text
Raw Network Traffic
        │
        ▼
    Parse Packets
        │
        ▼
    Identify Flows
        │
        ▼
 Inspect Application Data
        │
        ▼
 Classify the Traffic
        │
        ▼
 Apply Filtering Rules
        │
        ├───────────┐
        ▼           ▼
     Forward       Drop
        │
        ▼
    Output PCAP
```

The project therefore serves as a practical demonstration of how networking, packet processing, stateful systems, multiprocessing, and software testing can be combined into a single Python-based systems project.

---

# 32. Learning Path

A good way to understand the project is to study it in this order:

```text
1. Networking basics
       ↓
2. Ethernet / IPv4
       ↓
3. TCP / UDP
       ↓
4. Five-Tuple
       ↓
5. Flow Tracking
       ↓
6. TLS Client Hello
       ↓
7. SNI Extraction
       ↓
8. Application Classification
       ↓
9. Blocking Rules
       ↓
10. Multiprocessing
       ↓
11. Flow Affinity
       ↓
12. Testing
       ↓
13. Performance / Scalability
```

Once these concepts are understood, the complete packet-processing pipeline becomes much easier to follow.
