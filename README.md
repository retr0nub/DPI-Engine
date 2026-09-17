# DPI Engine (Python)

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-pytest-informational.svg)](#testing)

A lightweight **Deep Packet Inspection (DPI)** engine for analyzing PCAP
files, tracking network flows, extracting application-level information,
classifying traffic, and applying configurable filtering rules.

The engine parses Ethernet/IPv4/TCP/UDP packets without Scapy, inspects
**TLS SNI, HTTP Host, and DNS queries**, maintains per-flow state, and
uses Python multiprocessing with flow affinity for parallel processing.

## Table of Contents
- [What is DPI](#WhatisDPI?)
- [Features](#features)
- [Architecture](#architecture)
- [Why DPI?](#why-dpi)
- [Five-Tuple Flow Tracking](#five-tuple-flow-tracking)
- [Deep Packet Inspection](#deep-packet-inspection)
- [Application Classification](#application-classification)
- [Filtering Rules](#filtering-rules)
- [Multiprocessing and Flow Affinity](#multiprocessing-and-flow-affinity)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Testing](#testing)
- [Output](#output)
- [Example Report](#example-report)
- [Defensive Parsing](#defensive-parsing)
- [Current Scope](#current-scope)
- [Limitations](#limitations)
- [Future Improvements](#future-improvements)
- [What This Project Demonstrates](#what-this-project-demonstrates)
- [Learning Path](#learning-path)
- [Contributing](#contributing)
- [License](#license)

## What is DPI?
Deep Packet Inspection (DPI) is a technology used to examine the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at packet headers (source/destination IP), DPI looks inside the packet payload.

Real-World Uses:
ISPs: Throttle or block certain applications (e.g., BitTorrent)
Enterprises: Block social media on office networks
Parental Controls: Block inappropriate websites
Security: Detect malware or intrusion attempts
What Our DPI Engine Does:
User Traffic (PCAP) → [DPI Engine] → Filtered Traffic (PCAP)
                           ↓
                    - Identifies apps (YouTube, Facebook, etc.)
                    - Blocks based on rules
                    - Generates reports

## Features

- PCAP packet reading and writing
- Manual parsing of Ethernet, IPv4, TCP, and UDP headers
- Five-tuple flow tracking
- TLS ClientHello SNI extraction
- HTTP `Host` extraction
- DNS query extraction
- Application classification using traffic signatures
- Filtering by:
  - Source IP
  - Application
  - Domain
  - Destination port
- Stateful flow-based blocking
- Multiprocessing for parallel packet processing
- Flow affinity so packets from the same five-tuple reach the same worker
- Per-worker flow state without shared flow locks
- Processing statistics and application breakdown
- Defensive handling of malformed and truncated packets
- Automated tests for parsers, extractors, PCAP I/O, and classification

## Architecture

```text
                         Input PCAP
                             │
                             ▼
                    ┌─────────────────┐
                    │   Main Process  │
                    │ Read + Parse    │
                    │ + Hash Dispatch │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
          Worker 0        Worker 1        Worker N
              │              │              │
              ▼              ▼              ▼
         Flow State     Flow State     Flow State
              │              │              │
              └──────────────┼──────────────┘
                             ▼
                    Classification
                             │
                             ▼
                       Rule Engine
                       ┌─────┴─────┐
                       ▼           ▼
                     DROP        ALLOW
                                   │
                                   ▼
                              Output PCAP
```

### Processing pipeline

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
Assign Flow to Worker
 │
 ▼
Inspect Application Data
 ├── TLS  → SNI
 ├── HTTP → Host
 └── DNS  → Query
 │
 ▼
Classify Traffic
 │
 ▼
Apply Filtering Rules
 ├── Block → Drop
 └── Allow → Forward
 │
 ▼
Output PCAP + Report
```

## Why DPI?

Traditional packet filtering can make decisions from metadata such as IP
addresses, ports, and protocols. DPI goes further by inspecting
available application-layer information inside packet payloads.

This makes it possible to identify traffic using signals such as:

- TLS SNI
- HTTP Host
- DNS query names
- Application signatures
- IP addresses
- Destination ports

> **Important:** DPI cannot always see application-layer information.
> Modern encrypted protocols, encrypted DNS, QUIC, and traffic where the
> relevant metadata is unavailable can limit classification.

## Five-Tuple Flow Tracking

A flow is identified using:

```text
Source IP
Destination IP
Source Port
Destination Port
Protocol
```

Example:

```text
192.168.1.100:54321
        │
        ▼
142.250.185.206:443
        │
        ▼
       TCP
```

The five-tuple is used as the flow key. Flow state can contain
information such as:

```text
Flow
 ├── Application
 ├── SNI / Domain
 ├── Classification
 └── Blocked / Allowed state
```

Once a flow is classified as blocked, subsequent packets belonging to
that flow can be rejected without repeatedly performing the same
classification work.

## Deep Packet Inspection

### TLS SNI

For TLS traffic, the engine attempts to inspect the ClientHello and
extract the Server Name Indication (SNI).

```text
TLS Record
    │
    ▼
Handshake
    │
    ▼
ClientHello
    │
    ▼
Extensions
    │
    ▼
SNI
    │
    ▼
www.example.com
```

The SNI extension type is `0x0000`.

SNI can provide a useful hostname-based signal for traffic
classification when it is present and accessible.

### HTTP Host

For HTTP traffic, the engine can inspect request headers:

```http
GET /index.html HTTP/1.1
Host: example.com
```

The detected hostname can then be used by the classifier and domain
rules.

### DNS

DNS requests can expose the hostname being queried:

```text
Query: www.example.com
```

The engine extracts the query name and can use it for traffic analysis
and classification.

## Application Classification

The classifier can use information such as:

```text
Destination IP
Destination Port
TLS SNI
HTTP Host
DNS Query
```

Example:

```text
www.youtube.com
       │
       ▼
    YouTube

github.com
    │
    ▼
   GitHub
```

If no known signature matches the observed traffic, the application can
remain `Unknown`.

## Filtering Rules

The engine supports multiple filtering criteria.

| Rule        | Example        | Purpose                              |
| ----------- | -------------- | ------------------------------------ |
| IP          | `192.168.1.50` | Block traffic from a source IP       |
| Application | `YouTube`      | Block classified application traffic |
| Domain      | `facebook`     | Block matching detected hostnames    |
| Port        | `443`          | Block traffic to a destination port  |

Rules are evaluated against the information available for the
packet/flow.

## Multiprocessing and Flow Affinity

The engine uses Python's `multiprocessing` rather than relying on
multiple threads for CPU-bound packet processing.

The five-tuple determines the worker:

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
Connection A → Worker 0
Connection B → Worker 2
Connection C → Worker 1
```

Packets from the same flow are consistently assigned to the same worker.
This allows each worker to maintain its own flow table and avoids
requiring shared flow state between workers.

## Project Structure

The main components are organized around separate responsibilities:

```text
.
├── main.py
├── generate_test_pcap.py
├── dpi/
│   ├── parser.py
│   ├── extractors.py
│   └── rules.py
└── tests/
```

The exact project structure may contain additional modules depending on
the current implementation.

### Responsibilities

| Component               | Responsibility                                      |
| ------------------------ | ---------------------------------------------------- |
| `main.py`                | Application entry point and processing orchestration |
| `dpi/parser.py`          | Ethernet/IPv4/TCP/UDP packet parsing                  |
| `dpi/extractors.py`      | TLS, HTTP, and DNS payload inspection                 |
| `dpi/rules.py`           | Filtering and blocking logic                          |
| `generate_test_pcap.py`  | Generates test PCAP traffic                           |
| `tests/`                 | Automated test suite                                  |

## Requirements

- Python 3
- No runtime third-party package is required for the core DPI engine.
- `pytest` is required only for running the automated test suite.

The core implementation relies on Python standard-library modules such
as:

```text
struct
multiprocessing
```

## Quick Start

### 1. Generate a test PCAP

```bash
python3 generate_test_pcap.py
```

This creates:

```text
test_dpi.pcap
```

### 2. Run the DPI engine

```bash
python3 main.py test_dpi.pcap out.pcap \
  --block-app YouTube \
  --block-ip 192.168.1.50
```

### 3. Available options

```text
--block-ip IP
    Block a source IP. Repeatable.

--block-app APP
    Block an application by name. Repeatable.

--block-domain DOMAIN
    Block using a substring match against the detected hostname. Repeatable.

--block-port PORT
    Block a destination port. Repeatable.

--workers N
    Number of worker processes. Default: 4.
```

Example:

```bash
python3 main.py input.pcap filtered.pcap \
  --block-domain youtube \
  --block-port 23 \
  --workers 4
```

## Testing

Install `pytest` if it is not already available:

```bash
pip install pytest
```

Run the test suite:

```bash
pytest tests/ -v
```

The tests cover areas including:

- TLS/HTTP/DNS extraction
- Truncated and malformed input
- PCAP reader/writer round-trip behavior
- Packet parsing
- Application classification
- Regression cases

Malformed or incomplete network data should be rejected safely rather
than causing parser crashes or out-of-bounds reads.

## Output

The engine writes packets that pass the filtering rules to the output
PCAP.

Conceptually:

```text
Input PCAP
    │
    ▼
  Process
    │
 ┌──┴──┐
 ▼     ▼
DROP   ALLOW
 │       │
 X       ▼
      Output PCAP
```

Processing statistics can include:

```text
Total packets
Forwarded packets
Dropped packets
TCP packets
UDP packets
Application classifications
Detected domains
Worker processing statistics
```

## Example Report

A report may contain information similar to:

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
    Unknown             280
```

The values above are illustrative; actual results depend on the input
PCAP.

## Defensive Parsing

Network captures should be treated as untrusted input.

Before reading a protocol field, the parser checks that enough bytes are
available:

```text
Enough data?
    │
 ┌──┴──┐
Yes    No
 │      │
 ▼      ▼
Parse  Reject / Skip
```

This is important because PCAP files can contain truncated, malformed,
or unexpected packets.

## Current Scope

The current implementation focuses on:

- PCAP-based traffic processing
- Ethernet parsing
- IPv4 parsing
- TCP parsing
- UDP parsing
- Five-tuple flow tracking
- TLS ClientHello inspection
- TLS SNI extraction
- HTTP Host extraction
- DNS query extraction
- Application classification
- IP-based filtering
- Application-based filtering
- Domain-based filtering
- Destination-port filtering
- Multiprocessing
- Flow affinity
- Per-worker flow state
- Packet statistics
- Defensive packet parsing
- Automated testing

## Limitations

### IPv4-focused

The current parser primarily targets IPv4 traffic. IPv6 support would
require additional packet parsing, flow handling, and rule support.

### QUIC / HTTP/3

QUIC traffic is not currently handled as a full application-layer
protocol.

Modern HTTPS traffic can use QUIC over UDP/443, so TLS-over-TCP
inspection alone does not provide complete visibility into modern HTTPS
traffic.

### Domain matching

Domain blocking currently uses substring matching against the detected
hostname.

For example:

```text
--block-domain face
```

could match:

```text
facecraft.io
```

A production-oriented implementation should use hostname-aware matching
and domain boundaries.

### Memory usage

The current ordering mechanism buffers forwarded packets before writing
them in original packet order. Very large PCAP files may therefore
require significant memory.

A streaming, order-preserving writer would improve scalability.

### Encrypted traffic

DPI does not automatically decrypt encrypted application payloads.
Classification depends on metadata that remains observable, such as SNI
when available.

## Future Improvements

Potential extensions include:

1. **IPv6 support**
   - IPv6 parsing
   - IPv6 flow tracking
   - IPv6 filtering rules
2. **QUIC / HTTP/3 support**
   - Better handling of UDP/443 traffic
   - QUIC-aware parsing
3. **Expanded application signatures**
   - More applications and domains
   - More robust signature matching
4. **Persistent rules**
   - Load rules from a configuration file such as `rules.json`
5. **Improved domain matching**
   - Exact hostname matching
   - Subdomain-aware matching
   - Domain-boundary validation
6. **Streaming output**
   - Reduce memory usage for large captures
   - Preserve packet order while streaming results
7. **Live statistics**
   - Packets processed
   - Packets forwarded/dropped
   - Active flows
   - Application counts
   - Worker utilization
8. **Performance benchmarking**
   - Packets per second
   - Processing latency
   - CPU utilization
   - Memory usage
   - Worker scaling

## What This Project Demonstrates

This project combines several software-engineering and systems concepts:

```text
Python
  +
Networking
  +
Binary Packet Parsing
  +
Protocol Inspection
  +
State Management
  +
Multiprocessing
  +
Inter-Process Communication
  +
Rule Evaluation
  +
Defensive Programming
  +
Automated Testing
```

It is particularly useful as a systems-oriented project because it deals
with raw binary data, network protocols, stateful processing, concurrent
execution, and malformed input rather than only implementing
application-level CRUD functionality.

## Learning Path

A useful order for understanding the implementation is:

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
6. TLS ClientHello
       ↓
7. SNI Extraction
       ↓
8. HTTP / DNS Inspection
       ↓
9. Application Classification
       ↓
10. Blocking Rules
       ↓
11. Multiprocessing
       ↓
12. Flow Affinity
       ↓
13. Testing
       ↓
14. Performance / Scalability
```

## Contributing

Contributions are welcome. If you'd like to help:

1. Fork the repository and create a feature branch.
2. Make your changes, following the existing code style.
3. Add or update tests under `tests/` as needed.
4. Run `pytest tests/ -v` and confirm everything passes.
5. Open a pull request describing the change and its motivation.

Please open an issue first for larger changes so the approach can be
discussed before significant work is done.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE)
file for details (add one to the repository if it isn't already present).

## Summary

The DPI Engine is a Python-based PCAP inspection and filtering system
that:

- Parses network packets manually
- Tracks flows using five-tuples
- Extracts TLS SNI, HTTP Host, and DNS query information
- Classifies application traffic
- Applies IP, application, domain, and port rules
- Uses multiprocessing with flow affinity
- Safely handles malformed and truncated input
- Produces a filtered output PCAP and processing statistics
- Includes automated tests

The core processing model is:

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
 Classify Traffic
        │
        ▼
Apply Filtering Rules
        │
   ┌────┴────┐
   ▼         ▼
Forward     Drop
   │
   ▼
Output PCAP
```
