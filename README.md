# DPI Engine (Python) - Deep Packet Inspection System

A pure-Python Deep Packet Inspection (DPI) engine that reads PCAP
network captures, analyzes network flows, identifies applications using
TLS SNI and HTTP Host headers, applies configurable blocking rules, and
writes allowed traffic to a new PCAP file.

The project includes both a **single-threaded engine** for simplicity and
learning and a **multi-threaded engine** designed around a scalable
Reader → Load Balancer → Fast Path → Writer pipeline.

> Educational / research project. The core engine works offline on
> `.pcap` capture files and does not directly interact with a live
> network interface.

---

## What is DPI?

**Deep Packet Inspection (DPI)** is a network analysis technique that
examines packet headers and payload data to understand network traffic.

DPI can be used by:

- Network security systems
- Firewalls
- Parental-control software
- Network monitoring tools
- Traffic filtering systems

This project demonstrates how network traffic can be analyzed to identify
applications and domains and then apply configurable rules to allow or
block specific traffic.

### TLS SNI Detection

For HTTPS connections, the **Server Name Indication (SNI)** field in the
TLS Client Hello can reveal the destination hostname before encrypted
application data is exchanged.

For example:

```text
TLS Client Hello
├── Version
├── Random
├── Cipher Suites
└── Extensions
    └── SNI
        └── Server Name: "www.youtube.com"
Key Features
🔍 Deep Packet Inspection

The engine parses network packets at multiple protocol layers:

Ethernet
IPv4
TCP
UDP
TLS
HTTP
DNS

The packet parser is implemented using Python's standard library.

🌐 Application Classification

The engine can identify applications using domain information obtained
from TLS SNI and HTTP Host headers.

Example applications include:

YouTube
Facebook
TikTok
Netflix
Instagram
WhatsApp
GitHub
Google

Application signatures can be extended through the application-pattern
configuration.

🚫 Flexible Blocking Rules

The Rule Manager supports blocking based on:

Source IP address
Application
Domain name

Example:

Block IP      → 192.168.1.50
Block App     → YouTube
Block Domain  → facebook

Once a network flow is identified as blocked, subsequent packets belonging
to that flow are also dropped.

📦 PCAP Processing

The engine can:

Read packets from a PCAP file.
Parse packet headers.
Track network flows.
Identify applications.
Apply blocking rules.
Forward allowed packets.
Write the resulting traffic to another PCAP file.
Project Architecture
                    Input PCAP
                        │
                        ▼
                 ┌──────────────┐
                 │ PCAP Reader  │
                 └──────┬───────┘
                        │
                        ▼
                 ┌──────────────┐
                 │Packet Parser │
                 └──────┬───────┘
                        │
                        ▼
                 ┌──────────────┐
                 │ Flow Tracking│
                 └──────┬───────┘
                        │
                        ▼
                 ┌──────────────┐
                 │ SNI / HTTP   │
                 │ Classification│
                 └──────┬───────┘
                        │
                        ▼
                 ┌──────────────┐
                 │ Rule Manager │
                 └──────┬───────┘
                        │
                 ┌──────┴───────┐
                 │              │
              ALLOWED         BLOCKED
                 │              │
                 ▼              ▼
          Output PCAP          DROP
Project Structure
dpi_engine_python/
│
├── dpi/
│   ├── __init__.py
│   ├── types.py
│   ├── pcap_reader.py
│   ├── pcap_writer.py
│   ├── packet_parser.py
│   ├── sni_extractor.py
│   └── rule_manager.py
│
├── main_simple.py
├── dpi_mt.py
├── generate_test_pcap.py
├── dashboard.py
├── live_sniffer.py
│
├── tests/
│   ├── test_sni_extractor.py
│   ├── test_packet_parser.py
│   └── test_types_and_rules.py
│
├── .github/
│   └── workflows/
│       └── tests.yml
│
├── requirements-dev.txt
├── requirements-dashboard.txt
├── requirements-live.txt
└── README.md
Core Components
1. PCAP Reader

pcap_reader.py

Reads packets from a PCAP file and provides the raw packet data and
timestamps to the processing engine.

2. Packet Parser

packet_parser.py

Parses network packets layer by layer:

Ethernet
   ↓
IPv4
   ↓
TCP / UDP
   ↓
Application Payload

The parser extracts information such as:

Source IP
Destination IP
Source Port
Destination Port
Protocol
Payload
3. Flow Tracking

Network packets are grouped into flows using a five-tuple:

(Source IP,
 Destination IP,
 Source Port,
 Destination Port,
 Protocol)

This allows the engine to maintain state for each network connection.

4. SNI and HTTP Host Extraction

sni_extractor.py

The engine analyzes application-layer information to identify domains.

For HTTPS traffic:

TLS Client Hello
       ↓
SNI Extraction
       ↓
Domain Name
       ↓
Application Classification

For HTTP traffic:

HTTP Request
       ↓
Host Header
       ↓
Domain Name
       ↓
Application Classification
5. Application Classification

types.py

The extracted domain is mapped to an application category.

Example:

www.youtube.com
        ↓
     YouTube

The application mapping can be extended by adding additional domain
patterns.

6. Rule Manager

rule_manager.py

Responsible for applying traffic filtering rules.

Supported rule types:

IP Blocking
Application Blocking
Domain Blocking

Example:

--block-app YouTube
--block-ip 192.168.1.50
--block-domain facebook
Single-Threaded Engine

The main implementation is available in:

main_simple.py

It processes packets sequentially:

PCAP
 ↓
Reader
 ↓
Parser
 ↓
Flow Tracking
 ↓
Classification
 ↓
Rule Check
 ↓
Allow / Drop
 ↓
Output PCAP

This version is intentionally simple and easy to understand, making it
useful for learning and debugging the DPI pipeline.

Multi-Threaded Engine

The multi-threaded implementation is available in:

dpi_mt.py

It uses a producer-consumer architecture:

                ┌─────────────┐
                │    Reader   │
                └──────┬──────┘
                       │
                       ▼
              ┌─────────────────┐
              │ Load Balancers  │
              └────────┬────────┘
                       │
                       ▼
                ┌─────────────┐
                │ Fast Paths  │
                └──────┬──────┘
                       │
                       ▼
                ┌─────────────┐
                │ Output Queue│
                └──────┬──────┘
                       │
                       ▼
                ┌─────────────┐
                │    Writer   │
                └─────────────┘

Consistent hashing is used to ensure that packets belonging to the same
network flow are routed to the same processing worker.

This allows each worker to maintain its own flow state while reducing
unnecessary synchronization.

Packet Processing Flow

The complete processing pipeline is:

1. Read packet
       ↓
2. Parse Ethernet header
       ↓
3. Parse IPv4 header
       ↓
4. Identify TCP / UDP
       ↓
5. Build flow five-tuple
       ↓
6. Track flow state
       ↓
7. Extract TLS SNI / HTTP Host
       ↓
8. Identify application
       ↓
9. Apply blocking rules
       ↓
10. Forward or drop packet
       ↓
11. Generate processing statistics
       ↓
12. Write allowed packets to output PCAP
Usage
1. Generate Test PCAP

Generate a synthetic PCAP file for testing:

python generate_test_pcap.py

This creates:

test_dpi.pcap

The generated traffic contains example TLS, HTTP and DNS packets for
multiple applications and domains.

2. Run Single-Threaded DPI Engine
python main_simple.py test_dpi.pcap output.pcap \
    --block-app YouTube \
    --block-app TikTok \
    --block-ip 192.168.1.50 \
    --block-domain facebook

The engine will analyze the input PCAP and write allowed packets to:

output.pcap
3. Run Multi-Threaded DPI Engine
python dpi_mt.py test_dpi.pcap output.pcap \
    --lbs 2 \
    --fps 2 \
    --block-app YouTube \
    --block-domain tiktok

Here:

2 Load Balancer threads
        ×
2 Fast Path threads
        =
4 processing workers
Example Processing Report
==================================================================
               DPI ENGINE (Python, single-threaded)
==================================================================


[Rules] Blocked IP: 192.168.1.50
[Rules] Blocked app: YouTube
[Rules] Blocked app: TikTok
[Rules] Blocked domain: facebook


==================================================================
                      PROCESSING REPORT
==================================================================


Total Packets:   51
Total Bytes:     4581
TCP Packets:     50
UDP Packets:      1


------------------------------------------------------------------
Forwarded:       42
Dropped:          9
------------------------------------------------------------------


                    APPLICATION BREAKDOWN
------------------------------------------------------------------


Unknown          26   51.0%
YouTube           3    5.9%  (BLOCKED)
Facebook          3    5.9%
TikTok            3    5.9%  (BLOCKED)


==================================================================


[Detected Domains / SNIs]


- www.youtube.com  -> YouTube
- www.facebook.com -> Facebook
- www.tiktok.com    -> TikTok
Testing

The project includes automated unit tests covering:

TLS SNI extraction
HTTP Host extraction
Packet parsing
Application classification
Rule management
Flow processing

Run the tests using:

pip install -r requirements-dev.txt
pytest -v

The project also includes a GitHub Actions workflow that automatically
runs the test suite when changes are pushed to the repository.

Optional Web Dashboard

The project includes an optional Flask dashboard.

Install the dashboard dependencies:

pip install -r requirements-dashboard.txt

Run:

python dashboard.py

The dashboard provides:

PCAP analysis
Application statistics
Traffic breakdown
Blocking rules
Forwarded packet count
Dropped packet count
JSON statistics API

The dashboard can be used as a visual interface for understanding the
DPI processing results.

Optional Live Packet Capture

The project also includes an optional live capture module:

live_sniffer.py

It uses Scapy to capture traffic from a network interface.

Install the required dependency:

pip install -r requirements-live.txt

Example:

python live_sniffer.py --iface "Wi-Fi" --block-domain tiktok

Live packet capture may require administrator/root privileges depending
on the operating system and network capture configuration.

Security and Privacy

This project is designed primarily for educational, research and
authorized network-analysis purposes.

The core implementation processes saved PCAP files locally and does not
send captured data to external services.

When using live packet capture, only analyze traffic on networks and
devices where you have appropriate authorization.

Future Improvements

Possible extensions include:

QUIC / HTTP3 Support

Add support for modern UDP-based HTTPS traffic and QUIC Initial packets.

Bandwidth Throttling

Instead of dropping blocked traffic, introduce controlled delays to
simulate bandwidth restrictions.

Persistent Rules

Store IP, application and domain rules in a JSON configuration file.

Improved Application Detection

Expand the application signature database with additional domains and
protocol patterns.

Advanced Dashboard

Add:

Real-time traffic graphs
Flow statistics
Top applications
Top domains
Protocol distribution
Blocking history
Technologies Used
Python
Python Standard Library
PCAP
TCP/IP
TLS
HTTP
DNS
Multithreading
Producer-Consumer Architecture
Consistent Hashing
GitHub Actions
Flask (Optional)
Scapy (Optional)
Why This Project?

This project demonstrates practical understanding of:

Network packet processing
TCP/IP networking
Protocol parsing
TLS SNI analysis
HTTP Host extraction
Stateful flow tracking
Traffic classification
Rule-based network filtering
Multi-threaded processing
Producer-consumer architecture
Consistent hashing
Automated testing
CI/CD with GitHub Actions

It combines networking, cybersecurity, Python programming and
system-level processing into a single practical project.

Author

Sakshi Kaushal

GitHub: sakshikaushal09



### 🔥 Bas ek important baat


Maine **"original C++ implementation" completely remove** kar diya hai.


Ab README mein project ko:
- ❌ copied/ported project jaisa nahi dikhaya
- ✅ Python DPI project ke form mein present kiya
- ✅ architecture clearly explain kiya
- ✅ cybersecurity/networking skills highlight ki
- ✅ testing + GitHub Actions bhi highlight kiya
- ✅ future improvements bhi add kiye
- ✅ security/privacy note bhi add kiya


**Ab pura old README → Ctrl+A → Delete → ye wala pura paste → Commit changes.**
