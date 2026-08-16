# DPI Engine (Python) - Deep Packet Inspection System

A pure-Python (standard library only) Deep Packet Inspection engine that
reads PCAP captures, classifies network flows by application using
**TLS SNI** and **HTTP Host header** extraction, applies IP/app/domain
blocking rules, and writes the allowed traffic to a new PCAP file.

Ported from an original implemented to Python, with both a
**single-threaded** version (easy to read, good for learning) and a
**multi-threaded** version (Reader → Load Balancers → Fast Paths →
Writer pipeline, using consistent hashing so each flow always lands on
the same worker thread).

> Educational / research project. Runs entirely offline on `.pcap`
> capture files - it does not touch a live network interface.

---

## What is DPI?

**Deep Packet Inspection (DPI)** looks *inside* the payload of a
network packet, not just its headers. This project demonstrates the
classic technique used by firewalls, parental-control software, and
network operators to identify which website or app a connection is
for - even when that connection is HTTPS.

The trick: the **Server Name Indication (SNI)** field in a TLS
`Client Hello` is sent in **plaintext**, before encryption kicks in,
so the destination domain name is visible even on an encrypted
connection.

```
TLS Client Hello:
├── Version: TLS 1.2
├── Random: [32 bytes]
├── Cipher Suites: [list]
└── Extensions:
    └── SNI Extension:
        └── Server Name: "www.youtube.com"   ← extracted here
```

---

## Project layout

```
dpi_engine_python/
├── dpi/
│   ├── __init__.py
│   ├── types.py            # FiveTuple, AppType, Flow, sni_to_app_type()
│   ├── pcap_reader.py       # Minimal PCAP file reader
│   ├── pcap_writer.py       # Minimal PCAP file writer
│   ├── packet_parser.py     # Ethernet / IPv4 / TCP / UDP header parsing
│   ├── sni_extractor.py     # TLS SNI + HTTP Host extraction
│   └── rule_manager.py      # IP / app / domain blocking rules
├── main_simple.py           # ★ Single-threaded engine (CLI) ★
├── dpi_mt.py                 # ★ Multi-threaded engine (CLI) ★
├── generate_test_pcap.py    # Builds a synthetic test_dpi.pcap
├── dashboard.py              # Optional: Flask web dashboard
├── live_sniffer.py           # Optional: live capture via scapy
├── tests/                    # Optional: pytest unit tests
│   ├── test_sni_extractor.py
│   ├── test_packet_parser.py
│   └── test_types_and_rules.py
├── .github/workflows/tests.yml  # CI: runs tests on every push/PR
├── requirements-dev.txt      # pytest (for tests/)
├── requirements-dashboard.txt # flask (for dashboard.py)
├── requirements-live.txt     # scapy (for live_sniffer.py)
└── README.md
```

The **core engine** (everything above except the three "Optional"
entries) needs **zero** third-party dependencies - it's built entirely
on `struct`, `socket`, `threading`, and `queue` from the standard
library. See [Optional add-ons](#optional-add-ons) below for the
opt-in extras.

---

## How a packet flows through the engine

1. **Read** the next packet from the input PCAP (`pcap_reader.py`).
2. **Parse** Ethernet → IPv4 → TCP/UDP headers to get a five-tuple
   `(src_ip, dst_ip, src_port, dst_port, protocol)` (`packet_parser.py`).
3. **Look up (or create) the Flow** for that five-tuple - all packets
   of the same connection share state.
4. **Classify**: if this is the first payload-bearing packet on port
   443, try to extract the TLS SNI; on port 80, try the HTTP `Host:`
   header; map the result to an `AppType` (YouTube, Facebook, GitHub, …).
5. **Check rules**: is the source IP blocked? Is the app blocked? Does
   the SNI contain a blocked domain substring?
6. **Forward or drop**: once a flow is marked blocked, every
   subsequent packet on that flow is dropped too - DPI blocks at the
   *flow* level, not the *packet* level, since you can't know the app
   until you've seen the Client Hello.
7. **Report**: print packet/byte counts, forwarded/dropped totals, a
   per-app breakdown, and the list of detected domains.

### Multi-threaded pipeline (`dpi_mt.py`)

```
Reader Thread → hash(5-tuple) % num_lbs → Load Balancer Threads
                                              → hash(5-tuple) % num_fps
                                                 → Fast Path Threads (own flow table each)
                                                    → Output Queue
                                                       → Output Writer Thread
```

Consistent hashing guarantees every packet of a given connection is
routed to the *same* Load Balancer and the *same* Fast Path, so each
Fast Path thread can keep a private, lock-free flow table.

---

## Usage

### 1. Generate sample test data

```bash
python3 generate_test_pcap.py
# -> writes test_dpi.pcap (TLS handshakes to YouTube, Facebook, GitHub,
#    TikTok, Netflix, Instagram, WhatsApp, Google, plus HTTP and DNS)
```

### 2. Run the single-threaded engine

```bash
python3 main_simple.py test_dpi.pcap output.pcap \
    --block-app YouTube \
    --block-app TikTok \
    --block-ip 192.168.1.50 \
    --block-domain facebook
```

### 3. Run the multi-threaded engine

```bash
python3 dpi_mt.py test_dpi.pcap output.pcap --lbs 2 --fps 2 \
    --block-app YouTube --block-domain tiktok
# Creates 2 Load Balancer threads x 2 Fast Path threads = 4 workers
```

Both scripts accept any real PCAP file too - e.g. one exported from
Wireshark - not just the generated sample.

### Sample output

```
==================================================================
               DPI ENGINE (Python, single-threaded)
==================================================================
[Rules] Blocked IP: 192.168.1.50
[Rules] Blocked app: Youtube
[Rules] Blocked app: Tiktok
[Rules] Blocked domain: facebook

==================================================================
                      PROCESSING REPORT
==================================================================
Total Packets:   51
Total Bytes:     4581
TCP Packets:     50
UDP Packets:     1
------------------------------------------------------------------
Forwarded:       42
Dropped:         9
------------------------------------------------------------------
                    APPLICATION BREAKDOWN
------------------------------------------------------------------
Unknown         26   51.0% ##########
Youtube          3    5.9% # (BLOCKED)
Facebook         3    5.9% #
...
==================================================================

[Detected Domains/SNIs]
  - www.youtube.com -> Youtube
  - www.facebook.com -> Facebook
  ...
```

---

## Optional add-ons

The core engine (`main_simple.py`, `dpi_mt.py`, and everything in `dpi/`)
needs **zero** third-party packages. These three extras are each
self-contained and opt-in - install only what you want to try.

### 1. Unit tests + CI

```bash
pip install -r requirements-dev.txt
pytest -v
```

29 tests cover TLS SNI extraction, HTTP Host extraction, packet
parsing, app classification, and rule blocking. `.github/workflows/tests.yml`
runs the same suite automatically on every push/PR across Python
3.9 / 3.11 / 3.12, plus a smoke test that regenerates the sample PCAP
and runs the engine end-to-end.

### 2. Web dashboard

```bash
pip install -r requirements-dashboard.txt
python3 dashboard.py
# open http://127.0.0.1:5000
```

A single-file Flask app (`dashboard.py`) that:
- Analyzes the bundled `test_dpi.pcap`, or lets you upload your own
- Shows a live pie chart of the application breakdown (Chart.js)
- Lets you add/remove IP, app, and domain blocking rules from a form
  and see forwarded/dropped counts update immediately
- Exposes the same data as JSON at `GET /api/stats`

`dashboard.py` does not import from or modify `main_simple.py` /
`dpi_mt.py` - it only reuses the shared `dpi/` package, so the CLI
tools keep working exactly as before whether or not Flask is installed.

### 3. Live packet capture

```bash
pip install -r requirements-live.txt

# Linux/macOS (needs root for raw sockets):
sudo python3 live_sniffer.py --iface eth0 --block-app YouTube

# Windows (install Npcap first: https://npcap.com, run as Administrator):
python live_sniffer.py --iface "Wi-Fi" --block-domain tiktok
```

`live_sniffer.py` uses `scapy` to capture real traffic off a network
interface instead of reading a `.pcap` file, then feeds each raw
frame through the exact same `PacketParser` / `SNIExtractor` /
`RuleManager` classes used everywhere else in the project. It prints
each newly-classified flow and blocked connection live, and shows the
same summary report on Ctrl+C. If `scapy` isn't installed it prints a
clear message instead of crashing.

---

## Extending the project

- **Add more app signatures** — extend `_SNI_APP_PATTERNS` in `dpi/types.py`.
- **QUIC/HTTP3 support** — QUIC runs over UDP on port 443; its SNI is
  in the Initial packet, encrypted with a well-known key ("Initial
  Secrets"), which is a great next step for extending `sni_extractor.py`.
- **Bandwidth throttling** — instead of dropping, delay packets for a
  flow (`time.sleep`) to simulate throttling.
- **Persistent rules** — load/save `RuleManager` state to a JSON file.
- **Live capture** — swap `PcapReader` for a live-capture library
  (e.g. `scapy` or raw sockets) to DPI a live interface instead of a
  saved file.

---

## Why this project is a good portfolio piece

- Binary protocol parsing with Python's `struct` module (Ethernet,
  IPv4, TCP, UDP, TLS, DNS, HTTP - all hand-rolled, no `scapy`).
- Stateful flow tracking keyed by a five-tuple.
- A real multi-threaded producer/consumer pipeline with
  `threading` + `queue.Queue`, including consistent hashing for
  thread affinity.
- Practical security/networking concept (TLS SNI leakage) with a
  working, testable implementation end to end.
