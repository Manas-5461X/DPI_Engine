# DPI Engine - Deep Packet Inspection System


This document explains **everything** about this project - from basic networking concepts to the complete code architecture. After reading this, you should understand exactly how packets flow through the system without needing to read the code.

---

## Table of Contents

1. [What is DPI?](#1-what-is-dpi)
2. [Networking Background](#2-networking-background)
3. [Project Overview](#3-project-overview)
4. [File Structure](#4-file-structure)
5. [The Journey of a Packet (Simple Version)](#5-the-journey-of-a-packet-simple-version)
6. [The Journey of a Packet (Multi-processed Version)](#6-the-journey-of-a-packet-multi-processed-version)
7. [Deep Dive: Each Component](#7-deep-dive-each-component)
8. [How SNI Extraction Works](#8-how-sni-extraction-works)
9. [How Blocking Works](#9-how-blocking-works)
10. [Building and Running](#10-building-and-running)
11. [Understanding the Output](#11-understanding-the-output)

---

## 1. What is DPI?

**Deep Packet Inspection (DPI)** is a technology used to examine the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at packet headers (source/destination IP), DPI looks *inside* the packet payload.

### Real-World Uses:
- **ISPs**: Throttle or block certain applications (e.g., BitTorrent)
- **Enterprises**: Block social media on office networks
- **Parental Controls**: Block inappropriate websites
- **Security**: Detect malware or intrusion attempts

### What Our DPI Engine Does:
```
User Traffic (PCAP) → [DPI Engine] → Filtered Traffic (PCAP)
                           ↓
                    - Identifies apps (YouTube, Facebook, etc.)
                    - Blocks based on rules
                    - Generates reports
```

---

## 2. Networking Background

### The Network Stack (Layers)

When you visit a website, data travels through multiple "layers":

```
┌─────────────────────────────────────────────────────────┐
│ Layer 7: Application    │ HTTP, TLS, DNS               │
├─────────────────────────────────────────────────────────┤
│ Layer 4: Transport      │ TCP (reliable), UDP (fast)   │
├─────────────────────────────────────────────────────────┤
│ Layer 3: Network        │ IP addresses (routing)       │
├─────────────────────────────────────────────────────────┤
│ Layer 2: Data Link      │ MAC addresses (local network)│
└─────────────────────────────────────────────────────────┘
```

### A Packet's Structure

Every network packet is like a **Russian nesting doll** - headers wrapped inside headers:

```
┌──────────────────────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                                       │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ IP Header (20 bytes)                                         │ │
│ │ ┌──────────────────────────────────────────────────────────┐ │ │
│ │ │ TCP Header (20 bytes)                                    │ │ │
│ │ │ ┌──────────────────────────────────────────────────────┐ │ │ │
│ │ │ │ Payload (Application Data)                           │ │ │ │
│ │ │ │ e.g., TLS Client Hello with SNI                      │ │ │ │
│ │ │ └──────────────────────────────────────────────────────┘ │ │ │
│ │ └──────────────────────────────────────────────────────────┘ │ │
│ └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### The Five-Tuple

A **connection** (or "flow") is uniquely identified by 5 values:

| Field | Example | Purpose |
|-------|---------|---------|
| Source IP | 192.168.1.100 | Who is sending |
| Destination IP | 172.217.14.206 | Where it's going |
| Source Port | 54321 | Sender's application identifier |
| Destination Port | 443 | Service being accessed (443 = HTTPS) |
| Protocol | TCP (6) | TCP or UDP |

**Why is this important?** 
- All packets with the same 5-tuple belong to the same connection
- If we block one packet of a connection, we should block all of them
- This is how we "track" conversations between computers

### What is SNI?

**Server Name Indication (SNI)** is part of the TLS/HTTPS handshake. When you visit `https://www.youtube.com`:

1. Your browser sends a "Client Hello" message
2. This message includes the domain name in **plaintext** (not encrypted yet!)
3. The server uses this to know which certificate to send

```
TLS Client Hello:
├── Version: TLS 1.2
├── Random: [32 bytes]
├── Cipher Suites: [list]
└── Extensions:
    └── SNI Extension:
        └── Server Name: "www.youtube.com"  ← We extract THIS!
```

**This is the key to DPI**: Even though HTTPS is encrypted, the domain name is visible in the first packet!

---

## 3. Project Overview

### What This Project Does

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Wireshark   │     │ DPI Engine  │     │ Output      │
│ Capture     │ ──► │             │ ──► │ PCAP        │
│ (input.pcap)│     │ - Parse     │     │ (filtered)  │
└─────────────┘     │ - Classify  │     └─────────────┘
                    │ - Block     │
                    │ - Report    │
                    └─────────────┘
```

### Two Versions

| Version | File | Use Case |
|---------|------|----------|
| Simple (Single-threaded) | `src/dpi_simple.py` | Learning, small captures |
| Multi-processed | `src/dpi_mt.py` | Production, leveraging multiple CPU cores |

---

## 4. File Structure

```
packet_analyzer/
├── src/                        # Implementation files (Python)
│   ├── pcap_reader.py          # PCAP file handling
│   ├── packet_parser.py        # Protocol parsing
│   ├── sni_extractor.py        # SNI/Host extraction
│   ├── types.py                # Data structures (FiveTuple, AppType, etc.)
│   ├── dpi_simple.py           # ★ SIMPLE VERSION ★
│   ├── dpi_mt.py               # ★ MULTI-PROCESSED VERSION ★
│   └── __init__.py             # Python package marker
│
├── generate_test_pcap.py       # Creates test data
├── test_dpi.pcap               # Sample capture with various traffic
├── WINDOWS_SETUP.md            # Setup guide for Windows
└── README.md                   # This file!
```

---

## 5. The Journey of a Packet (Simple Version)

Let's trace a single packet through `dpi_simple.py`:

### Step 1: Read PCAP File

```python
reader = PcapReader()
reader.open("capture.pcap")
```

**What happens:**
1. Open the file in binary mode
2. Read the 24-byte global header (magic number, version, etc.)
3. Verify it's a valid PCAP file

**PCAP File Format:**
```
┌────────────────────────────┐
│ Global Header (24 bytes)   │  ← Read once at start
├────────────────────────────┤
│ Packet Header (16 bytes)   │  ← Timestamp, length
│ Packet Data (variable)     │  ← Actual network bytes
├────────────────────────────┤
│ Packet Header (16 bytes)   │
│ Packet Data (variable)     │
├────────────────────────────┤
│ ... more packets ...       │
└────────────────────────────┘
```

### Step 2: Read Each Packet

```python
while True:
    raw = reader.read_next_packet()
    if not raw: break
    # raw.data contains the packet bytes
    # raw.header contains timestamp and length
```

**What happens:**
1. Read 16-byte packet header
2. Read N bytes of packet data (N = header.incl_len)
3. Return false when no more packets

### Step 3: Parse Protocol Headers

```python
parsed = PacketParser.parse(raw)
```

**What happens (in packet_parser.py):**

```
raw.data bytes:
[0-13]   Ethernet Header
[14-33]  IP Header  
[34-53]  TCP Header
[54+]    Payload

After parsing:
parsed.src_mac  = "00:11:22:33:44:55"
parsed.dest_mac = "aa:bb:cc:dd:ee:ff"
parsed.src_ip   = "192.168.1.100"
parsed.dest_ip  = "172.217.14.206"
parsed.src_port = 54321
parsed.dest_port = 443
parsed.protocol = 6 (TCP)
parsed.has_tcp  = True
```

**Parsing the Ethernet Header (14 bytes):**
```
Bytes 0-5:   Destination MAC
Bytes 6-11:  Source MAC
Bytes 12-13: EtherType (0x0800 = IPv4)
```

**Parsing the IP Header (20+ bytes):**
```
Byte 0:      Version (4 bits) + Header Length (4 bits)
Byte 8:      TTL (Time To Live)
Byte 9:      Protocol (6=TCP, 17=UDP)
Bytes 12-15: Source IP
Bytes 16-19: Destination IP
```

**Parsing the TCP Header (20+ bytes):**
```
Bytes 0-1:   Source Port
Bytes 2-3:   Destination Port
Bytes 4-7:   Sequence Number
Bytes 8-11:  Acknowledgment Number
Byte 12:     Data Offset (header length)
Byte 13:     Flags (SYN, ACK, FIN, etc.)
```

### Step 4: Create Five-Tuple and Look Up Flow

```python
tuple_key = FiveTuple(
    src_ip=parsed.src_ip_int,
    dst_ip=parsed.dest_ip_int,
    src_port=parsed.src_port,
    dst_port=parsed.dest_port,
    protocol=parsed.protocol,
)

if tuple_key not in flows:
    flows[tuple_key] = Flow(tuple_key)

flow = flows[tuple_key]
```

**What happens:**
- The flow table is a hash map: `FiveTuple → Flow`
- If this 5-tuple exists, we get the existing flow
- If not, a new flow is created
- All packets with the same 5-tuple share the same flow

### Step 5: Extract SNI (Deep Packet Inspection)

```python
# For HTTPS traffic (port 443)
if flow.app_type == AppType.UNKNOWN and parsed.has_tcp and parsed.dest_port == 443:
    if parsed.payload_data:
        sni = SNIExtractor.extract(parsed.payload_data)
        if sni:
            flow.sni = sni
            flow.app_type = sni_to_app_type(sni)
```

**What happens (in sni_extractor.py):**

1. **Check if it's a TLS Client Hello:**
   ```
   Byte 0: Content Type = 0x16 (Handshake) ✓
   Byte 5: Handshake Type = 0x01 (Client Hello) ✓
   ```

2. **Navigate to Extensions:**
   ```
   Skip: Version, Random, Session ID, Cipher Suites, Compression
   ```

3. **Find SNI Extension (type 0x0000):**
   ```
   Extension Type: 0x0000 (SNI)
   Extension Length: N
   SNI List Length: M
   SNI Type: 0x00 (hostname)
   SNI Length: L
   SNI Value: "www.youtube.com"  ← FOUND!
   ```

4. **Map SNI to App Type:**
   ```python
   # In src/types.py
   if "youtube" in lower_sni:
       return AppType.YOUTUBE
   ```

### Step 6: Check Blocking Rules

```python
if not flow.blocked:
    flow.blocked = rules.is_blocked(tuple_key.src_ip, flow.app_type, flow.sni)
```

**What happens:**
```python
# Check IP blacklist
if src_ip in self.blocked_ips:
    return True

# Check app blacklist
if app in self.blocked_apps:
    return True

# Check domain blacklist (substring match)
for dom in self.blocked_domains:
    if dom in sni:
        return True

return False
```

### Step 7: Forward or Drop

```python
if flow.blocked:
    dropped += 1
else:
    forwarded += 1
    # Write packet to output file
    output.write(packet_header)
    output.write(packet_data)
```

### Step 8: Generate Report

After processing all packets:
```python
# Count apps
for tuple, flow in flows.items():
    app_stats[flow.app_type] += 1

# Print report
print("YouTube: 150 packets (15%)")
print("Facebook: 80 packets (8%)")
...
```

---

## 6. The Journey of a Packet (Multi-processed Version)

The multi-processed version (`src/dpi_mt.py`) adds **parallelism** for high performance:

### Architecture Overview

```
                    ┌─────────────────┐
                    │  Reader Process │
                    │  (reads PCAP)   │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │      hash(5-tuple) % 2      │
              ▼                             ▼
    ┌─────────────────┐           ┌─────────────────┐
    │  LB0 Process    │           │  LB1 Process    │
    │  (Load Balancer)│           │  (Load Balancer)│
    └────────┬────────┘           └────────┬────────┘
             │                             │
      ┌──────┴──────┐               ┌──────┴──────┐
      │hash % 2     │               │hash % 2     │
      ▼             ▼               ▼             ▼
┌──────────┐ ┌──────────┐   ┌──────────┐ ┌──────────┐
│FP0 Proc  │ │FP1 Proc  │   │FP2 Proc  │ │FP3 Proc  │
│(Fast Path)│ │(Fast Path)│   │(Fast Path)│ │(Fast Path)│
└─────┬────┘ └─────┬────┘   └─────┬────┘ └─────┬────┘
      │            │              │            │
      └────────────┴──────────────┴────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │   Output Queue        │
              └───────────┬───────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │  Output Writer Proc   │
              │  (writes to PCAP)     │
              └───────────────────────┘
```

### Why This Design?

1. **Load Balancers (LBs):** Distribute work across FPs
2. **Fast Paths (FPs):** Do the actual DPI processing
3. **Consistent Hashing:** Same 5-tuple always goes to same FP

**Why consistent hashing matters:**
```
Connection: 192.168.1.100:54321 → 142.250.185.206:443

Packet 1 (SYN):         hash → FP2
Packet 2 (SYN-ACK):     hash → FP2  (same process!)
Packet 3 (Client Hello): hash → FP2  (same process!)
Packet 4 (Data):        hash → FP2  (same process!)

All packets of this connection go to FP2.
FP2 can track the flow state correctly in its own memory.
```

### Detailed Flow

#### Step 1: Reader Process

```python
# Main loop in Reader process
while True:
    raw = reader.read_next_packet()
    if not raw: break
    
    pkt = create_packet_object(raw)
    lb_idx = hash(pkt.tuple) % num_lbs
    
    # Send to Load Balancer via Queue
    lb_queues[lb_idx].put(pkt)
```

#### Step 2: Load Balancer Process

```python
def lb_worker(input_queue, fp_queues):
    while True:
        pkt = input_queue.get()
        if pkt is None: break  # Shutdown signal
        
        fp_idx = hash(pkt.tuple) % num_fps
        fp_queues[fp_idx].put(pkt)
```

#### Step 3: Fast Path Process

```python
def fp_worker(input_queue, output_queue, rules):
    flows = {}  # Local flow table for this process
    while True:
        pkt = input_queue.get()
        if pkt is None: break
        
        flow = flows.setdefault(pkt.tuple, Flow(pkt.tuple))
        classify_flow(pkt, flow)
        
        if not rules.is_blocked(pkt.tuple.src_ip, flow.app_type, flow.sni):
            output_queue.put(pkt)
```

#### Step 4: Output Writer Process

```python
def writer_worker(output_queue, output_file):
    with PcapWriter(output_file) as writer:
        while True:
            pkt = output_queue.get()
            if pkt is None: break
            writer.write_packet(pkt)
```

---

## 7. Deep Dive: Each Component

### pcap_reader.py

**Purpose:** Read network captures saved by Wireshark

**Key Logic (using `struct`):**
```python
# Read Global Header
# 4sHHiIII = magic, version_maj, version_min, thiszone, sigfigs, snaplen, network
data = file.read(24)
global_header = struct.unpack('<IHHIIII', data)

# Read Packet Header
# IIII = ts_sec, ts_usec, incl_len, orig_len
header_data = file.read(16)
p_header = struct.unpack('<IIII', header_data)
```

### packet_parser.py

**Purpose:** Extract protocol fields from raw bytes

**Key function:**
```python
def parse(raw_packet):
    # 1. Parse Ethernet
    # 2. Parse IPv4 (extract protocol, IPs)
    # 3. Parse TCP or UDP (extract ports)
    # 4. Extract remaining payload
    return ParsedPacket(...)
```

**Important concepts:**

*Network Byte Order:* Network protocols use big-endian. Python's `struct` uses `>` for big-endian:
```python
# Unpack 2 bytes (16-bit port) at offset 34
src_port = struct.unpack('>H', data[34:36])[0]

# Unpack 4 bytes (32-bit sequence number) at offset 38
seq_num = struct.unpack('>I', data[38:42])[0]
```

### sni_extractor.py

**Purpose:** Extract domain names from TLS and HTTP

**For TLS (HTTPS):**
- Verify TLS record header (0x16)
- Verify Client Hello handshake (0x01)
- Skip variable-length fields (Session ID, Cipher Suites)
- Find SNI extension (type 0x0000)

**For HTTP:**
- Search for "Host: " string in the payload
- Extract value until the next newline

### types.py

**Purpose:** Define data structures used throughout

```python
@dataclass(frozen=True)
class FiveTuple:
    src_ip: int
    dst_ip: int
    src_port: int
    dst_port: int
    protocol: int

class AppType(Enum):
    UNKNOWN = 0
    HTTP = 1
    HTTPS = 2
    YOUTUBE = 3
    # ...
```

---

## 8. How SNI Extraction Works

### The TLS Handshake

When you visit `https://www.youtube.com`:

```
┌──────────┐                              ┌──────────┐
│  Browser │                              │  Server  │
└────┬─────┘                              └────┬─────┘
     │                                         │
     │ ──── Client Hello ─────────────────────►│
     │      (includes SNI: www.youtube.com)    │
     │                                         │
     │ ◄─── Server Hello ───────────────────── │
     │      (includes certificate)             │
     │                                         │
     │ ──── Key Exchange ─────────────────────►│
     │                                         │
     │ ◄═══ Encrypted Data ══════════════════► │
     │      (from here on, everything is       │
     │       encrypted - we can't see it)      │
```

**We can only extract SNI from the Client Hello!**

### Extraction Code (Simplified Python)

```python
def extract_sni(payload):
    if payload[0] != 0x16 or payload[5] != 0x01:
        return None  # Not a Client Hello
    
    offset = 43  # Skip to session ID
    session_len = payload[offset]
    offset += 1 + session_len
    
    cipher_len = int.from_bytes(payload[offset:offset+2], 'big')
    offset += 2 + cipher_len
    
    comp_len = payload[offset]
    offset += 1 + comp_len
    
    # Extensions...
    ext_total_len = int.from_bytes(payload[offset:offset+2], 'big')
    offset += 2
    
    # Loop through extensions to find type 0x0000 (SNI)
    # ...
```

---

## 9. How Blocking Works

### Rule Types

| Rule Type | Example | What it Blocks |
|-----------|---------|----------------|
| IP | `192.168.1.50` | All traffic from this source |
| App | `YouTube` | All YouTube connections |
| Domain | `tiktok` | Any SNI containing "tiktok" |

### The Blocking Flow

```
Packet arrives
      │
      ▼
┌─────────────────────────────────┐
│ Is source IP in blocked list?  │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Is app type in blocked list?   │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Does SNI match blocked domain? │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
            FORWARD
```

---

---

## 10. Building and Running

### Quick Start (Windows)

1.  **Open `run_analyzer.bat`** in a text editor (like Notepad).
2.  **Change the `INPUT_PCAP`** variable if you want to analyze your own capture:
    ```batch
    set INPUT_PCAP=your_file.pcap
    ```
3.  **Save and Double-click** the file to run the multi-processed analyzer automatically.

### Prerequisites

- **Python 3.8+**
- No external Python libraries needed (`multiprocessing` and `struct` are built-in)!

### Manual Method (Terminal)

If you prefer to use the Command Prompt or PowerShell directly, **you must first generate the test data** (if you don't already have a `.pcap` file):

**Step 1. Go to your project folder:**
```cmd
cd path/to/Packet_analyzer
```

**Step 2. Generate Test Traffic (Run once):**
```cmd
python generate_test_pcap.py
```

**Step 2. Run the Multi-processed version** (High performance):
```cmd
python -m src.dpi_mt test_dpi.pcap output.pcap
```

*(Optional)* **Run the Simple version** (For learning/debugging):
```cmd
python -m src.dpi_simple test_dpi.pcap output.pcap
```

---

### Advanced Blocking (Apps, IPs, Domains)

You can tell the analyzer to block specific traffic by adding "flags" to your command. 

**What you can block:**
*   **Applications (`--block-app`)**: `YouTube`, `Facebook`, `TikTok`, `WhatsApp`, `Instagram`, `Twitter`, `Netflix`, `Amazon`, `Microsoft`, `Apple`, `Telegram`, `Spotify`, `Zoom`, `Discord`, `GitHub`, `Cloudflare`, `Google`.
*   **IP Addresses (`--block-ip`)**: Any valid IPv4 address (e.g., `192.168.1.50`).
*   **Domains (`--block-domain`)**: Any substring (e.g., `tiktok`, `porn`, `google`). If a domain contains this word, it drops the packet.

**1. Block an Application:**
```cmd
python -m src.dpi_mt test_dpi.pcap output.pcap --block-app YouTube
```

**2. Block a specific IP address:**
```cmd
python -m src.dpi_mt test_dpi.pcap output.pcap --block-ip 192.168.1.50
```

**3. Block a Domain name:**
```cmd
python -m src.dpi_mt test_dpi.pcap output.pcap --block-domain tiktok
```

**4. Combine multiple rules:**
```cmd
python -m src.dpi_mt test_dpi.pcap output.pcap --block-app YouTube --block-ip 1.1.1.1 --block-domain porn
```

---

### The Easiest Advanced Way: `run_advanced.bat`

If you want a dedicated script where you can just "set and forget" your rules, use **`run_advanced.bat`**:

1.  Right-click **`run_advanced.bat`** and select **Edit**.
2.  Change the variables at the top of the file:
    ```batch
    set BLOCK_APP=YouTube
    set BLOCK_IP=192.168.1.50
    set BLOCK_DOMAIN=tiktok
    ```
3.  **Save and Double-click** the file. It will build the command for you and run the analysis with your rules.

---

### How to add rules to the standard `run_analyzer.bat`

If you prefer to keep using the standard script:
1.  Right-click **`run_analyzer.bat`** and select **Edit**.
2.  Find the line that starts with `python -m src.dpi_mt`.
3.  Add your blocking flags at the end of that line. For example:
    ```batch
    python -m src.dpi_mt %INPUT_PCAP% %OUTPUT_PCAP% --fps %WORKERS% --block-app YouTube
    ```
4.  Save and run!

---

### Creating Test Data

```bash
python generate_test_pcap.py
# Creates test_dpi.pcap with sample traffic
```

---

## 11. Understanding the Output

### Sample Output

```
╔══════════════════════════════════════════════════════════════╗
║              DPI ENGINE v2.0 (Multi-processed)                ║
╠══════════════════════════════════════════════════════════════╣
║ Load Balancers:  2    FPs per LB:  2    Total Processes: 5   ║
╚══════════════════════════════════════════════════════════════╝

[Rules] Blocked app: YouTube
[Rules] Blocked IP: 192.168.1.50

[Reader] Processing packets...
[Reader] Done reading 77 packets

╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                        ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:                77                              ║
║ Total Bytes:                5738                              ║
║ Forwarded:                    69                              ║
║ Dropped:                       8                              ║
╠══════════════════════════════════════════════════════════════╣
║ PROCESS STATISTICS                                            ║
║   LB0 dispatched:             53                              ║
║   LB1 dispatched:             24                              ║
║   FP0 processed:              53                              ║
║   ...                                                         ║
╚══════════════════════════════════════════════════════════════╝
```

---

## 12. Extending the Project

### Ideas for Improvement

1. **Add More App Signatures**
   ```python
   # In src/types.py
   if "twitch" in lower_sni:
       return AppType.TWITCH
   ```

2. **Add Bandwidth Throttling**
   ```python
   # Instead of DROP, delay packets slightly (concept)
   if should_throttle(flow):
       time.sleep(0.01)
   ```

3. **Add QUIC/HTTP3 Support**
   - QUIC uses UDP on port 443
   - SNI is in the Initial packet

---

## Summary

This DPI engine demonstrates:
1. **Network Protocol Parsing** - Understanding packet structure
2. **Deep Packet Inspection** - Looking inside encrypted connections
3. **Flow Tracking** - Managing stateful connections
4. **Multi-processed Architecture** - Scaling with Python's multiprocessing
5. **Producer-Consumer Pattern** - Synchronized queues

The key insight is that even HTTPS traffic leaks the destination domain in the TLS handshake, allowing network operators to identify and control application usage.

---

## Questions?

If you have questions about any part of this project, the code is well-commented and follows the same flow described in this document. Start with the simple version (`src/dpi_simple.py`) to understand the concepts, then move to the multi-processed version (`src/dpi_mt.py`) to see how parallelism is added.

Happy learning! 🚀
