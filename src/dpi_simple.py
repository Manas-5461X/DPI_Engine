import sys
import collections
from typing import Dict, Set

from .types import FiveTuple, AppType, sni_to_app_type
from .pcap_reader import PcapReader
from .packet_parser import PacketParser
from .sni_extractor import SNIExtractor, HTTPHostExtractor


class Flow:
    def __init__(self, tuple: FiveTuple):
        self.tuple = tuple
        self.app_type = AppType.UNKNOWN
        self.sni = ""
        self.packets = 0
        self.bytes = 0
        self.blocked = False


class BlockingRules:
    def __init__(self):
        self.blocked_ips: Set[int] = set()
        self.blocked_apps: Set[AppType] = set()
        self.blocked_domains: list[str] = []

    def block_ip(self, ip: str):
        addr = BlockingRules.parse_ip(ip)
        self.blocked_ips.add(addr)
        print(f"[Rules] Blocked IP: {ip}")

    def block_app(self, app_str: str):
        app_str_lower = app_str.lower()
        for app in AppType:
            if str(app).lower() == app_str_lower or app.name.lower() == app_str_lower:
                self.blocked_apps.add(app)
                print(f"[Rules] Blocked app: {str(app)}")
                return
        print(f"[Rules] Unknown app: {app_str}", file=sys.stderr)

    def block_domain(self, domain: str):
        self.blocked_domains.append(domain)
        print(f"[Rules] Blocked domain: {domain}")

    def is_blocked(self, src_ip: int, app: AppType, sni: str) -> bool:
        if src_ip in self.blocked_ips:
            return True
        if app in self.blocked_apps:
            return True
        for dom in self.blocked_domains:
            if dom in sni:
                return True
        return False

    @staticmethod
    def parse_ip(ip: str) -> int:
        parts = ip.split(".")
        if len(parts) != 4:
            return 0
        try:
            return (
                int(parts[0])
                | (int(parts[1]) << 8)
                | (int(parts[2]) << 16)
                | (int(parts[3]) << 24)
            )
        except ValueError:
            return 0


def print_usage(prog: str):
    print(f"""
DPI Engine - Deep Packet Inspection System (Python Port)
========================================================

Usage: {prog} <input.pcap> <output.pcap> [options]

Options:
  --block-ip <ip>        Block traffic from source IP
  --block-app <app>      Block application (YouTube, Facebook, etc.)
  --block-domain <dom>   Block domain (substring match)

Example:
  {prog} capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50
""")


def main():
    if len(sys.argv) < 3:
        print_usage(sys.argv[0])
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    rules = BlockingRules()

    # Parse options
    i = 3
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "--block-ip" and i + 1 < len(sys.argv):
            i += 1
            rules.block_ip(sys.argv[i])
        elif arg == "--block-app" and i + 1 < len(sys.argv):
            i += 1
            rules.block_app(sys.argv[i])
        elif arg == "--block-domain" and i + 1 < len(sys.argv):
            i += 1
            rules.block_domain(sys.argv[i])
        i += 1

    print("\n╔══════════════════════════════════════════════════════════════╗")
    print("║                    DPI ENGINE v1.0 (PYTHON)                  ║")
    print("╚══════════════════════════════════════════════════════════════╝\n")

    reader = PcapReader()
    if not reader.open(input_file):
        sys.exit(1)

    try:
        output = open(output_file, "wb")
    except IOError:
        print("Error: Cannot open output file", file=sys.stderr)
        sys.exit(1)

    import struct

    # Write PCAP global header
    hdr = reader.global_header
    output.write(
        struct.pack(
            "=IHHIIII",
            hdr.magic_number,
            hdr.version_major,
            hdr.version_minor,
            hdr.thiszone,
            hdr.sigfigs,
            hdr.snaplen,
            hdr.network,
        )
    )

    flows: Dict[FiveTuple, Flow] = {}

    total_packets = 0
    forwarded = 0
    dropped = 0
    app_stats = collections.defaultdict(int)

    print("[DPI] Processing packets...\n")

    while True:
        raw = reader.read_next_packet()
        if not raw:
            break

        total_packets += 1

        parsed = PacketParser.parse(raw)
        if not parsed.has_ip or (not parsed.has_tcp and not parsed.has_udp):
            continue

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
        flow.packets += 1
        flow.bytes += len(raw.data)

        if (
            (flow.app_type == AppType.UNKNOWN or flow.app_type == AppType.HTTPS)
            and not flow.sni
            and parsed.has_tcp
            and parsed.dest_port == 443
        ):
            if parsed.payload_length > 5:
                sni = SNIExtractor.extract(parsed.payload_data)
                if sni:
                    flow.sni = sni
                    flow.app_type = sni_to_app_type(sni)

        if (
            (flow.app_type == AppType.UNKNOWN or flow.app_type == AppType.HTTP)
            and not flow.sni
            and parsed.has_tcp
            and parsed.dest_port == 80
        ):
            if parsed.payload_length > 0:
                host = HTTPHostExtractor.extract(parsed.payload_data)
                if host:
                    flow.sni = host
                    flow.app_type = sni_to_app_type(host)

        if flow.app_type == AppType.UNKNOWN and (
            parsed.dest_port == 53 or parsed.src_port == 53
        ):
            flow.app_type = AppType.DNS

        if flow.app_type == AppType.UNKNOWN:
            if parsed.dest_port == 443:
                flow.app_type = AppType.HTTPS
            elif parsed.dest_port == 80:
                flow.app_type = AppType.HTTP

        if not flow.blocked:
            flow.blocked = rules.is_blocked(tuple_key.src_ip, flow.app_type, flow.sni)
            if flow.blocked:
                sni_str = f": {flow.sni}" if flow.sni else ""
                print(
                    f"[BLOCKED] {parsed.src_ip} -> {parsed.dest_ip} ({str(flow.app_type)}{sni_str})"
                )

        app_stats[flow.app_type] += 1

        if flow.blocked:
            dropped += 1
        else:
            forwarded += 1
            hdr = raw.header
            output.write(
                struct.pack(
                    "=IIII", hdr.ts_sec, hdr.ts_usec, hdr.incl_len, hdr.orig_len
                )
            )
            output.write(raw.data)

    reader.close()
    output.close()

    print("\n╔══════════════════════════════════════════════════════════════╗")
    print("║                      PROCESSING REPORT                       ║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print(f"║ Total Packets:      {total_packets:<41}║")
    print(f"║ Forwarded:          {forwarded:<41}║")
    print(f"║ Dropped:            {dropped:<41}║")
    print(f"║ Active Flows:       {len(flows):<41}║")
    print("╠══════════════════════════════════════════════════════════════╣")
    print("║                    APPLICATION BREAKDOWN                     ║")
    print("╠══════════════════════════════════════════════════════════════╣")

    sorted_apps = sorted(app_stats.items(), key=lambda x: x[1], reverse=True)

    for app, count in sorted_apps:
        if total_packets > 0:
            pct = 100.0 * count / total_packets
        else:
            pct = 0.0
        bar_len = int(pct / 5)
        bar = "#" * bar_len

        app_name = str(app)
        print(f"║ {app_name:<15} {count:>8} {pct:>5.1f}% {bar:<29}║")

    print("╚══════════════════════════════════════════════════════════════╝")

    print("\n[Detected Applications/Domains]")
    unique_snis = {}
    for flow in flows.values():
        if flow.sni:
            unique_snis[flow.sni] = flow.app_type

    for sni, app in unique_snis.items():
        print(f"  - {sni} -> {str(app)}")

    print(f"\nOutput written to: {output_file}")


if __name__ == "__main__":
    main()
