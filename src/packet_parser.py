import struct
from .pcap_reader import RawPacket


class Protocol:
    ICMP = 1
    TCP = 6
    UDP = 17


class EtherType:
    IPv4 = 0x0800
    IPv6 = 0x86DD
    ARP = 0x0806


class TCPFlags:
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20


class ParsedPacket:
    def __init__(self):
        self.timestamp_sec = 0
        self.timestamp_usec = 0

        self.src_mac = ""
        self.dest_mac = ""
        self.ether_type = 0

        self.has_ip = False
        self.ip_version = 0
        self.src_ip = ""
        self.dest_ip = ""
        self.src_ip_int = 0
        self.dest_ip_int = 0
        self.protocol = 0
        self.ttl = 0

        self.has_tcp = False
        self.has_udp = False
        self.src_port = 0
        self.dest_port = 0

        self.tcp_flags = 0
        self.seq_number = 0
        self.ack_number = 0

        self.payload_length = 0
        self.payload_data = b""
        self.payload_offset = 0


class PacketParser:
    @staticmethod
    def parse(raw: RawPacket) -> ParsedPacket:
        parsed = ParsedPacket()
        parsed.timestamp_sec = raw.header.ts_sec
        parsed.timestamp_usec = raw.header.ts_usec

        data = raw.data
        length = len(data)
        offset = 0

        # Parse Ethernet
        success, offset = PacketParser._parse_ethernet(data, length, parsed, offset)
        if not success:
            return parsed

        if parsed.ether_type == EtherType.IPv4:
            success, offset = PacketParser._parse_ipv4(data, length, parsed, offset)
            if not success:
                return parsed

            if parsed.protocol == Protocol.TCP:
                success, offset = PacketParser._parse_tcp(data, length, parsed, offset)
            elif parsed.protocol == Protocol.UDP:
                success, offset = PacketParser._parse_udp(data, length, parsed, offset)

        if offset < length:
            parsed.payload_length = length - offset
            parsed.payload_data = data[offset:]
            parsed.payload_offset = offset
        else:
            parsed.payload_length = 0
            parsed.payload_data = b""
            parsed.payload_offset = 0

        return parsed

    @staticmethod
    def _parse_ethernet(
        data: bytes, length: int, parsed: ParsedPacket, offset: int
    ) -> tuple[bool, int]:
        ETH_HEADER_LEN = 14
        if length < offset + ETH_HEADER_LEN:
            return False, offset

        eth_data = data[offset : offset + ETH_HEADER_LEN]

        parsed.dest_mac = PacketParser.mac_to_string(eth_data[0:6])
        parsed.src_mac = PacketParser.mac_to_string(eth_data[6:12])
        parsed.ether_type = struct.unpack(">H", eth_data[12:14])[0]

        return True, offset + ETH_HEADER_LEN

    @staticmethod
    def _parse_ipv4(
        data: bytes, length: int, parsed: ParsedPacket, offset: int
    ) -> tuple[bool, int]:
        MIN_IP_HEADER_LEN = 20
        if length < offset + MIN_IP_HEADER_LEN:
            return False, offset

        version_ihl = data[offset]
        parsed.ip_version = (version_ihl >> 4) & 0x0F
        ihl = version_ihl & 0x0F

        if parsed.ip_version != 4:
            return False, offset

        ip_header_len = ihl * 4
        if ip_header_len < MIN_IP_HEADER_LEN or length < offset + ip_header_len:
            return False, offset

        parsed.ttl = data[offset + 8]
        parsed.protocol = data[offset + 9]

        # In Python, we want to store the integer value natively, but big-endian from packet
        # so we can use struct.unpack. However, the exact C++ logic stored it such that parsing it out later
        # matched the exact memory layout. We unpack it into an integer for easy usage.
        src_ip_bytes = data[offset + 12 : offset + 16]
        dest_ip_bytes = data[offset + 16 : offset + 20]

        parsed.src_ip_int = struct.unpack("<I", src_ip_bytes)[0]
        parsed.dest_ip_int = struct.unpack("<I", dest_ip_bytes)[0]

        parsed.src_ip = PacketParser.ip_to_string(parsed.src_ip_int)
        parsed.dest_ip = PacketParser.ip_to_string(parsed.dest_ip_int)

        parsed.has_ip = True
        return True, offset + ip_header_len

    @staticmethod
    def _parse_tcp(
        data: bytes, length: int, parsed: ParsedPacket, offset: int
    ) -> tuple[bool, int]:
        MIN_TCP_HEADER_LEN = 20
        if length < offset + MIN_TCP_HEADER_LEN:
            return False, offset

        tcp_data = data[offset:]
        parsed.src_port = struct.unpack(">H", tcp_data[0:2])[0]
        parsed.dest_port = struct.unpack(">H", tcp_data[2:4])[0]
        parsed.seq_number = struct.unpack(">I", tcp_data[4:8])[0]
        parsed.ack_number = struct.unpack(">I", tcp_data[8:12])[0]

        data_offset = (tcp_data[12] >> 4) & 0x0F
        tcp_header_len = data_offset * 4

        parsed.tcp_flags = tcp_data[13]

        if tcp_header_len < MIN_TCP_HEADER_LEN or length < offset + tcp_header_len:
            return False, offset

        parsed.has_tcp = True
        return True, offset + tcp_header_len

    @staticmethod
    def _parse_udp(
        data: bytes, length: int, parsed: ParsedPacket, offset: int
    ) -> tuple[bool, int]:
        UDP_HEADER_LEN = 8
        if length < offset + UDP_HEADER_LEN:
            return False, offset

        udp_data = data[offset : offset + 8]
        parsed.src_port = struct.unpack(">H", udp_data[0:2])[0]
        parsed.dest_port = struct.unpack(">H", udp_data[2:4])[0]

        parsed.has_udp = True
        return True, offset + UDP_HEADER_LEN

    @staticmethod
    def mac_to_string(mac: bytes) -> str:
        return ":".join(f"{b:02x}" for b in mac)

    @staticmethod
    def ip_to_string(ip_int: int) -> str:
        # C++ did: ((ip >> 0) & 0xFF) ... which means ip in C++ was treating little endian layout directly.
        # So we unpack it with <I above, then format the same way.
        b0 = (ip_int >> 0) & 0xFF
        b1 = (ip_int >> 8) & 0xFF
        b2 = (ip_int >> 16) & 0xFF
        b3 = (ip_int >> 24) & 0xFF
        return f"{b0}.{b1}.{b2}.{b3}"

    @staticmethod
    def protocol_to_string(protocol: int) -> str:
        if protocol == Protocol.ICMP:
            return "ICMP"
        if protocol == Protocol.TCP:
            return "TCP"
        if protocol == Protocol.UDP:
            return "UDP"
        return f"Unknown({protocol})"

    @staticmethod
    def tcp_flags_to_string(flags: int) -> str:
        parts = []
        if flags & TCPFlags.SYN:
            parts.append("SYN")
        if flags & TCPFlags.ACK:
            parts.append("ACK")
        if flags & TCPFlags.FIN:
            parts.append("FIN")
        if flags & TCPFlags.RST:
            parts.append("RST")
        if flags & TCPFlags.PSH:
            parts.append("PSH")
        if flags & TCPFlags.URG:
            parts.append("URG")
        return " ".join(parts) if parts else "none"
