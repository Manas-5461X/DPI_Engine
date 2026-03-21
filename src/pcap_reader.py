import struct
import sys

# Magic numbers for PCAP files
PCAP_MAGIC_NATIVE = 0xA1B2C3D4
PCAP_MAGIC_SWAPPED = 0xD4C3B2A1


class PcapGlobalHeader:
    def __init__(self):
        self.magic_number = 0
        self.version_major = 0
        self.version_minor = 0
        self.thiszone = 0
        self.sigfigs = 0
        self.snaplen = 0
        self.network = 0


class PcapPacketHeader:
    def __init__(self):
        self.ts_sec = 0
        self.ts_usec = 0
        self.incl_len = 0
        self.orig_len = 0


class RawPacket:
    def __init__(self):
        self.header = PcapPacketHeader()
        self.data = b""


class PcapReader:
    def __init__(self):
        self.file = None
        self.global_header = PcapGlobalHeader()
        self.needs_byte_swap = False
        self._global_header_format = "IHHIIII"
        self._packet_header_format = "IIII"

    def open(self, filename: str) -> bool:
        self.close()

        try:
            self.file = open(filename, "rb")
        except IOError as e:
            print(f"Error: Could not open file: {filename} - {e}", file=sys.stderr)
            return False

        header_bytes = self.file.read(24)
        if len(header_bytes) < 24:
            print("Error: Could not read PCAP global header", file=sys.stderr)
            self.close()
            return False

        # Unpack as native first to check magic
        unpacked = struct.unpack(f"={self._global_header_format}", header_bytes)

        self.global_header.magic_number = unpacked[0]

        if self.global_header.magic_number == PCAP_MAGIC_NATIVE:
            self.needs_byte_swap = False
            fmt = f"={self._global_header_format}"
        elif self.global_header.magic_number == PCAP_MAGIC_SWAPPED:
            self.needs_byte_swap = True
            # Determine opposite endianness
            endian = ">" if sys.byteorder == "little" else "<"
            fmt = f"{endian}{self._global_header_format}"
        else:
            print(
                f"Error: Invalid PCAP magic number: 0x{self.global_header.magic_number:x}",
                file=sys.stderr,
            )
            self.close()
            return False

        # Re-unpack with correct endianness
        unpacked = struct.unpack(fmt, header_bytes)
        self.global_header.magic_number = unpacked[0]
        self.global_header.version_major = unpacked[1]
        self.global_header.version_minor = unpacked[2]
        self.global_header.thiszone = unpacked[3]
        self.global_header.sigfigs = unpacked[4]
        self.global_header.snaplen = unpacked[5]
        self.global_header.network = unpacked[6]

        print(f"Opened PCAP file: {filename}")
        print(
            f"  Version: {self.global_header.version_major}.{self.global_header.version_minor}"
        )
        print(f"  Snaplen: {self.global_header.snaplen} bytes")
        link_type = " (Ethernet)" if self.global_header.network == 1 else ""
        print(f"  Link type: {self.global_header.network}{link_type}")

        return True

    def close(self):
        if self.file:
            self.file.close()
            self.file = None
        self.needs_byte_swap = False

    def read_next_packet(self) -> RawPacket:
        if not self.file:
            return None

        header_bytes = self.file.read(16)
        if len(header_bytes) < 16:
            return None

        endian = "="
        if self.needs_byte_swap:
            endian = ">" if sys.byteorder == "little" else "<"

        fmt = f"{endian}{self._packet_header_format}"
        unpacked = struct.unpack(fmt, header_bytes)

        raw_packet = RawPacket()
        raw_packet.header.ts_sec = unpacked[0]
        raw_packet.header.ts_usec = unpacked[1]
        raw_packet.header.incl_len = unpacked[2]
        raw_packet.header.orig_len = unpacked[3]

        if (
            raw_packet.header.incl_len > self.global_header.snaplen
            or raw_packet.header.incl_len > 65535
        ):
            print(
                f"Error: Invalid packet length: {raw_packet.header.incl_len}",
                file=sys.stderr,
            )
            return None

        raw_packet.data = self.file.read(raw_packet.header.incl_len)
        if len(raw_packet.data) < raw_packet.header.incl_len:
            print("Error: Could not read packet data", file=sys.stderr)
            return None

        return raw_packet
