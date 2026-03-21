import enum
import time
from dataclasses import dataclass, field


class AppType(enum.Enum):
    UNKNOWN = 0
    HTTP = 1
    HTTPS = 2
    DNS = 3
    TLS = 4
    QUIC = 5
    GOOGLE = 6
    FACEBOOK = 7
    YOUTUBE = 8
    TWITTER = 9
    INSTAGRAM = 10
    NETFLIX = 11
    AMAZON = 12
    MICROSOFT = 13
    APPLE = 14
    WHATSAPP = 15
    TELEGRAM = 16
    TIKTOK = 17
    SPOTIFY = 18
    ZOOM = 19
    DISCORD = 20
    GITHUB = 21
    CLOUDFLARE = 22
    APP_COUNT = 23

    def __str__(self):
        names = {
            AppType.UNKNOWN: "Unknown",
            AppType.HTTP: "HTTP",
            AppType.HTTPS: "HTTPS",
            AppType.DNS: "DNS",
            AppType.TLS: "TLS",
            AppType.QUIC: "QUIC",
            AppType.GOOGLE: "Google",
            AppType.FACEBOOK: "Facebook",
            AppType.YOUTUBE: "YouTube",
            AppType.TWITTER: "Twitter/X",
            AppType.INSTAGRAM: "Instagram",
            AppType.NETFLIX: "Netflix",
            AppType.AMAZON: "Amazon",
            AppType.MICROSOFT: "Microsoft",
            AppType.APPLE: "Apple",
            AppType.WHATSAPP: "WhatsApp",
            AppType.TELEGRAM: "Telegram",
            AppType.TIKTOK: "TikTok",
            AppType.SPOTIFY: "Spotify",
            AppType.ZOOM: "Zoom",
            AppType.DISCORD: "Discord",
            AppType.GITHUB: "GitHub",
            AppType.CLOUDFLARE: "Cloudflare"
        }
        return names.get(self, "Unknown")

def sni_to_app_type(sni: str) -> AppType:
    if not sni:
        return AppType.UNKNOWN
    
    lower_sni = sni.lower()
    
    if any(x in lower_sni for x in ["google", "gstatic", "googleapis", "ggpht", "gvt1"]):
        return AppType.GOOGLE
    if any(x in lower_sni for x in ["youtube", "ytimg", "youtu.be", "yt3.ggpht"]):
        return AppType.YOUTUBE
    if any(x in lower_sni for x in ["facebook", "fbcdn", "fb.com", "fbsbx", "meta.com"]):
        return AppType.FACEBOOK
    if any(x in lower_sni for x in ["instagram", "cdninstagram"]):
        return AppType.INSTAGRAM
    if any(x in lower_sni for x in ["whatsapp", "wa.me"]):
        return AppType.WHATSAPP
    if any(x in lower_sni for x in ["twitter", "twimg", "x.com", "t.co"]):
        return AppType.TWITTER
    if any(x in lower_sni for x in ["netflix", "nflxvideo", "nflximg"]):
        return AppType.NETFLIX
    if any(x in lower_sni for x in ["amazon", "amazonaws", "cloudfront", "aws"]):
        return AppType.AMAZON
    if any(x in lower_sni for x in ["microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing"]):
        return AppType.MICROSOFT
    if any(x in lower_sni for x in ["apple", "icloud", "mzstatic", "itunes"]):
        return AppType.APPLE
    if any(x in lower_sni for x in ["telegram", "t.me"]):
        return AppType.TELEGRAM
    if any(x in lower_sni for x in ["tiktok", "tiktokcdn", "musical.ly", "bytedance"]):
        return AppType.TIKTOK
    if any(x in lower_sni for x in ["spotify", "scdn.co"]):
        return AppType.SPOTIFY
    if "zoom" in lower_sni:
        return AppType.ZOOM
    if any(x in lower_sni for x in ["discord", "discordapp"]):
        return AppType.DISCORD
    if any(x in lower_sni for x in ["github", "githubusercontent"]):
        return AppType.GITHUB
    if any(x in lower_sni for x in ["cloudflare", "cf-"]):
        return AppType.CLOUDFLARE
    
    return AppType.HTTPS

class ConnectionState(enum.Enum):
    NEW = 0
    ESTABLISHED = 1
    CLASSIFIED = 2
    BLOCKED = 3
    CLOSED = 4

class PacketAction(enum.Enum):
    FORWARD = 0
    DROP = 1
    INSPECT = 2
    LOG_ONLY = 3

@dataclass
class FiveTuple:
    src_ip: int
    dst_ip: int
    src_port: int
    dst_port: int
    protocol: int  # TCP=6, UDP=17

    def reverse(self):
        return FiveTuple(self.dst_ip, self.src_ip, self.dst_port, self.src_port, self.protocol)
    
    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol))

    def __eq__(self, other):
        if not isinstance(other, FiveTuple):
            return False
        return (self.src_ip == other.src_ip and
                self.dst_ip == other.dst_ip and
                self.src_port == other.src_port and
                self.dst_port == other.dst_port and
                self.protocol == other.protocol)

    def to_string(self) -> str:
        def format_ip(ip):
            return f"{(ip >> 24) & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 8) & 0xFF}.{ip & 0xFF}"
        
        proto_str = "TCP" if self.protocol == 6 else ("UDP" if self.protocol == 17 else "?")
        return f"{format_ip(self.src_ip)}:{self.src_port} -> {format_ip(self.dst_ip)}:{self.dst_port} ({proto_str})"

@dataclass
class Connection:
    tuple: FiveTuple
    state: ConnectionState = ConnectionState.NEW
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""
    
    packets_in: int = 0
    packets_out: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    
    action: PacketAction = PacketAction.FORWARD
    
    # TCP state tracking
    syn_seen: bool = False
    syn_ack_seen: bool = False
    fin_seen: bool = False

@dataclass
class PacketJob:
    packet_id: int
    tuple: FiveTuple
    data: bytes
    eth_offset: int = 0
    ip_offset: int = 0
    transport_offset: int = 0
    payload_offset: int = 0
    payload_length: int = 0
    tcp_flags: int = 0
    
    # Timestamps
    ts_sec: int = 0
    ts_usec: int = 0
    
    @property
    def payload_data(self) -> bytes:
        return self.data[self.payload_offset:self.payload_offset+self.payload_length]

@dataclass
class DPIStats:
    total_packets: int = 0
    total_bytes: int = 0
    forwarded_packets: int = 0
    dropped_packets: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    other_packets: int = 0
    active_connections: int = 0
