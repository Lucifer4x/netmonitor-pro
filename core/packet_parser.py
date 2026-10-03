"""
NetMonitor Pro - Pure Python Packet & Protocol Parser
Parses Ethernet, IP, TCP, UDP, ICMP, ARP, and DNS packets.
"""

import struct
import socket
import logging
from dataclasses import dataclass, field
from typing import Optional, Tuple

logger = logging.getLogger("netmonitor.parser")

@dataclass
class PacketInfo:
    """Parsed packet data model."""
    id: int = 0
    timestamp: float = 0.0
    frame_length: int = 0
    eth_src: str = ""
    eth_dst: str = ""
    eth_proto: str = ""
    ip_version: int = 4
    src_ip: str = ""
    dst_ip: str = ""
    protocol: str = "OTHER"   # TCP, UDP, ICMP, ARP, 802.11
    src_port: int = 0
    dst_port: int = 0
    tcp_flags: dict = field(default_factory=dict)
    arp_opcode: int = 0
    arp_src_mac: str = ""
    arp_src_ip: str = ""
    payload_size: int = 0
    info: str = ""

class PacketParser:
    """Parses raw binary network packets."""

    @staticmethod
    def format_mac(b: bytes) -> str:
        """Format 6-byte MAC address into XX:XX:XX:XX:XX:XX."""
        return ":".join(f"{byte:02x}" for byte in b)

    @staticmethod
    def format_ip(b: bytes) -> str:
        """Format 4-byte IPv4 address."""
        return socket.inet_ntoa(b)

    def parse_raw_ethernet(self, raw_data: bytes, packet_id: int = 0, timestamp: float = 0.0) -> PacketInfo:
        """Parse raw Ethernet frame (14-byte header)."""
        pkt = PacketInfo(id=packet_id, timestamp=timestamp, frame_length=len(raw_data))

        if len(raw_data) < 14:
            pkt.info = "Malformed Short Frame"
            return pkt

        dst_mac, src_mac, eth_type = struct.unpack("!6s6sH", raw_data[:14])
        pkt.eth_dst = self.format_mac(dst_mac)
        pkt.eth_src = self.format_mac(src_mac)
        pkt.eth_proto = f"0x{eth_type:04x}"

        payload = raw_data[14:]

        # IPv4 (0x0800)
        if eth_type == 0x0800:
            self._parse_ipv4(payload, pkt)
        # ARP (0x0806)
        elif eth_type == 0x0806:
            self._parse_arp(payload, pkt)
        # IPv6 (0x86DD)
        elif eth_type == 0x86DD:
            pkt.protocol = "IPv6"
            pkt.info = "IPv6 Packet"
        else:
            pkt.info = f"Ethernet Type {pkt.eth_proto}"

        return pkt

    def _parse_ipv4(self, data: bytes, pkt: PacketInfo) -> None:
        if len(data) < 20:
            return

        ip_header = struct.unpack("!BBHHHBBH4s4s", data[:20])
        version_ihl = ip_header[0]
        ihl = (version_ihl & 0x0F) * 4
        proto_num = ip_header[6]

        pkt.ip_version = 4
        pkt.src_ip = self.format_ip(ip_header[8])
        pkt.dst_ip = self.format_ip(ip_header[9])

        ip_payload = data[ihl:]
        pkt.payload_size = len(ip_payload)

        # TCP (6)
        if proto_num == 6:
            self._parse_tcp(ip_payload, pkt)
        # UDP (17)
        elif proto_num == 17:
            self._parse_udp(ip_payload, pkt)
        # ICMP (1)
        elif proto_num == 1:
            pkt.protocol = "ICMP"
            if len(ip_payload) >= 2:
                icmp_type, icmp_code = struct.unpack("!BB", ip_payload[:2])
                pkt.info = f"ICMP Type {icmp_type} Code {icmp_code}"
            else:
                pkt.info = "ICMP Packet"
        else:
            pkt.protocol = f"IP-Proto-{proto_num}"

    def _parse_tcp(self, data: bytes, pkt: PacketInfo) -> None:
        pkt.protocol = "TCP"
        if len(data) < 20:
            return

        tcp_header = struct.unpack("!HHLLBBHHH", data[:20])
        pkt.src_port = tcp_header[0]
        pkt.dst_port = tcp_header[1]
        flags_byte = tcp_header[5]

        pkt.tcp_flags = {
            "FIN": bool(flags_byte & 0x01),
            "SYN": bool(flags_byte & 0x02),
            "RST": bool(flags_byte & 0x04),
            "PSH": bool(flags_byte & 0x08),
            "ACK": bool(flags_byte & 0x10),
            "URG": bool(flags_byte & 0x20),
        }

        active_flags = [flag for flag, active in pkt.tcp_flags.items() if active]
        pkt.info = f"TCP {pkt.src_port} -> {pkt.dst_port} [{','.join(active_flags)}]"

    def _parse_udp(self, data: bytes, pkt: PacketInfo) -> None:
        pkt.protocol = "UDP"
        if len(data) < 8:
            return

        udp_header = struct.unpack("!HHHH", data[:8])
        pkt.src_port = udp_header[0]
        pkt.dst_port = udp_header[1]

        if pkt.dst_port == 53 or pkt.src_port == 53:
            pkt.protocol = "DNS"
            pkt.info = f"DNS Query/Response ({pkt.src_port} -> {pkt.dst_port})"
        else:
            pkt.info = f"UDP {pkt.src_port} -> {pkt.dst_port}"

    def _parse_arp(self, data: bytes, pkt: PacketInfo) -> None:
        pkt.protocol = "ARP"
        if len(data) < 28:
            return

        arp_header = struct.unpack("!HHBBH6s4s6s4s", data[:28])
        pkt.arp_opcode = arp_header[4]
        pkt.arp_src_mac = self.format_mac(arp_header[5])
        pkt.arp_src_ip = self.format_ip(arp_header[6])
        dst_ip = self.format_ip(arp_header[8])

        op_str = "Request" if pkt.arp_opcode == 1 else "Reply" if pkt.arp_opcode == 2 else f"Op-{pkt.arp_opcode}"
        pkt.info = f"ARP {op_str}: Who has {dst_ip}? Tell {pkt.arp_src_ip}"
