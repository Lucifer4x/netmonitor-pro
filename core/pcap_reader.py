"""
NetMonitor Pro - PCAP Packet Reader & Synthetic Generator
Reads standard .pcap files and generates synthetic packet captures for demo & testing.
"""
import socket
import os
import time
import struct
import random
import logging
from typing import List, Tuple
from core.packet_parser import PacketParser, PacketInfo

logger = logging.getLogger("netmonitor.pcap")

class PcapEngine:
    """PCAP file generator and reader."""

    def __init__(self):
        self.parser = PacketParser()

    def generate_sample_pcap(self, filepath: str) -> None:
        """Generate a realistic PCAP file with normal traffic + embedded security events."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        # Write Global PCAP Header (24 bytes)
        # Magic (0xa1b2c3d4), Major 2, Minor 4, Zone 0, Sigfigs 0, Snaplen 65535, Network 1 (Ethernet)
        global_header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

        raw_packets = []
        base_time = time.time() - 60.0

        # 1. Normal HTTP/DNS Traffic
        for i in range(30):
            t = base_time + (i * 0.5)
            # Ethernet header (dst_mac, src_mac, eth_type 0x0800)
            eth = b"\x00\x11\x22\x33\x44\x55\xaa\xbb\xcc\xdd\xee\xff\x08\x00"
            # IP header (src 192.168.1.105, dst 93.184.216.34, proto 6 TCP)
            ip = b"\x45\x00\x00\x34\x12\x34\x40\x00\x40\x06\x00\x00\xc0\xa8\x01\x69\x5d\xb8\xd8\x22"
            # TCP header (src 54321, dst 80, SYN+ACK)
            tcp = struct.pack("!HHLLBBHHH", 54321 + (i % 5), 80, 1000 + i, 0, 0x50, 0x02, 64240, 0, 0)
            raw_packets.append((t, eth + ip + tcp))

        # 2. ARP Spoofing Attack Trace
        # ARP Reply (opcode 2): Gateway 192.168.1.1 claimed by attacker MAC aa:bb:cc:dd:ee:ff
        for i in range(5):
            t = base_time + 20.0 + i
            eth = b"\xff\xff\xff\xff\xff\xff\xaa\xbb\xcc\xdd\xee\xff\x08\x06"
            # ARP Header: Hardware 1 (Ethernet), Proto 0x0800, Hlen 6, Plen 4, Opcode 2 (Reply)
            # Attacker MAC aa:bb:cc:dd:ee:ff, IP 192.168.1.1 (Gateway), Target MAC 00:11:22:33:44:55, IP 192.168.1.105
            arp = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 2,
                              b"\xaa\xbb\xcc\xdd\xee\xff", socket.inet_aton("192.168.1.1"),
                              b"\x00\x11\x22\x33\x44\x55", socket.inet_aton("192.168.1.105"))
            raw_packets.append((t, eth + arp))

        # 3. Port Scan Trace (Probe ports 20-40)
        for port in range(20, 45):
            t = base_time + 35.0 + (port * 0.1)
            eth = b"\x00\x11\x22\x33\x44\x55\x11\x22\x33\x44\x55\x66\x08\x00"
            ip = b"\x45\x00\x00\x28\x56\x78\x40\x00\x40\x06\x00\x00\xc0\xa8\x01\xc8\xc0\xa8\x01\x01" # 192.168.1.200 -> 192.168.1.1
            tcp = struct.pack("!HHLLBBHHH", 40000 + port, port, 500, 0, 0x50, 0x02, 1024, 0, 0) # SYN
            raw_packets.append((t, eth + ip + tcp))

        with open(filepath, "wb") as f:
            f.write(global_header)
            for t, pkt_data in raw_packets:
                sec = int(t)
                usec = int((t - sec) * 1000000)
                pkt_header = struct.pack("<IIII", sec, usec, len(pkt_data), len(pkt_data))
                f.write(pkt_header)
                f.write(pkt_data)

        logger.info("Generated sample PCAP at %s (%d packets)", filepath, len(raw_packets))

    def read_pcap(self, filepath: str) -> List[PacketInfo]:
        """Read and parse packets from a PCAP file."""
        if not os.path.exists(filepath):
            self.generate_sample_pcap(filepath)

        packets = []
        with open(filepath, "rb") as f:
            global_hdr = f.read(24)
            if len(global_hdr) < 24:
                return packets

            pkt_id = 0
            while True:
                pkt_hdr = f.read(16)
                if len(pkt_hdr) < 16:
                    break
                sec, usec, incl_len, orig_len = struct.unpack("<IIII", pkt_hdr)
                ts = sec + (usec / 1000000.0)
                pkt_data = f.read(incl_len)
                if len(pkt_data) < incl_len:
                    break

                pkt_id += 1
                parsed = self.parser.parse_raw_ethernet(pkt_data, packet_id=pkt_id, timestamp=ts)
                packets.append(parsed)

        return packets
