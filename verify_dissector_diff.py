#!/usr/bin/env python3
"""
Verification Script: Diff Scapy GTP-U Packet Layout vs Wireshark dissector (packet-gtpv1.c).

This script constructs GTP-U mutations using gtpu_scapy.build_gtpu_packet_from_mutation(),
prints pkt.show(), writes a synthetic PCAP, and dissects it via tshark to eyeball-confirm
and close the verification TODO.
"""

import sys
import subprocess
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.utils import wrpcap

from gtpu_scapy import build_gtpu_packet_from_mutation, build_gtpu_packet
from phase1_starter import GTP_U_Mutation, ExtensionHeader


def run_verification():
    print("=" * 80)
    print("GTP-U Packet Builder Verification vs Wireshark packet-gtpv1.c Dissector")
    print("=" * 80)

    # Packet 1: UL PDU Session Information (QFI=48, RQI=0, PPI=0)
    mut1 = GTP_U_Mutation(
        teid=0x11223344,
        extension_headers=[ExtensionHeader(ext_type=0x85, qfi=48, rqi=0, ppi=0)],
        sequence_number=0x000A,
    )
    pkt1 = build_gtpu_packet_from_mutation(mut1, pdu_type=1)

    # Packet 2: DL PDU Session Information (QFI=15, RQI=1, PPI=0)
    mut2 = GTP_U_Mutation(
        teid=0x55667788,
        extension_headers=[ExtensionHeader(ext_type=0x85, qfi=15, rqi=1, ppi=0)],
        sequence_number=0x0014,
    )
    pkt2 = build_gtpu_packet_from_mutation(mut2, pdu_type=0)

    # Packet 3: DL PDU Session Information (QFI=63, RQI=1, PPP=1, PPI=7)
    dict3 = {
        "teid": 0x99AABBCC,
        "sequence_number": 0x001E,
        "pdu_type": 0,
        "extension_headers": [{"type": 0x85, "qfi": 63, "rqi": 1, "PPP": 1, "ppi": 7}],
    }
    pkt3 = build_gtpu_packet_from_mutation(dict3)

    test_packets = [
        ("Packet 1: UL PDU Session Info (QFI=48)", pkt1),
        ("Packet 2: DL PDU Session Info (QFI=15, RQI=1)", pkt2),
        ("Packet 3: DL PDU Session Info (QFI=63, RQI=1, PPP=1, PPI=7)", pkt3),
    ]

    pcap_frames = []

    for name, pkt in test_packets:
        print(f"\n[{name}]")
        print("--- pkt.show() Output ---")
        pkt.show()
        raw_bytes = bytes(pkt)
        print("--- Raw Byte Hex Layout ---")
        print(" ".join(f"{b:02x}" for b in raw_bytes))
        
        # Frame with L2/L3/L4 encapsulation for PCAP export
        frame = Ether() / IP(src="192.168.1.100", dst="192.168.1.200") / UDP(sport=2152, dport=2152) / pkt
        pcap_frames.append(frame)

    pcap_filename = "gtpu_verification.pcap"
    wrpcap(pcap_filename, pcap_frames)
    print(f"\n[OK] Wrote synthetic PCAP to {pcap_filename}")

    print("\n" + "=" * 80)
    print("Wireshark (tshark) Dissector Output (packet-gtpv1.c Analysis)")
    print("=" * 80)
    
    cmd = ["tshark", "-r", pcap_filename, "-O", "gtp"]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode == 0:
        print(res.stdout)
    else:
        print(f"[WARN] tshark failed: {res.stderr}")


if __name__ == "__main__":
    run_verification()
