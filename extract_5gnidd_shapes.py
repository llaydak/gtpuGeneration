#!/usr/bin/env python3
"""Extract within-flow packet size shapes from the 5G-NIDD packet captures.

The Argus flow CSV (see extract_5gnidd_reference.py) gives only a flow's MEAN
packet size, so splitting a flow's bytes across its packets had to be even —
an artifact at the packet level. The pcaps carry every packet, so the real
within-flow size sequence is recoverable here and nowhere else.

Only captures whose attack cannot land on a benign TCP port are used, and each
one's attack port is excluded outright: SSH (drop port 22), UDPScan / UDPflood
(UDP attack) and ICMPflood (ICMP attack) leave TCP untouched. The HTTP(S) DoS
and TCP flood/scan captures are deliberately skipped — their attack traffic is
itself TCP and could not be separated from benign by port.

Per downlink flow (inner src public, inner dst private) each packet's inner IP
total length and arrival time are recorded. These become the few-shot examples
shown to the LLM (reference_models.sample_example_flows): the model sees real
flows and decides its own, rather than the generator copying them onto the wire.
Output is a ragged array (sizes + gaps + offsets), so a flow's real packet
count, size pattern and internal timing all come from the same measured flow.

Usage:
    ./upfvenv/bin/python extract_5gnidd_shapes.py [PCAP_DIR] [--out ...]
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import subprocess
import sys
from collections import defaultdict
from datetime import datetime

import numpy as np

DEFAULT_DIR = os.path.expanduser("~/Downloads/BS2")
DEFAULT_OUT = "reference_data/5gnidd_flow_shapes.npz"
# capture -> extra display-filter clause removing that capture's attack traffic.
SAFE_CAPTURES = {
    "SSH_BS2.pcapng": " && tcp.port!=22",
    "UDPScan_BS2.pcapng": "",     # attack is UDP
    "UDPflood_BS2.pcapng": "",    # attack is UDP
    "ICMPflood_BS2.pcapng": "",   # attack is ICMP
}
BASE_FILTER = "gtp && tcp"
MIN_PACKETS = 2
# A TCP stream stays open for minutes, so grouping by stream alone would make one
# "flow" span the whole capture. Argus — which produced the 5G-NIDD flow CSV —
# closes a record after this much idle time AND caps its span at the same value
# (the CSV's Dur maxes out at 4.999995 s). Applying both keeps these shapes and
# the payload reference on one flow definition.
IDLE_TIMEOUT_S = 5.0
MAX_FLOW_SPAN_S = 5.0


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def read_flows(pcap: str, tag: str, extra_filter: str):
    """Yield (flow_key, inner IP total length, arrival time) for downlink packets."""
    cmd = ["tshark", "-r", pcap, "-Y", BASE_FILTER + extra_filter, "-T", "fields",
           "-Eoccurrence=l", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.stream",
           "-e", "ip.len", "-e", "frame.time_epoch"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    for line in proc.stdout:
        parts = line.rstrip("\n").split("\t")
        if len(parts) != 5:
            continue
        src, dst, stream, length, ts = parts
        if not stream or not length or not _is_private(dst) or _is_private(src):
            continue
        try:
            n, t = int(length), float(ts)
        except ValueError:
            continue
        if n > 0:
            yield (tag, stream), n, t
    proc.wait()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap_dir", nargs="?", default=DEFAULT_DIR)
    ap.add_argument("--out", default=DEFAULT_OUT)
    args = ap.parse_args()

    flows: dict = defaultdict(list)
    used = []
    for name, extra in SAFE_CAPTURES.items():
        path = os.path.join(args.pcap_dir, name)
        if not os.path.exists(path):
            print(f"[skip] {name} not found")
            continue
        before = len(flows)
        for key, n, t in read_flows(path, name, extra):
            flows[key].append((t, n))
        print(f"[OK] {name}: +{len(flows) - before} flows")
        used.append(name)

    kept = []
    for pkts in flows.values():
        pkts.sort()
        run: list = []
        for t, n in pkts + [(float("inf"), 0)]:
            if run and (t - run[-1][0] > IDLE_TIMEOUT_S or t - run[0][0] > MAX_FLOW_SPAN_S):
                if len(run) >= MIN_PACKETS:
                    t0 = run[0][0]
                    kept.append(([n for _, n in run], [s - t0 for s, _ in run]))
                run = []
            if t != float("inf"):
                run.append((t, n))
    if not kept:
        sys.exit("[ERROR] no benign downlink flows extracted; check tshark and the pcap dir.")
    kept.sort(key=lambda f: sum(f[0]))

    sizes = np.fromiter((n for f, _ in kept for n in f), dtype=np.int32)
    # Gap before each packet; the first of a flow is 0 (the LLM supplies that one).
    gaps = np.fromiter((b - a for _, ts in kept for a, b in zip([ts[0]] + ts[:-1], ts)),
                       dtype=np.float32)
    offsets = np.cumsum([0] + [len(f) for f, _ in kept]).astype(np.int64)
    totals = np.fromiter((sum(f) for f, _ in kept), dtype=np.int64)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    np.savez_compressed(args.out, sizes=sizes, gaps=gaps, offsets=offsets, totals=totals)

    flat = sizes.astype(float)
    dur = np.fromiter((ts[-1] for _, ts in kept), dtype=float)
    stats = {
        "flows": len(kept), "packets": int(sizes.size),
        "flow_bytes": {"p50": float(np.median(totals)), "mean": float(totals.mean()),
                       "max": int(totals.max())},
        "packets_per_flow": {"p50": float(np.median(np.diff(offsets))),
                             "p90": float(np.quantile(np.diff(offsets), .90))},
        "duration_s": {"p50": float(np.median(dur)), "p90": float(np.quantile(dur, .90))},
        "packet_bytes": {"p25": float(np.quantile(flat, .25)), "p50": float(np.median(flat)),
                         "p75": float(np.quantile(flat, .75)), "p90": float(np.quantile(flat, .90)),
                         "max": int(flat.max()),
                         "frac_at_mtu": float((flat >= 1400).mean())},
    }
    prov = {
        "dataset": "5G-NIDD (Oulu, real 5G RF network) — Samarakoon et al. 2022, arXiv:2212.01298",
        "captures": used,
        "extracted_at": datetime.now().isoformat(timespec="seconds"),
        "display_filter": BASE_FILTER + " (+ per-capture attack-port exclusion)",
        "unit": "per downlink packet: inner IP total length + gap since previous, grouped per TCP stream, sorted by flow total",
        "selection": {k: (BASE_FILTER + v) for k, v in SAFE_CAPTURES.items()},
        "min_packets_per_flow": MIN_PACKETS,
        "idle_timeout_s": IDLE_TIMEOUT_S,
        "max_flow_span_s": MAX_FLOW_SPAN_S,
        "stats": stats,
    }
    with open(os.path.splitext(args.out)[0] + ".provenance.json", "w") as f:
        json.dump(prov, f, indent=2)

    print(f"\n[OK] wrote {args.out}")
    print("Stats:", json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
