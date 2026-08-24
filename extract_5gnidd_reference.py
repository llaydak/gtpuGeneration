#!/usr/bin/env python3
"""Extract the real-5G reference measurements from the 5G-NIDD flow CSV.

5G-NIDD (Samarakoon et al. 2022, arXiv:2212.01298) was captured on a real 5G RF
network (Oulu) with benign traffic from actual mobile devices, published as
Argus flow records — the same unit the packetizer (generate_llm_pcap.py) emits
(one TCP connection per arrival), so no reconstruction and no segmentation
parameter is needed.

Two distinct uses, both written to one .npz:
  * bytes            — per-flow downlink payload, the GoF reference the
                       LLM's own payload_size is scored against.
  * pkts, dur, ttl,
    req_bytes        — how a flow of a given size physically appears on the
                       wire. The packetizer reads these to render the LLM's
                       flow size without inventing packet counts or timing.

Filter: Label == Benign, Proto == tcp, DstBytes > 0. TCP-only because the
packetizer models TCP; the benign mix is otherwise kept unfiltered, since TS
23.501 defines 5QI 6 as a general Non-GBR bucket (www, e-mail, chat, ftp, p2p).

Byte accounting: DstBytes is link-layer. The packetizer's payload_size counts
inner IP+TCP bytes, so 14 B/packet of Ethernet is subtracted to match.

Usage:
    ./upfvenv/bin/python extract_5gnidd_reference.py [CSV] [--out ...]
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from datetime import datetime

import numpy as np

DEFAULT_CSV = os.path.expanduser("~/Downloads/BTS1_BTS2_fields_preserved.csv")
DEFAULT_OUT = "reference_data/5gnidd_benign_tcp_flows.npz"
ETHERNET_HDR = 14


def _num(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def _start_seconds(s):
    """5G-NIDD StartTime is corrupted to "MM:SS.f" (date/hour lost in export).
    MM is minute-in-hour (0-59), so parse to seconds; hour rollover is handled
    later per device by detecting the 59->00 wrap in file order."""
    try:
        mm, ss = s.split(":")
        return int(mm) * 60 + float(ss)
    except (AttributeError, ValueError):
        return None


def _arrival_gaps_ms(arrivals):
    """Per-device flow inter-arrival gaps (ms). The packetizer models one PDU
    session = one UE, so a single device's flow-start sequence is the like-for-
    like arrival process (not the whole-BS aggregate). Gaps are diffed within
    each SrcAddr in file order, adding an hour on each 59->00 minute wrap."""
    from collections import defaultdict
    by_dev = defaultdict(list)
    for src, t in arrivals:
        by_dev[src].append(t)
    gaps = []
    for times in by_dev.values():
        if len(times) < 2:
            continue
        cum, add = [], 0.0
        for i, t in enumerate(times):
            if i and t < times[i - 1] - 1.0:  # minute wrapped 59->00 = next hour
                add += 3600.0
            cum.append(t + add)
        g = np.diff(cum)
        gaps.extend(x * 1000.0 for x in g if 0.0 <= x < 3600.0)
    return np.asarray(gaps, dtype=np.float64)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv", nargs="?", default=DEFAULT_CSV,
                    help=f"5G-NIDD Argus flow CSV (default: {DEFAULT_CSV})")
    ap.add_argument("--out", default=DEFAULT_OUT, help=f"output .npz (default {DEFAULT_OUT})")
    args = ap.parse_args()

    if not os.path.exists(args.csv):
        sys.exit(f"[ERROR] CSV not found: {args.csv}\n"
                 "Download 5G-NIDD from https://ieee-dataport.org and pass its flow CSV.")

    cols = ("Label", "Proto", "DstBytes", "DstPkts", "Dur", "dTtl", "SrcBytes",
            "StartTime", "SrcAddr")
    with open(args.csv, newline="") as f:
        r = csv.reader(f)
        idx = {c: i for i, c in enumerate(next(r))}
        for need in cols:
            if need not in idx:
                sys.exit(f"[ERROR] column {need!r} not in CSV header.")

        rows, ttls, reqs, arrivals, scanned = [], [], [], [], 0
        for row in r:
            scanned += 1
            if row[idx["Label"]].strip() != "Benign" or row[idx["Proto"]].strip().lower() != "tcp":
                continue
            b, k = _num(row[idx["DstBytes"]]), _num(row[idx["DstPkts"]])
            d, t = _num(row[idx["Dur"]]), _num(row[idx["dTtl"]])
            q = _num(row[idx["SrcBytes"]])
            if not b or not k or k < 1:
                continue
            inner = b - ETHERNET_HDR * k
            if inner <= 0:
                continue
            rows.append((inner, k, max(d or 0.0, 0.0)))
            if t and 0 < t <= 255:
                ttls.append(t)
            if q and q > 0:
                reqs.append(q)
            # (device, flow-start seconds) in file order for the arrival process.
            st = _start_seconds(row[idx["StartTime"]])
            if st is not None:
                arrivals.append((row[idx["SrcAddr"]].strip(), st))

    if not rows:
        sys.exit("[ERROR] no benign TCP downlink flows matched the filter.")

    # Sorted by size so the packetizer can look up "how does a flow this big
    # actually appear on the wire" with a binary search.
    arr = np.asarray(sorted(rows), dtype=np.float64)
    payload, pkts, dur = arr[:, 0].astype(np.int64), arr[:, 1].astype(np.int64), arr[:, 2]
    ttl = np.asarray(ttls, dtype=np.int64)
    req = np.asarray(reqs, dtype=np.int64)
    arrival_gaps_ms = _arrival_gaps_ms(arrivals)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    np.savez_compressed(args.out, bytes=payload, pkts=pkts, dur=dur, ttl=ttl,
                        req_bytes=req, arrival_gaps_ms=arrival_gaps_ms)

    def _stats(x):
        x = np.asarray(x, dtype=float)
        return {"n": int(x.size), "mean": float(x.mean()), "cv": float(x.std() / x.mean()),
                "p50": float(np.median(x)), "p90": float(np.quantile(x, 0.90)),
                "p99": float(np.quantile(x, 0.99)), "max": float(x.max())}

    stats = {"payload_bytes": _stats(payload), "packets_per_flow": _stats(pkts),
             "duration_s": _stats(dur), "ttl": _stats(ttl), "request_bytes": _stats(req),
             "arrival_gap_ms": _stats(arrival_gaps_ms)}
    prov = {
        "dataset": "5G-NIDD (Oulu, real 5G RF network) — Samarakoon et al. 2022, arXiv:2212.01298",
        "source_csv": os.path.abspath(args.csv),
        "source_csv_bytes": os.path.getsize(args.csv),
        "extracted_at": datetime.now().isoformat(timespec="seconds"),
        "unit": "per-FLOW (one Argus record = one TCP connection), sorted by payload",
        "columns": {
            "bytes": f"DstBytes - {ETHERNET_HDR} * DstPkts (strip Ethernet to match packetizer accounting)",
            "pkts": "DstPkts", "dur": "Dur (seconds)", "ttl": "dTtl", "req_bytes": "SrcBytes (uplink request)",
            "arrival_gaps_ms": "per-device (SrcAddr) flow inter-arrival, from StartTime (MM:SS.f) diffed in file order",
        },
        "filter": {"Label": "Benign", "Proto": "tcp", "DstBytes": "> 0"},
        "rows_scanned": scanned,
        "stats": stats,
        "caveats": [
            "Argus caps Dur at ~5 s; ~23% of flows hit it, so their duration includes idle time.",
            "Only per-flow MEAN packet size is recoverable here, not the within-flow size distribution.",
        ],
        "note": "TS 23.501 5QI 6 is a general Non-GBR bucket; benign TCP mix kept, not app-filtered.",
    }
    prov_path = os.path.splitext(args.out)[0] + ".provenance.json"
    with open(prov_path, "w") as f:
        json.dump(prov, f, indent=2)

    print(f"[OK] wrote {args.out}  (flows={payload.size:,}, ttl={ttl.size:,}, req={req.size:,}, "
          f"arrival_gaps={arrival_gaps_ms.size:,})")
    print(f"[OK] wrote {prov_path}")
    print("Stats:", json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
