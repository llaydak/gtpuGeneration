"""Tier-1 dataset integrity check: injected attacks are semantic, not structural.

Runs two detectors over a generated pcap and scores both against the
ground-truth labels written alongside it:

  1. STRUCTURAL — tshark's own GTP-U dissector (grammar/syntax layer).
  2. SEMANTIC   — a session-aware policy check, re-deriving each packet's
     QFI / RQI / outer-DSCP / direction from the wire.

SCOPE — what these numbers do and do not show:
  * The structural rate is 0% BY CONSTRUCTION: generate_attack_pcap skips any
    mutation with raw_schema_valid=False, and build_gtpu_packet rejects
    out-of-range fields, so a malformed packet can never reach the pcap. What
    this check earns is the round-trip: an independent parser (tshark, not the
    Scapy that wrote the packets) confirms the packets are well-formed.
  * The semantic rate is near-tautological: the rules below mirror
    LLMClient._evaluate_semantic_precision, which produced the labels. It
    verifies the intended violation survives serialization, not that semantic
    detection "works".
  * The benign false-positive rate is a real measurement for QFI/RQI (the
    benign path puts the model's own extension headers on the wire) but NOT
    for DSCP, which generate_llm_pcap pins to the session value.
  The empirical enforcement claim is the live free5GC result (DATASET_VALIDATION
  #24), not this file.

Usage:
    ./upfvenv/bin/python detection_gap_report.py <pcap> [--telemetry J] [--plot]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional

_TIME_TOLERANCE_S = 1e-3


@dataclass
class SessionPolicy:
    """The QER/FAR state a semantic detector checks each packet against."""
    active_qfis: List[int]
    reflective_qos_enabled_qfis: List[int]
    dscp_marking: int

    @classmethod
    def from_telemetry(cls, telemetry: Dict) -> "SessionPolicy":
        sc = telemetry["session_context"]
        dscp = sc["dscp_marking"]
        return cls(
            active_qfis=list(sc["active_qfis"]),
            reflective_qos_enabled_qfis=list(sc.get("reflective_qos_enabled_qfis", [])),
            dscp_marking=int(dscp, 16) if isinstance(dscp, str) else int(dscp),
        )


@dataclass
class PacketVerdict:
    index: int                 # 0-based position in the pcap == ground_truth index
    is_attack: bool            # ground-truth label
    structural_flag: bool      # STRUCTURAL: un-parseable or out-of-range
    semantic_flag: bool        # SEMANTIC: violates session policy
    pdu_type: Optional[int] = None
    qfi: Optional[int] = None
    rqi: Optional[int] = None
    dscp: Optional[int] = None
    detail: List[str] = field(default_factory=list)


def _tshark_dissect(pcap_path: str) -> List[Dict]:
    """Per-frame GTP-U container fields, read by tshark rather than Scapy so the
    'well-formed' claim does not depend on the library that wrote the packets."""
    tshark = shutil.which("tshark")
    if not tshark:
        raise SystemExit("tshark not found in PATH — it is required as the independent GTP-U parser.")
    # Wireshark uses 'pdu_ses_con' for QFI/PDU-type but 'pdu_ses_cont' for RQI
    # (an upstream naming inconsistency).
    proc = subprocess.run(
        [tshark, "-r", pcap_path, "-T", "fields",
         "-e", "frame.time_epoch",
         "-e", "gtp.ext_hdr.pdu_ses_con.qos_flow_id",
         "-e", "gtp.ext_hdr.pdu_ses_con.pdu_type",
         "-e", "gtp.ext_hdr.pdu_ses_cont.rqi",
         "-e", "ip.dsfield.dscp"],
        capture_output=True, text=True,
    )
    rows: List[Dict] = []
    for line in proc.stdout.splitlines():
        cols = (line.split("\t") + [""] * 5)[:5]
        time_s, qfi_s, pt_s, rqi_s, dscp_s = (c.strip() for c in cols)
        # ip.dsfield.dscp yields "outer,inner"; the outer tunnel DSCP is first.
        head = dscp_s.split(",")[0].strip()
        rows.append({
            "time": float(time_s) if time_s else None,
            "qfi": int(qfi_s) if qfi_s.isdigit() else None,
            "pdu_type": int(pt_s) if pt_s.isdigit() else None,
            # RQI is a DL-only field; empty on the UL container -> treated as 0.
            "rqi": 1 if rqi_s in ("1", "True", "true") else 0,
            "dscp": int(head) if head.isdigit() else None,
        })
    return rows


def _structural_malformed(row: Dict) -> bool:
    """What a session-unaware parser can object to: the container is missing, or
    a field falls outside its 3GPP range."""
    return (row["qfi"] is None or not 0 <= row["qfi"] <= 63
            or row["pdu_type"] not in (0, 1))


def _semantic_check(row: Dict, policy: SessionPolicy) -> tuple:
    """Session-policy violations visible on the wire. A None DSCP means tshark
    read no ToS byte, so that rule abstains rather than counting as a violation."""
    reasons: List[str] = []
    qfi, dscp = row["qfi"], row["dscp"]
    if qfi not in policy.active_qfis:
        side = "UL" if row["pdu_type"] == 1 else "DL"
        why = " (UPF QoS-flow-ID verification)" if side == "UL" else ""
        reasons.append(f"{side} QFI {qfi} not in active set {policy.active_qfis}{why}")
    if row["pdu_type"] == 1:
        return bool(reasons), reasons  # RQI/PPI and outer DSCP are DL-only concerns
    if row["rqi"] == 1 and qfi not in policy.reflective_qos_enabled_qfis:
        reasons.append(f"RQI=1 on QFI {qfi} outside reflective-QoS allow-list "
                       f"{policy.reflective_qos_enabled_qfis}")
    if dscp is not None and dscp != policy.dscp_marking:
        reasons.append(f"outer DSCP {dscp} != session DSCP {policy.dscp_marking}")
    return bool(reasons), reasons


def analyze(pcap_path: str, telemetry: Dict) -> List[PacketVerdict]:
    """Score every frame. Labels are matched to frames positionally, so the two
    sequences must agree in length AND timestamp — a silent misalignment would
    mislabel every packet after the divergence."""
    policy = SessionPolicy.from_telemetry(telemetry)
    ground_truth = telemetry["ground_truth"]
    rows = _tshark_dissect(pcap_path)
    if len(rows) != len(ground_truth):
        raise SystemExit(f"[ERROR] tshark saw {len(rows)} frames but ground_truth has "
                         f"{len(ground_truth)} — labels cannot be aligned to frames.")
    for i, (r, g) in enumerate(zip(rows, ground_truth)):
        if r["time"] is None or abs(r["time"] - float(g["time"])) > _TIME_TOLERANCE_S:
            raise SystemExit(f"[ERROR] frame {i} timestamp {r['time']} does not match "
                             f"ground_truth {g['time']} — pcap and telemetry are not the same run.")

    verdicts = []
    for i, (r, g) in enumerate(zip(rows, ground_truth)):
        structural_flag = _structural_malformed(r)
        semantic_flag, detail = (False, []) if structural_flag else _semantic_check(r, policy)
        verdicts.append(PacketVerdict(
            index=i, is_attack=bool(g["is_attack"]),
            structural_flag=structural_flag, semantic_flag=semantic_flag,
            pdu_type=r["pdu_type"], qfi=r["qfi"], rqi=r["rqi"], dscp=r["dscp"], detail=detail,
        ))
    return verdicts


def _detector_stats(verdicts: List[PacketVerdict], flag_attr: str) -> Dict:
    tp = fp = fn = tn = 0
    for v in verdicts:
        flagged = getattr(v, flag_attr)
        if v.is_attack:
            tp, fn = (tp + 1, fn) if flagged else (tp, fn + 1)
        else:
            fp, tn = (fp + 1, tn) if flagged else (fp, tn + 1)
    return {
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "attack_detection_rate": round(tp / (tp + fn), 4) if tp + fn else 0.0,
        "benign_false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else 0.0,
        "precision": round(tp / (tp + fp), 4) if tp + fp else 0.0,
    }


def build_report(pcap_path: str, telemetry: Dict, verdicts: List[PacketVerdict]) -> Dict:
    attacks = [v for v in verdicts if v.is_attack]
    # The detection gap: attack packets a standard parser accepts as valid that
    # the session-aware detector still catches.
    gap = [v for v in attacks if not v.structural_flag and v.semantic_flag]
    schema_valid = [v for v in attacks if not v.structural_flag]
    return {
        "pcap_file": pcap_path,
        "attack_direction": telemetry.get("attack_direction", "DL"),
        "total_packets": len(verdicts),
        "attack_packets": len(attacks),
        "benign_packets": len(verdicts) - len(attacks),
        "structural_ids": _detector_stats(verdicts, "structural_flag"),
        "semantic_ids": _detector_stats(verdicts, "semantic_flag"),
        "schema_valid_attack_rate": round(len(schema_valid) / len(attacks), 4) if attacks else 0.0,
        "detection_gap_packets": len(gap),
        "detection_gap_rate": round(len(gap) / len(attacks), 4) if attacks else 0.0,
        # >0 means the DSCP rule abstained on some frames; see _semantic_check.
        "dscp_unavailable_packets": sum(1 for v in verdicts if v.dscp is None),
        "gap_examples": [
            {"index": v.index, "pdu_type": v.pdu_type, "qfi": v.qfi, "rqi": v.rqi,
             "dscp": v.dscp, "reasons": v.detail}
            for v in gap[:10]
        ],
    }


def print_report(report: Dict) -> None:
    s, m = report["structural_ids"], report["semantic_ids"]
    print("=" * 72)
    print(f" DETECTION-GAP REPORT (Tier-1, offline)  —  direction={report['attack_direction']}")
    print("=" * 72)
    print(f" pcap                     : {report['pcap_file']}")
    print(f" Total / attack / benign  : {report['total_packets']} / "
          f"{report['attack_packets']} / {report['benign_packets']}")
    print()
    print(f" {'Detector':<22}{'attack-detect':>14}{'benign-FPR':>13}")
    for name, d in (("Structural (parser)", s), ("Semantic (policy)", m)):
        print(f" {name:<22}{d['attack_detection_rate']*100:>13.1f}%"
              f"{d['benign_false_positive_rate']*100:>12.1f}%")
    print()
    print(f" Schema-valid attack rate : {report['schema_valid_attack_rate']*100:.1f}%  "
          f"(attacks an independent parser accepts as well-formed)")
    print(f" >> DETECTION GAP         : {report['detection_gap_packets']}/{report['attack_packets']} "
          f"attacks ({report['detection_gap_rate']*100:.1f}%) — invisible to syntax, caught by policy")
    if report["dscp_unavailable_packets"]:
        print(f" [WARN] DSCP unreadable on {report['dscp_unavailable_packets']} frame(s); "
              f"that rule abstained there.")
    if report["gap_examples"]:
        print("\n Gap examples (structurally valid, semantically anomalous):")
        for ex in report["gap_examples"]:
            print(f"   pkt #{ex['index']:<5} pdu_type={ex['pdu_type']} qfi={ex['qfi']} -> "
                  f"{'; '.join(ex['reasons']) or '(no reason recorded)'}")
    print("=" * 72)


def plot_report(verdicts: List[PacketVerdict], telemetry: Dict, out_path: str) -> None:
    """QFI per packet over time — where the anomaly actually sits. The
    detector-rate bars live in plot_gof.py, which reads the report JSON."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    gt = telemetry["ground_truth"]
    t0 = float(gt[0]["time"])
    active = [int(q) for q in telemetry["session_context"]["active_qfis"]]
    pts = [(float(gt[v.index]["time"]) - t0, v.qfi if v.qfi is not None else -1, v.is_attack)
           for v in verdicts]

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.axhspan(min(active) - 0.4, max(active) + 0.4, color="tab:green", alpha=0.12,
               label=f"provisioned QFI set {active}")
    for is_atk, style in ((False, dict(s=4, c="0.6", label="benign", rasterized=True)),
                          (True, dict(s=140, marker="X", c="tab:red", edgecolor="k",
                                      zorder=5, label="attack"))):
        sel = [(t, q) for t, q, a in pts if a == is_atk]
        if sel:
            ax.scatter([t for t, _ in sel], [q for _, q in sel], **style)
            if is_atk:
                # One label per distinct QFI: several attacks share a value, and
                # per-point labels overplot into an unreadable smear.
                for q in sorted({q for _, q in sel}):
                    t = min(t for t, qq in sel if qq == q)
                    ax.annotate(f"QFI {q}", (t, q), textcoords="offset points",
                                xytext=(6, 6), fontsize=9)
    ax.set_xlabel("time (s)")
    ax.set_ylabel("QFI (per packet)")
    # Attacks inside the shaded band are the RQI / outer-DSCP violations: their
    # QFI is authorized, so the anomaly is not visible on this axis.
    ax.set_title("Attack packets against the provisioned QFI set\n"
                 "(marks inside the band violate RQI or outer DSCP instead)",
                 fontsize=11)
    ax.legend(loc="upper right")
    fig.tight_layout()
    fig.savefig(out_path, dpi=130)
    print(f" Figure                   : {out_path}")


def main() -> None:
    p = argparse.ArgumentParser(description="Tier-1 semantic-vs-structural check for a generated GTP-U attack pcap.")
    p.add_argument("pcap", help="Path to the injected-attack pcap.")
    p.add_argument("--telemetry", default=None, help="Ground-truth telemetry JSON (default: <pcap>_telemetry.json).")
    p.add_argument("--out", default=None, help="Report JSON path (default: <pcap>_detection_gap.json).")
    p.add_argument("--plot", nargs="?", const="", default=None,
                   help="Also save the QFI-timeline figure (default: <pcap>_detection_gap.png).")
    args = p.parse_args()

    telemetry_path = args.telemetry or args.pcap.replace(".pcap", "_telemetry.json")
    if not os.path.exists(telemetry_path):
        raise SystemExit(f"Telemetry JSON not found: {telemetry_path} (pass --telemetry).")
    with open(telemetry_path) as f:
        telemetry = json.load(f)

    verdicts = analyze(args.pcap, telemetry)
    report = build_report(args.pcap, telemetry, verdicts)
    print_report(report)

    out_path = args.out or args.pcap.replace(".pcap", "_detection_gap.json")
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f" Report JSON              : {out_path}")

    if args.plot is not None:
        plot_report(verdicts, telemetry, args.plot or args.pcap.replace(".pcap", "_detection_gap.png"))


if __name__ == "__main__":
    main()
