"""Tier-1 detection-gap proof for the GTP-U semantic-fuzzing dataset.

This is the offline, testbed-free evidence that the injected attack packets are
*semantic* anomalies rather than *structural* ones. It runs two independent
detectors over a generated pcap and compares what each catches against the
ground-truth labels written alongside the pcap:

  1. STRUCTURAL IDS  — a standard, session-unaware parser (tshark / Wireshark's
     own GTP-U dissector). A packet is "flagged" only if it is malformed at the
     GTP-U layer: the PDU Session Container fails to dissect, or a field falls
     outside its 3GPP range (QFI 0-63, PDU type 0/1). This is the grammar/syntax
     layer. It deliberately ignores Wireshark's heuristic upper-layer dissectors
     (LISP/TLS/...) misfiring on the random inner T-PDU payload, since that is
     opaque user data a UPF forwards without inspection — not a GTP-U defect.

  2. SEMANTIC IDS    — a session-aware policy checker that re-derives each
     packet's QFI / RQI / outer-DSCP and direction from the wire and tests them
     against the session's QER/FAR state (active QFI set, reflective-QoS
     allow-list, expected DSCP). This is the same read-only logic the generator
     records as ground truth, re-implemented here directly off the pcap so the
     proof does not merely trust the generator's labels.

The headline result is the DETECTION GAP: attack packets that the structural
IDS accepts as perfectly valid but the semantic IDS catches. A large gap with a
low semantic false-positive rate is the evidence that "schema-valid yet
semantically inconsistent" is a real, exploitable class the syntax layer cannot
see — the core claim of the study.

Usage:
    ./upfvenv/bin/python detection_gap_report.py pcap_files/injected_attack_stream_*.pcap
    ./upfvenv/bin/python detection_gap_report.py <pcap> --telemetry <telemetry.json>
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional

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
        dscp = int(dscp, 16) if isinstance(dscp, str) else int(dscp)
        return cls(
            active_qfis=list(sc["active_qfis"]),
            reflective_qos_enabled_qfis=list(sc.get("reflective_qos_enabled_qfis", [])),
            dscp_marking=dscp,
        )


@dataclass
class PacketVerdict:
    index: int                 # 0-based position in the pcap == ground_truth index
    is_attack: bool            # ground-truth label
    parsed_gtp: bool           # a PDU Session Container was found on the wire
    structural_flag: bool      # STRUCTURAL IDS: malformed / un-parseable
    semantic_flag: bool        # SEMANTIC IDS: violates session policy
    pdu_type: Optional[int] = None
    qfi: Optional[int] = None
    rqi: Optional[int] = None
    dscp: Optional[int] = None
    detail: List[str] = field(default_factory=list)


def _tshark_dissect(pcap_path: str) -> List[Dict]:
    """Independent per-frame GTP-U dissection via tshark (Wireshark's own
    parser), in frame order. Returns one dict per frame:
    {parsed, qfi, pdu_type, rqi, dscp}.

    This scopes the STRUCTURAL check to the GTP-U tunnelling layer and its PDU
    Session Container — the bytes a UPF/GTP parser actually validates.
    Deliberately does NOT use Wireshark whole-frame expert-info, because
    tshark's heuristic upper-layer dissectors (LISP, TLS, ...) misfire on the
    random inner T-PDU payload and raise "malformed" errors that have nothing
    to do with GTP-U well-formedness. The inner T-PDU is opaque user data the
    UPF forwards without inspection, so those artifacts are out of scope.
    """
    tshark = shutil.which("tshark")
    if not tshark:
        raise SystemExit("tshark not found in PATH — it is required as the independent GTP-U parser.")
    # Field-name note: Wireshark uses 'pdu_ses_con' for QFI/PDU-type but
    # 'pdu_ses_cont' for RQI (an upstream naming inconsistency).
    proc = subprocess.run(
        [tshark, "-r", pcap_path, "-T", "fields",
         "-e", "gtp.ext_hdr.pdu_ses_con.qos_flow_id",
         "-e", "gtp.ext_hdr.pdu_ses_con.pdu_type",
         "-e", "gtp.ext_hdr.pdu_ses_cont.rqi",
         "-e", "ip.dsfield.dscp"],
        capture_output=True, text=True,
    )
    rows: List[Dict] = []
    for line in proc.stdout.splitlines():
        cols = line.split("\t")
        while len(cols) < 4:
            cols.append("")
        qfi_s, pt_s, rqi_s, dscp_s = (c.strip() for c in cols[:4])
        qfi = int(qfi_s) if qfi_s.isdigit() else None
        pdu_type = int(pt_s) if pt_s.isdigit() else None
        # RQI is a DL-only field; empty on the UL container -> treated as 0.
        rqi = 1 if rqi_s in ("1", "True", "true") else 0
        # ip.dsfield.dscp yields "outer,inner"; the outer tunnel DSCP is first.
        dscp = None
        if dscp_s:
            head = dscp_s.split(",")[0].strip()
            if head.isdigit():
                dscp = int(head)
        rows.append({
            "parsed": qfi is not None and pdu_type is not None,
            "qfi": qfi, "pdu_type": pdu_type, "rqi": rqi, "dscp": dscp,
        })
    return rows


def _structural_malformed(row: Dict) -> bool:
    """STRUCTURAL IDS: is this packet malformed at the GTP-U layer? True only
    if the PDU Session Container did not dissect, or a field is out of its
    3GPP-defined range (QFI 0-63, PDU type 0/1). An unauthorized-but-in-range
    QFI is NOT structurally malformed — that is a semantic violation.
    """
    if not row["parsed"]:
        return True
    if row["qfi"] is None or not (0 <= row["qfi"] <= 63):
        return True
    if row["pdu_type"] not in (0, 1):
        return True
    return False


def _semantic_check(pdu_type: int, qfi: int, rqi: int, dscp: int,
                    policy: SessionPolicy) -> tuple:
    """Direction-aware session-policy check. Mirrors
    LLMClient._evaluate_semantic_precision so the proof and the generator agree
    on what "semantically anomalous" means, but is computed straight off the
    wire here.

    Returns (is_anomalous, reasons).
    """
    reasons: List[str] = []
    violates_qfi = qfi not in policy.active_qfis
    if pdu_type == 1:
        # Uplink: the UPF verifies the marked QFI against the authorized set.
        # RQI/PPI do not exist on the uplink container, and outer DSCP is a
        # transport marking the UPF does not semantically verify.
        if violates_qfi:
            reasons.append(f"UL QFI {qfi} not in authorized set {policy.active_qfis} (UPF QoS-flow-ID verification)")
        return bool(reasons), reasons
    # Downlink: QFI / RQI / DSCP are all policy-bearing.
    if violates_qfi:
        reasons.append(f"DL QFI {qfi} not in active set {policy.active_qfis}")
    if rqi == 1 and qfi not in policy.reflective_qos_enabled_qfis:
        reasons.append(f"RQI=1 on QFI {qfi} outside reflective-QoS allow-list {policy.reflective_qos_enabled_qfis}")
    if dscp != policy.dscp_marking:
        reasons.append(f"outer DSCP {dscp} != session DSCP {policy.dscp_marking}")
    return bool(reasons), reasons


def analyze(pcap_path: str, telemetry: Dict) -> List[PacketVerdict]:
    policy = SessionPolicy.from_telemetry(telemetry)
    ground_truth = telemetry["ground_truth"]
    rows = _tshark_dissect(pcap_path)
    if len(rows) != len(ground_truth):
        print(f"[WARN] tshark saw {len(rows)} frames but telemetry ground_truth has "
              f"{len(ground_truth)} — aligning on the shorter of the two.")

    verdicts: List[PacketVerdict] = []
    n = min(len(rows), len(ground_truth))
    for i in range(n):
        r = rows[i]
        is_attack = bool(ground_truth[i]["is_attack"])
        parsed = r["parsed"]
        structural_flag = _structural_malformed(r)

        # SEMANTIC IDS: session-policy violation (only meaningful once the
        # container is well-formed).
        semantic_flag = False
        detail: List[str] = []
        if parsed and not structural_flag:
            semantic_flag, detail = _semantic_check(r["pdu_type"], r["qfi"], r["rqi"], r["dscp"], policy)

        verdicts.append(PacketVerdict(
            index=i, is_attack=is_attack, parsed_gtp=parsed,
            structural_flag=structural_flag, semantic_flag=semantic_flag,
            pdu_type=r["pdu_type"], qfi=r["qfi"], rqi=r["rqi"], dscp=r["dscp"], detail=detail,
        ))
    return verdicts


def _confusion(verdicts: List[PacketVerdict], flag_attr: str) -> Dict[str, int]:
    tp = fp = fn = tn = 0
    for v in verdicts:
        flagged = getattr(v, flag_attr)
        if v.is_attack and flagged:
            tp += 1
        elif v.is_attack and not flagged:
            fn += 1
        elif not v.is_attack and flagged:
            fp += 1
        else:
            tn += 1
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn}


def _rates(cm: Dict[str, int]) -> Dict[str, float]:
    tp, fp, fn, tn = cm["tp"], cm["fp"], cm["fn"], cm["tn"]
    recall = tp / (tp + fn) if (tp + fn) else 0.0          # attack detection rate
    fpr = fp / (fp + tn) if (fp + tn) else 0.0             # benign false-positive rate
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    return {"recall": recall, "fpr": fpr, "precision": precision}


def build_report(pcap_path: str, telemetry: Dict, verdicts: List[PacketVerdict]) -> Dict:
    attacks = [v for v in verdicts if v.is_attack]
    struct_cm = _confusion(verdicts, "structural_flag")
    sem_cm = _confusion(verdicts, "semantic_flag")
    struct_rates = _rates(struct_cm)
    sem_rates = _rates(sem_cm)

    # The detection gap: attack packets a standard parser accepts as valid
    # (structural IDS silent) that the session-aware detector still catches.
    gap_packets = [v for v in attacks if not v.structural_flag and v.semantic_flag]
    schema_valid_attacks = [v for v in attacks if not v.structural_flag]

    return {
        "pcap_file": pcap_path,
        "attack_direction": telemetry.get("attack_direction", "DL"),
        "total_packets": len(verdicts),
        "attack_packets": len(attacks),
        "benign_packets": len(verdicts) - len(attacks),
        "structural_ids": {
            "confusion": struct_cm,
            "attack_detection_rate": round(struct_rates["recall"], 4),
            "benign_false_positive_rate": round(struct_rates["fpr"], 4),
        },
        "semantic_ids": {
            "confusion": sem_cm,
            "attack_detection_rate": round(sem_rates["recall"], 4),
            "benign_false_positive_rate": round(sem_rates["fpr"], 4),
            "precision": round(sem_rates["precision"], 4),
        },
        "schema_valid_attack_rate": round(len(schema_valid_attacks) / len(attacks), 4) if attacks else 0.0,
        "detection_gap_packets": len(gap_packets),
        "detection_gap_rate": round(len(gap_packets) / len(attacks), 4) if attacks else 0.0,
        "gap_examples": [
            {"index": v.index, "pdu_type": v.pdu_type, "qfi": v.qfi, "rqi": v.rqi,
             "dscp": v.dscp, "reasons": v.detail}
            for v in gap_packets[:10]
        ],
    }


def print_report(report: Dict) -> None:
    print("=" * 72)
    print(f" DETECTION-GAP REPORT (Tier-1, offline)  —  direction={report['attack_direction']}")
    print("=" * 72)
    print(f" pcap                     : {report['pcap_file']}")
    print(f" Total / attack / benign  : {report['total_packets']} / {report['attack_packets']} / {report['benign_packets']}")
    print()
    print(f" {'Detector':<16}{'attack-detect':>15}{'benign-FPR':>14}")
    s = report["structural_ids"]
    m = report["semantic_ids"]
    print(f" {'Structural (parser)':<16}{s['attack_detection_rate']*100:>13.1f}%{s['benign_false_positive_rate']*100:>13.1f}%")
    print(f" {'Semantic (policy)':<16}{m['attack_detection_rate']*100:>13.1f}%{m['benign_false_positive_rate']*100:>13.1f}%")
    print()
    print(f" Schema-valid attack rate : {report['schema_valid_attack_rate']*100:.1f}%  "
          f"(attacks a standard parser accepts as well-formed)")
    print(f" >> DETECTION GAP         : {report['detection_gap_packets']}/{report['attack_packets']} attacks "
          f"({report['detection_gap_rate']*100:.1f}%) — invisible to syntax, caught by session policy")
    if report["gap_examples"]:
        print("\n Gap examples (structurally valid, semantically anomalous):")
        for ex in report["gap_examples"]:
            reason = "; ".join(ex["reasons"]) or "(no reason recorded)"
            print(f"   pkt #{ex['index']:<5} pdu_type={ex['pdu_type']} qfi={ex['qfi']} -> {reason}")
    print("=" * 72)


def _default_telemetry_path(pcap_path: str) -> str:
    return pcap_path.replace(".pcap", "_telemetry.json")


def main() -> None:
    parser = argparse.ArgumentParser(description="Tier-1 semantic-vs-structural detection-gap proof for a generated GTP-U attack pcap.")
    parser.add_argument("pcap", help="Path to the injected-attack pcap.")
    parser.add_argument("--telemetry", default=None, help="Ground-truth telemetry JSON (default: <pcap>_telemetry.json).")
    parser.add_argument("--out", default=None, help="Where to write the report JSON (default: <pcap>_detection_gap.json).")
    args = parser.parse_args()

    telemetry_path = args.telemetry or _default_telemetry_path(args.pcap)
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


if __name__ == "__main__":
    main()
