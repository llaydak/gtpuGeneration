"""Script to generate realistic GTP-U traffic streams and PCAP traces.

Supports:
1. Web Browsing benign baseline stream (5QI 6, LLM-driven, configurable duration).
2. LLM-driven adversarial attack stream (benign baseline + injected attack packets).
"""

import os
import json
import time
from datetime import datetime
from typing import Optional, List, Dict

from scapy.all import IP, UDP, ICMP, Raw, wrpcap
from phase1_starter import (
    MistralClient,
    SessionContext,
    GTP_U_Mutation,
    build_gtpu_packet_from_mutation,
    MODEL_VARIANT,
)

# Fixed session for 5QI 6 (Web Browsing): single QFI, known DSCP.
# 3GPP TS 23.501 Table 5.7.4-1: 5QI 6 = Non-GBR, Priority 60, PDB 300ms, PER 1e-6
# Example services: www, e-mail, chat, ftp, p2p file sharing.
WEB_BROWSING_QFI = 6
WEB_BROWSING_5QI = 6
WEB_BROWSING_DSCP = 0x00   # Best-effort outer DSCP for Non-GBR traffic
WEB_BROWSING_SESSION_TEID = 0xDEADBEEF  # Fixed TEID for the single Web Browsing session

# Nominal packetization period for 5QI 6 from Table II of the reference paper.
# Used as a fallback advance when the LLM fails to return a packet.
_5QI6_NOMINAL_T_MS = 100.0

_GNODEB_IP_DEFAULT = "192.168.100.10"
_UPF_IP_DEFAULT = "192.168.100.20"
_UE_IP = "10.45.0.2"
_REMOTE_IP = "8.8.8.8"


def generate_timestamped_filename(
    prefix: str = "stream",
    output_dir: str = "pcap_files",
    extension: str = "pcap",
) -> str:
    """Generate a unique timestamped filename inside the output directory."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(output_dir, f"{prefix}_{timestamp}.{extension}")


def _make_web_browsing_session() -> SessionContext:
    """Return a fixed single-QFI session wired to 5QI 6 (Web Browsing)."""
    return SessionContext(
        teid=WEB_BROWSING_SESSION_TEID,
        active_qfis=[WEB_BROWSING_QFI],
        qfi_to_5qi={WEB_BROWSING_QFI: WEB_BROWSING_5QI},
        qfi_to_qer={WEB_BROWSING_QFI: 1},
        reflective_qos_enabled_qfis=[],
        dscp_marking=WEB_BROWSING_DSCP,
        pdu_type=0,
    )


def _build_wire_packet(
    ctx: SessionContext,
    pkt_json: Dict,
    base_inner_payload,
    gnodeb_ip: str,
    upf_ip: str,
    seq: int,
    sim_time: float,
):
    """Convert a single LLM packet dict into a timestamped Scapy wire packet.

    Pads the inner payload to match the LLM's requested payload_size and
    advances the PCAP timestamp by inter_arrival_ms.

    Returns:
        (wire_packet, inter_arrival_ms, payload_size)
    """
    mutation = GTP_U_Mutation.from_json(ctx, pkt_json)

    payload_size = mutation.payload_size if mutation.payload_size else 250
    pad_len = max(0, payload_size - len(base_inner_payload))
    actual_payload = base_inner_payload / Raw(load=b"X" * pad_len) if pad_len > 0 else base_inner_payload

    gtp_packet = build_gtpu_packet_from_mutation(mutation, payload=actual_payload)
    gtp_packet.seq = seq

    inter_arrival_ms = mutation.inter_arrival_ms if mutation.inter_arrival_ms else _5QI6_NOMINAL_T_MS

    wire_packet = (
        IP(src=gnodeb_ip, dst=upf_ip, tos=ctx.dscp_marking << 2)
        / UDP(sport=2152, dport=2152)
        / gtp_packet
    )
    wire_packet.time = sim_time + inter_arrival_ms / 1000.0

    return wire_packet, inter_arrival_ms, payload_size


def create_web_browsing_stream(
    duration_minutes: float = 15.0,
    output_dir: str = "pcap_files",
    gnodeb_ip: str = "192.168.100.10",
    upf_ip: str = "192.168.100.20",
) -> tuple:
    """Generate a 5QI 6 (Web Browsing) benign GTP-U stream via LLM for the given duration.

    The LLM determines payload_size and inter_arrival_ms for each packet based on
    its own knowledge of 3GPP TS 23.501. Packets are generated until the simulated
    elapsed time reaches duration_minutes.

    Args:
        duration_minutes: Simulated traffic duration to cover (default: 15 minutes).
        output_dir: Directory where PCAP and telemetry JSON files will be saved.
        gnodeb_ip: Outer IP address for gNodeB.
        upf_ip: Outer IP address for UPF.

    Returns:
        tuple: (path_to_pcap_file, path_to_telemetry_json)
    """
    target_duration_sec = duration_minutes * 60.0
    ctx = _make_web_browsing_session()
    mistral = MistralClient(model_name=MODEL_VARIANT)

    print("=" * 70)
    print(f"5G GTP-U Web Browsing Baseline Stream Generator (5QI {WEB_BROWSING_5QI})")
    print(f"Target simulated duration: {duration_minutes:.1f} minutes ({target_duration_sec:.0f} s)")
    print("=" * 70)
    print("\n[Session State Context]")
    print(ctx.to_prompt_block())

    pcap_filename = generate_timestamped_filename(prefix="web_browsing_benign", output_dir=output_dir)
    json_filename = pcap_filename.replace(".pcap", "_telemetry.json")

    packets: List = []
    telemetry_records: List[Dict] = []
    base_inner_payload = IP(src="10.45.0.2", dst="8.8.8.8") / ICMP(type=8, code=0)

    sim_elapsed_sec = 0.0
    start_wall_time = time.time()
    current_sim_time = start_wall_time
    seq = 0

    print(f"\n[Generating LLM packets until {target_duration_sec:.0f} s of simulated traffic is covered...]\n")

    while sim_elapsed_sec < target_duration_sec:
        seq += 1
        pkt_json = mistral.generate_benign(ctx, max_retries=3)
        if pkt_json is None:
            print(f"[WARN] Packet #{seq} failed after retries — skipping slot.")
            sim_elapsed_sec += _5QI6_NOMINAL_T_MS / 1000.0
            continue

        wire_packet, inter_arrival_ms, payload_size = _build_wire_packet(
            ctx, pkt_json, base_inner_payload, gnodeb_ip, upf_ip, seq, current_sim_time
        )
        sim_elapsed_sec += inter_arrival_ms / 1000.0
        current_sim_time += inter_arrival_ms / 1000.0

        packets.append(wire_packet)
        telemetry_records.append({
            "seq": seq,
            "payload_size_bytes": payload_size,
            "inter_arrival_ms": inter_arrival_ms,
            "sim_time_sec": round(sim_elapsed_sec, 3),
            "raw_llm_compliant": pkt_json.get("raw_llm_compliant"),
            "session_consistent": pkt_json.get("session_consistent"),
            "reasoning": pkt_json.get("reasoning", ""),
        })

        print(
            f"  Pkt #{seq:4d} | size={payload_size:5d}B | iat={inter_arrival_ms:7.1f}ms"
            f" | sim={sim_elapsed_sec:7.1f}s / {target_duration_sec:.0f}s"
            f" | compliant={pkt_json.get('raw_llm_compliant')}"
        )

    wrpcap(pcap_filename, packets)
    total_bytes = sum(len(p) for p in packets)

    telemetry_data = {
        "experiment_type": "web_browsing_benign_llm_stream",
        "5qi": WEB_BROWSING_5QI,
        "qfi": WEB_BROWSING_QFI,
        "timestamp": datetime.now().isoformat(),
        "pcap_file": pcap_filename,
        "target_duration_minutes": duration_minutes,
        "simulated_duration_seconds": round(sim_elapsed_sec, 2),
        "packet_count": len(packets),
        "total_bytes": total_bytes,
        "avg_packet_size_bytes": round(total_bytes / max(len(packets), 1), 2),
        "avg_inter_arrival_ms": round(
            sum(r["inter_arrival_ms"] for r in telemetry_records) / max(len(telemetry_records), 1), 2
        ),
        "llm_compliance_rate": round(
            sum(1 for r in telemetry_records if r["raw_llm_compliant"]) / max(len(telemetry_records), 1), 4
        ),
        "session_context": {
            "teid": hex(ctx.teid),
            "active_qfis": ctx.active_qfis,
            "qfi_to_5qi": ctx.qfi_to_5qi,
            "dscp_marking": hex(ctx.dscp_marking),
        },
        "packet_records": telemetry_records,
    }

    with open(json_filename, "w") as f:
        json.dump(telemetry_data, f, indent=2)

    print("\n" + "=" * 70)
    print(" WEB BROWSING STREAM COMPLETED")
    print("=" * 70)
    print(f" PCAP file          : {pcap_filename}")
    print(f" Telemetry JSON     : {json_filename}")
    print(f" Packets generated  : {len(packets)}")
    print(f" Simulated duration : {sim_elapsed_sec:.1f} s ({sim_elapsed_sec/60:.2f} min)")
    print(f" Avg payload size   : {telemetry_data['avg_packet_size_bytes']} bytes")
    print(f" Avg inter-arrival  : {telemetry_data['avg_inter_arrival_ms']} ms")
    print(f" LLM compliance     : {telemetry_data['llm_compliance_rate']*100:.1f}%")
    print("=" * 70)

    return pcap_filename, json_filename

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Generate a realistic 5G GTP-U web browsing PCAP stream.")
    parser.add_argument(
        "--duration",
        type=float,
        default=15.0,
        help="Simulated traffic duration in minutes (default: 15.0).",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="pcap_files",
        help="Directory for output PCAP files (default: pcap_files).",
    )

    args = parser.parse_args()
    create_web_browsing_stream(duration_minutes=args.duration, output_dir=args.output_dir)
