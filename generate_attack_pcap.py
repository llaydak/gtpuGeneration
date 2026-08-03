"""Generate a benign GTP-U baseline stream with one LLM-driven cross-flow-
interference attack campaign injected into the middle of it — mixed benign +
attack traffic in a single PCAP, as it would actually occur on the wire.

Cross-flow interference is a multi-packet anomaly: each individual attack
packet can look schema-valid, but the QFI chosen diverges packet-to-packet
within the campaign in a way inconsistent with the session's real bearer
usage (see MistralClient._infer_anomaly_type, Check 1).
"""

import json
from datetime import datetime
from typing import Dict, Optional

from scapy.all import IP, UDP, Raw, wrpcap, rdpcap

from mistral_client import MistralClient
from session_context import SessionContext
from packet_model import GTP_U_Mutation
from gtpu_scapy import build_gtpu_packet_from_mutation, MODEL_VARIANT
from generate_llm_pcap import (
    create_web_browsing_stream,
    generate_timestamped_filename,
    _make_web_browsing_session,
)


def _build_attack_packet(ctx: SessionContext, mutation: Dict, gnodeb_ip: str, upf_ip: str, sim_time: float):
    """Convert one LLM mutation dict into a timestamped Scapy wire packet."""
    gtp_mutation = GTP_U_Mutation.from_json(ctx, mutation)
    payload = Raw(load=b"X" * max(0, mutation.get("payload_size") or 0))
    gtp_packet = build_gtpu_packet_from_mutation(gtp_mutation, payload=payload)
    wire_packet = (
        IP(src=gnodeb_ip, dst=upf_ip, tos=ctx.dscp_marking << 2)
        / UDP(sport=2152, dport=2152)
        / gtp_packet
    )
    wire_packet.time = sim_time
    return wire_packet


def create_injected_attack_stream(
    background_duration_minutes: float = 1.0,
    burst_size: int = 15,
    injection_fraction: float = 0.5,
    output_dir: str = "pcap_files",
    gnodeb_ip: str = "192.168.100.10",
    upf_ip: str = "192.168.100.20",
    model_name: str = MODEL_VARIANT,
    backend: str = "ollama",
    max_output_tokens: Optional[int] = None,
) -> tuple:
    """Generate a benign 5QI 6 background stream (stats mode, matches the
    reference paper) and inject one LLM-generated cross-flow-interference
    attack campaign at injection_fraction of the way through it.

    Both the background and the attack packets belong to the SAME session
    (same TEID/QFI) — the attack represents a compromised/malicious flow
    riding the same tunnel, not a separate unrelated session.

    Returns:
        tuple: (path_to_pcap_file, path_to_telemetry_json)
    """
    ctx = _make_web_browsing_session()
    mistral = MistralClient(model_name=model_name, backend=backend, max_output_tokens=max_output_tokens)

    print(f"GTP-U Benign + Injected Attack Stream (background={background_duration_minutes}min, burst_size={burst_size})")
    print("=" * 70)

    # Cheap, paper-faithful background traffic (see prior stats-vs-llm
    # comparison — stats mode matches Table II's distributions, not just its
    # mean, and costs nothing).
    benign_pcap, _ = create_web_browsing_stream(
        duration_minutes=background_duration_minutes, mode="stats", output_dir=output_dir,
        gnodeb_ip=gnodeb_ip, upf_ip=upf_ip,
    )
    benign_packets = rdpcap(benign_pcap)
    if not benign_packets:
        raise RuntimeError(f"Background stream {benign_pcap} produced no packets.")

    injection_index = max(0, min(len(benign_packets) - 1, int(len(benign_packets) * injection_fraction)))
    injection_time = float(benign_packets[injection_index].time)

    print(f"\n[Attack Session Context — same session as background]")
    print(ctx.to_prompt_block())
    print(f"\nInjecting {burst_size}-packet attack campaign at packet #{injection_index}/{len(benign_packets)} "
          f"(t={injection_time:.2f}s)\n")

    mutations = mistral.generate_burst(ctx, burst_size=burst_size, max_retries_per_pkt=3)
    if not mutations:
        raise RuntimeError("LLM failed to generate any attack packets for this campaign.")

    attack_packets = []
    sim_time = injection_time
    for i, mutation in enumerate(mutations, start=1):
        sim_time += (mutation.get("inter_arrival_ms") or 20.0) / 1000.0
        attack_packets.append(_build_attack_packet(ctx, mutation, gnodeb_ip, upf_ip, sim_time))
        qfi = mutation["extension_headers"][0]["qfi"]
        print(
            f"  Attack pkt #{i} | qfi={qfi:2d} | primary={mutation['primary_anomaly']:22s} "
            f"| detected={mutation['detected_anomalies']} | compound={mutation['is_compound_anomaly']}"
        )

    attack_ids = {id(p) for p in attack_packets}
    combined = sorted(list(benign_packets) + attack_packets, key=lambda p: float(p.time))

    pcap_filename = generate_timestamped_filename(prefix="injected_attack_stream", output_dir=output_dir)
    json_filename = pcap_filename.replace(".pcap", "_telemetry.json")
    wrpcap(pcap_filename, combined)

    cross_flow_hits = sum(1 for m in mutations if "cross_flow_interference" in m["detected_anomalies"])
    ground_truth = [
        {"seq": i + 1, "time": float(p.time), "is_attack": id(p) in attack_ids}
        for i, p in enumerate(combined)
    ]

    telemetry_data = {
        "experiment_type": "benign_plus_injected_cross_flow_attack",
        "model_name": model_name,
        "timestamp": datetime.now().isoformat(),
        "pcap_file": pcap_filename,
        "background_pcap_file": benign_pcap,
        "background_packet_count": len(benign_packets),
        "attack_burst_size_requested": burst_size,
        "attack_burst_size_generated": len(mutations),
        "injection_index": injection_index,
        "injection_time_sec": injection_time,
        "total_packet_count": len(combined),
        "cross_flow_interference_hits": cross_flow_hits,
        "llm_usage": {
            "api_call_count": mistral.call_count,
            "total_prompt_tokens": mistral.total_prompt_tokens,
            "total_completion_tokens": mistral.total_completion_tokens,
        },
        "session_context": {
            "teid": hex(ctx.teid),
            "active_qfis": ctx.active_qfis,
            "qfi_to_5qi": ctx.qfi_to_5qi,
            "dscp_marking": hex(ctx.dscp_marking),
        },
        "attack_mutations": mutations,
        "ground_truth": ground_truth,
    }

    with open(json_filename, "w") as f:
        json.dump(telemetry_data, f, indent=2)

    print("\n INJECTED ATTACK STREAM COMPLETED \n")
    print(f" PCAP file                : {pcap_filename}")
    print(f" Telemetry JSON           : {json_filename}")
    print(f" Background packets       : {len(benign_packets)}")
    print(f" Attack packets injected  : {len(mutations)}/{burst_size}")
    print(f" cross_flow_interference  : {cross_flow_hits}/{len(mutations)} attack packets")
    print(
        f" LLM API calls            : {mistral.call_count} "
        f"({mistral.total_prompt_tokens} prompt / {mistral.total_completion_tokens} completion tokens)"
    )
    print("=" * 70)

    return pcap_filename, json_filename


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate a benign GTP-U stream with one LLM-driven cross-flow-interference attack campaign injected into it."
    )
    parser.add_argument("--background-duration", type=float, default=1.0, help="Background traffic duration in minutes (default: 1.0).")
    parser.add_argument("--burst-size", type=int, default=15, help="Packets in the injected attack campaign (default: 15).")
    parser.add_argument("--injection-fraction", type=float, default=0.5, help="Where in the background stream to inject the attack, 0-1 (default: 0.5).")
    parser.add_argument("--output-dir", type=str, default="pcap_files")
    parser.add_argument("--model", type=str, default=MODEL_VARIANT)
    parser.add_argument("--backend", choices=["ollama", "openai"], default="ollama")
    parser.add_argument("--max-output-tokens", type=int, default=None)
    args = parser.parse_args()

    create_injected_attack_stream(
        background_duration_minutes=args.background_duration,
        burst_size=args.burst_size,
        injection_fraction=args.injection_fraction,
        output_dir=args.output_dir,
        model_name=args.model,
        backend=args.backend,
        max_output_tokens=args.max_output_tokens,
    )
