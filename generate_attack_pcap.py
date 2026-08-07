"""Generate a benign GTP-U baseline stream with one LLM-driven qfi_qer_mismatch
attack campaign injected — mixed benign + attack traffic as it would actually occur on the wire.

Each attack packet is individually schema-valid but carries a QFI/RQI/DSCP
combination that violates the session's QER/FAR policy.
"""

import json
import os
import random
from datetime import datetime
from typing import Dict, Optional

from scapy.all import IP, UDP, TCP, Raw, wrpcap, rdpcap

from llm_client import LLMClient
from session_context import SessionContext
from packet_model import GTP_U_Mutation
from gtpu_scapy import build_gtpu_packet_from_mutation, MODEL_VARIANT
from generate_llm_pcap import (
    create_web_browsing_stream,
    generate_timestamped_filename,
    _make_web_browsing_session,
    _UE_IP,
    _WEB_SERVER_IP,
    _WEB_SERVER_PORT,
)


def _build_attack_packet(ctx: SessionContext, mutation: Dict, gnodeb_ip: str, upf_ip: str,
                         sim_time: float, direction: str = "DL"):
    """Convert one LLM mutation dict into a timestamped Scapy wire packet.

    The T-PDU is a real inner IP/TCP frame matching the benign path's
    web-browsing pattern, not raw filler bytes — otherwise Wireshark's GTP-U
    dissector tries to parse the filler as IP and flags the packet as
    malformed, which would make attack packets trivially distinguishable from
    a structural artifact instead of the intended QFI/RQI/DSCP policy
    violation. Per-packet randomized IP ID / ephemeral port / sequence number
    and high-entropy payload all mirror the benign path for the same reason.
    The outer IP's ToS carries the mutation's own (possibly violating)
    outer_dscp, not the session's expected one — a DSCP-violation mutation
    must actually carry the wrong DSCP on the wire, not just in telemetry.

    ``direction`` selects the on-wire orientation:

    * ``"DL"`` — downlink G-PDU. Outer tunnel runs UPF -> gNB; inner T-PDU runs
      web server -> UE (matching the benign background). Models a
      compromised-UPF egress.
    * ``"UL"`` — uplink G-PDU. Outer tunnel runs gNB -> UPF; inner T-PDU runs
      UE -> web server. This is the direction the UPF verifies the marked QFI
      against the session's authorized set, so it is the case an unauthorized
      QFI is meant to probe.
    """
    gtp_mutation = GTP_U_Mutation.from_json(ctx, mutation)

    if direction == "UL":
        inner_src, inner_dst = _UE_IP, _WEB_SERVER_IP
        tcp_sport, tcp_dport = random.randint(1024, 65535), _WEB_SERVER_PORT
        outer_src, outer_dst = gnodeb_ip, upf_ip
    else:
        inner_src, inner_dst = _WEB_SERVER_IP, _UE_IP
        tcp_sport, tcp_dport = _WEB_SERVER_PORT, random.randint(1024, 65535)
        outer_src, outer_dst = upf_ip, gnodeb_ip

    base_inner_payload = (
        IP(
            src=inner_src,
            dst=inner_dst,
            id=random.randint(0, 0xFFFF),
            ttl=random.randint(52, 62),
        )
        / TCP(
            sport=tcp_sport,
            dport=tcp_dport,
            flags="PA",
            seq=random.randint(0, 0xFFFFFFFF),
            ack=random.randint(400, 2000),
        )
    )
    payload_size = mutation.get("payload_size") or 0
    pad_len = max(0, payload_size - len(base_inner_payload))
    payload = base_inner_payload / Raw(load=os.urandom(pad_len)) if pad_len > 0 else base_inner_payload

    gtp_packet = build_gtpu_packet_from_mutation(gtp_mutation, payload=payload)
    wire_packet = (
        IP(
            src=outer_src,
            dst=outer_dst,
            tos=gtp_mutation.outer_dscp << 2,
            id=random.randint(0, 0xFFFF),
        )
        / UDP(sport=2152, dport=2152)
        / gtp_packet
    )
    wire_packet.time = sim_time
    return wire_packet


def create_injected_attack_stream(
    background_duration_minutes: float = 1.0,
    burst_size: Optional[int] = None,
    injection_fraction: Optional[float] = None,
    direction: str = "DL",
    output_dir: str = "pcap_files",
    gnodeb_ip: str = "192.168.100.10",
    upf_ip: str = "192.168.100.20",
    model_name: str = MODEL_VARIANT,
    backend: str = "ollama",
    max_output_tokens: Optional[int] = None,
    llm_batch_size: int = 200,
    background_max_packets: Optional[int] = None,
) -> tuple:
    """Generate a benign 5QI 6 background stream via LLM batch calls and
    inject one LLM-generated qfi_qer_mismatch attack campaign into it.

    burst_size/injection_fraction default to None, meaning the model itself
    decides the campaign's length and where in the traffic it lands (see
    LLMClient.generate_burst) — every run can land at a different point with
    a different size instead of a fixed spot. Pass explicit values to pin
    them for a reproducible run.

    Both the background and the attack packets belong to the SAME session
    (same TEID/QFI) — the attack represents a compromised/malicious flow
    riding the same tunnel, not a separate unrelated session.

    Returns:
        tuple: (path_to_pcap_file, path_to_telemetry_json)
    """
    ctx = _make_web_browsing_session()
    llm = LLMClient(model_name=model_name, backend=backend, max_output_tokens=max_output_tokens)

    print(f"GTP-U Benign + Injected Attack Stream (background={background_duration_minutes}min, burst_size={burst_size or 'model-decided'})")
    print("=" * 70)

    benign_pcap, _ = create_web_browsing_stream(
        duration_minutes=background_duration_minutes, output_dir=output_dir,
        gnodeb_ip=gnodeb_ip, upf_ip=upf_ip, max_packets=background_max_packets,
        model_name=model_name, backend=backend, max_output_tokens=max_output_tokens,
        llm_batch_size=llm_batch_size,
    )
    benign_packets = rdpcap(benign_pcap)
    if not benign_packets:
        raise RuntimeError(f"Background stream {benign_pcap} produced no packets.")

    print(f"\n[Attack Session Context — same session as background]")
    print(ctx.to_prompt_block())
    print()

    mutations = llm.generate_burst(ctx, burst_size=burst_size, direction=direction, max_retries_per_pkt=3)
    if not mutations:
        raise RuntimeError("LLM failed to generate any attack packets for this campaign.")

    if injection_fraction is None:
        model_fraction = mutations[0].get("injection_fraction")
        if isinstance(model_fraction, (int, float)):
            injection_fraction = float(model_fraction)
        else:
            print(f"[WARN] Model didn't provide a usable injection_fraction ({model_fraction!r}); falling back to 0.5.")
            injection_fraction = 0.5

    injection_index = max(0, min(len(benign_packets) - 1, int(len(benign_packets) * injection_fraction)))
    injection_time = float(benign_packets[injection_index].time)

    print(f"Injecting {len(mutations)}-packet attack campaign at packet #{injection_index}/{len(benign_packets)} "
          f"(t={injection_time:.2f}s, injection_fraction={injection_fraction:.3f})\n")

    attack_packets = []
    sim_time = injection_time
    for i, mutation in enumerate(mutations, start=1):
        sim_time += (mutation.get("inter_arrival_ms") or 20.0) / 1000.0
        attack_packets.append(_build_attack_packet(ctx, mutation, gnodeb_ip, upf_ip, sim_time, direction=direction))
        qfi = mutation["extension_headers"][0]["qfi"]
        is_violation = mutation["semantic_precision"]["is_semantically_anomalous"]
        print(f"  Attack pkt #{i} | qfi={qfi:2d} | raw_schema_valid={mutation['raw_schema_valid']} | policy_violation={is_violation}")

    attack_ids = {id(p) for p in attack_packets}
    combined = sorted(list(benign_packets) + attack_packets, key=lambda p: float(p.time))

    pcap_filename = generate_timestamped_filename(prefix="injected_attack_stream", output_dir=output_dir)
    json_filename = pcap_filename.replace(".pcap", "_telemetry.json")
    wrpcap(pcap_filename, combined)

    requested_burst_size = burst_size if burst_size is not None else mutations[0].get("campaign_size", len(mutations))
    policy_violation_hits = sum(1 for m in mutations if m["semantic_precision"]["is_semantically_anomalous"])
    ground_truth = [
        {"seq": i + 1, "time": float(p.time), "is_attack": id(p) in attack_ids}
        for i, p in enumerate(combined)
    ]

    telemetry_data = {
        "experiment_type": "benign_plus_injected_qfi_qer_mismatch_attack",
        "attack_direction": direction,
        "model_name": model_name,
        "timestamp": datetime.now().isoformat(),
        "pcap_file": pcap_filename,
        "background_pcap_file": benign_pcap,
        "background_packet_count": len(benign_packets),
        "attack_burst_size_requested": requested_burst_size,
        "attack_burst_size_generated": len(mutations),
        "injection_fraction": injection_fraction,
        "injection_index": injection_index,
        "injection_time_sec": injection_time,
        "total_packet_count": len(combined),
        "policy_violation_hits": policy_violation_hits,
        "llm_usage": {
            "api_call_count": llm.call_count,
            "total_prompt_tokens": llm.total_prompt_tokens,
            "total_completion_tokens": llm.total_completion_tokens,
        },
        "session_context": {
            "teid": hex(ctx.teid),
            "active_qfis": ctx.active_qfis,
            "qfi_to_5qi": ctx.qfi_to_5qi,
            "reflective_qos_enabled_qfis": ctx.reflective_qos_enabled_qfis,
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
    print(f" Attack packets injected  : {len(mutations)}/{requested_burst_size}")
    print(f" Policy violations        : {policy_violation_hits}/{len(mutations)} attack packets")
    print(
        f" LLM API calls            : {llm.call_count} "
        f"({llm.total_prompt_tokens} prompt / {llm.total_completion_tokens} completion tokens)"
    )
    print("=" * 70)

    return pcap_filename, json_filename


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate a benign GTP-U stream with one LLM-driven qfi_qer_mismatch attack campaign injected into it."
    )
    parser.add_argument("--background-duration", type=float, default=1.0, help="Background traffic duration in minutes (default: 1.0).")
    parser.add_argument("--burst-size", type=int, default=None, help="Packets in the injected attack campaign. Default: unset — the model decides the campaign size itself.")
    parser.add_argument("--injection-fraction", type=float, default=None, help="Where in the background stream to inject the attack, 0-1. Default: unset — the model decides where in the traffic to strike.")
    parser.add_argument("--direction", choices=["DL", "UL"], default="DL",
                        help="Attack orientation. 'UL' (uplink, pdu_type=1) is the QFI the UPF's own QoS-flow-ID verification is meant to reject; 'DL' (downlink, pdu_type=0, default) models a compromised-UPF egress.")
    parser.add_argument("--output-dir", type=str, default="pcap_files")
    parser.add_argument("--model", type=str, default=MODEL_VARIANT)
    parser.add_argument("--backend", choices=["ollama", "openai"], default="ollama")
    parser.add_argument("--max-output-tokens", type=int, default=None)
    parser.add_argument("--llm-batch-size", type=int, default=200, help="Packets requested per background LLM batch call (default: 200 — tested to sustain diversity/consistency across a single call).")
    parser.add_argument("--background-max-packets", type=int, default=None, help="Cap on background LLM-generated arrivals (not wire packets/segments), to bound LLM call cost (default: unbounded).")
    args = parser.parse_args()

    create_injected_attack_stream(
        background_duration_minutes=args.background_duration,
        burst_size=args.burst_size,
        injection_fraction=args.injection_fraction,
        direction=args.direction,
        output_dir=args.output_dir,
        model_name=args.model,
        backend=args.backend,
        max_output_tokens=args.max_output_tokens,
        llm_batch_size=args.llm_batch_size,
        background_max_packets=args.background_max_packets,
    )
