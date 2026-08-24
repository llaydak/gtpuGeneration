"""Generate a benign GTP-U baseline stream with LLM-driven qfi_qer_mismatch
attack campaign injected.

Each attack packet is individually schema-valid but carries a QFI/RQI/DSCP
combination that violates the session's QER/FAR policy.
"""

import json
import random
from datetime import datetime
from typing import Dict, Optional

import numpy as np
from scapy.all import wrpcap, rdpcap

import reference_models
from llm_client import LLMClient, MODEL_VARIANT
from session_context import SessionContext
from gtpu import GTP_U_Mutation
from generate_llm_pcap import (
    assemble_gpdu,
    create_web_browsing_stream,
    generate_timestamped_filename,
    _make_web_browsing_session,
    _UE_IP,
    _WEB_SERVER_IP,
    _WEB_SERVER_PORT,
    _GNODEB_IP,
    _UPF_IP,
)


def _build_attack_packet(ctx: SessionContext, mutation: Dict,
                         sim_time: float, direction: str = "DL"):
    """Convert one LLM mutation dict into a timestamped Scapy wire packet.

    The T-PDU is a real inner IP/TCP frame matching the benign path's
    web-browsing pattern, not raw filler bytes.
    The outer IP's ToS carries the mutation's own (possibly violating)
    outer_dscp, not the session's expected one.

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
        sport, dport = random.randint(1024, 65535), _WEB_SERVER_PORT
        outer_src, outer_dst = _GNODEB_IP, _UPF_IP
    else:
        inner_src, inner_dst = _WEB_SERVER_IP, _UE_IP
        sport, dport = _WEB_SERVER_PORT, random.randint(1024, 65535)
        outer_src, outer_dst = _UPF_IP, _GNODEB_IP

    wire_packet = assemble_gpdu(
        gtp_mutation, inner_src=inner_src, inner_dst=inner_dst, sport=sport, dport=dport,
        seq=random.randint(0, 0xFFFFFFFF), ack=random.randint(400, 2000), flags="PA",
        ttl=random.randint(52, 62), payload_size=mutation.get("payload_size") or 0,
        outer_src=outer_src, outer_dst=outer_dst,
    )
    wire_packet.time = sim_time
    return wire_packet


def _script_attack_burst(llm, ctx, direction, burst_size, duration_sec, max_packets, rng):
    """Rotates the same three violation dimensions the LLM campaign uses (DL: QFI/RQI/DSCP; UL: QFI
    only), with benign-like payload/timing drawn from 5G-NIDD so only the QoS
    marking is anomalous."""
    active = ctx.active_qfis[0]
    unauth = [q for q in (2, 7, 9, 11, 13) if q not in ctx.active_qfis] or [max(ctx.active_qfis) + 1]
    dims = ("qfi",) if direction == "UL" else ("qfi", "rqi", "dscp")
    scalars = reference_models.sample_benign_flow_scalars(max_packets, rng)
    out, elapsed = [], 0.0
    for i in range(max_packets):
        if duration_sec is not None:
            if elapsed >= duration_sec:
                break
        elif len(out) >= (burst_size or 100):
            break
        dim = dims[i % len(dims)]
        pdu_type = 1 if direction == "UL" else 0
        if dim == "qfi":
            qfi, rqi, dscp = unauth[i % len(unauth)], 0, ctx.dscp_marking
            reason = f"rule-based script: QFI {qfi} outside active set {ctx.active_qfis}"
        elif dim == "rqi":
            qfi, rqi, dscp = active, 1, ctx.dscp_marking
            reason = "rule-based script: RQI=1 outside reflective-QoS allow-list"
        else:
            qfi, rqi, dscp = active, 0, 18
            reason = "rule-based script: outer DSCP 18 != session DSCP"
        iat = min(9000.0, max(3000.0, float(scalars["iat_ms"][i]))) if scalars else 5000.0
        payload = min(1400, int(max(64, scalars["payload"][i]))) if scalars else 1200
        raw = {"extension_headers": [{"type": 133, "pdu_type": pdu_type, "qfi": qfi, "rqi": rqi, "ppi": 0}],
               "outer_dscp": dscp, "payload_size": payload, "inter_arrival_ms": iat, "reasoning": reason}
        if not out:
            raw["injection_fraction"], raw["campaign_size"] = 0.5, burst_size or max_packets
        m = llm._sanitize_mutation(raw, ctx, direction=direction)
        if m:
            out.append(m)
            elapsed += iat / 1000.0
    return out


def create_injected_attack_stream(
    background_duration_minutes: float = 1.0,
    burst_size: Optional[int] = None,
    attack_duration_minutes: Optional[float] = None,
    injection_fraction: Optional[float] = None,
    direction: str = "DL",
    output_dir: str = "pcap_files",
    model_name: str = MODEL_VARIANT,
    backend: str = "ollama",
    max_output_tokens: Optional[int] = None,
    llm_batch_size: int = 200,
    background_max_packets: Optional[int] = None,
    attack_max_packets: int = 500,
    background_num_ues: int = 1,
    generation_mode: str = "llm",
) -> tuple:
    """Generate a benign 5QI 6 background stream via LLM batch calls and
    inject one LLM-generated qfi_qer_mismatch attack campaign into it.

    The attack rides UE 0's session (TEID/IP), so with background_num_ues > 1
    the compromised UE is hidden inside a realistic UPF crowd, the attack is one malicious flow among many innocent sessions, not a
    lone stream.

    Returns:
        tuple: (path_to_pcap_file, path_to_telemetry_json)
    """
    if burst_size is not None and attack_duration_minutes is not None:
        raise ValueError("Pass either burst_size or attack_duration_minutes, not both.")
    attack_duration_sec = attack_duration_minutes * 60.0 if attack_duration_minutes is not None else None
    ctx = _make_web_browsing_session()
    llm = LLMClient(model_name=model_name, backend=backend, max_output_tokens=max_output_tokens)

    if attack_duration_minutes is not None:
        attack_len_desc = f"duration={attack_duration_minutes}min (cap {attack_max_packets} pkts)"
    else:
        attack_len_desc = f"burst_size={burst_size or 'model-decided'}"
    print(f"GTP-U Benign + Injected Attack Stream (background={background_duration_minutes}min, {attack_len_desc})")
    print("=" * 70)

    benign_pcap, _ = create_web_browsing_stream(
        duration_minutes=background_duration_minutes, output_dir=output_dir,
        max_packets=background_max_packets,
        model_name=model_name, backend=backend, max_output_tokens=max_output_tokens,
        llm_batch_size=llm_batch_size, num_ues=background_num_ues,
        generation_mode="sampled" if generation_mode == "script" else "llm",
    )
    benign_packets = rdpcap(benign_pcap)
    if not benign_packets:
        raise RuntimeError(f"Background stream {benign_pcap} produced no packets.")

    print("\n[Attack Session Context — same session as background]")
    print(ctx.to_prompt_block())
    print()

    if generation_mode == "script":
        mutations = _script_attack_burst(
            llm, ctx, direction, burst_size, attack_duration_sec,
            attack_max_packets, np.random.default_rng(),
        )
    else:
        mutations = llm.generate_burst(
            ctx, burst_size=burst_size, duration_sec=attack_duration_sec,
            direction=direction, max_retries_per_pkt=3, duration_max_packets=attack_max_packets,
        )
    if not mutations:
        raise RuntimeError(f"{generation_mode} generator produced no attack packets for this campaign.")

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
    schema_invalid_skipped = 0
    sim_time = injection_time
    for i, mutation in enumerate(mutations, start=1):
        sim_time += (mutation.get("inter_arrival_ms") or 5000.0) / 1000.0
        headers = mutation.get("extension_headers") or [{}]
        qfi = headers[0].get("qfi")
        if not mutation.get("raw_schema_valid"):
            schema_invalid_skipped += 1
            print(f"  Attack pkt #{i} | qfi={qfi} | raw_schema_valid=False -> SKIPPED (unserializable, counted)")
            continue
        attack_packets.append(_build_attack_packet(ctx, mutation, sim_time, direction=direction))
        is_violation = mutation["semantic_precision"]["is_semantically_anomalous"]
        print(f"  Attack pkt #{i} | qfi={qfi:2d} | raw_schema_valid=True | policy_violation={is_violation}")

    attack_ids = {id(p) for p in attack_packets}
    combined = sorted(list(benign_packets) + attack_packets, key=lambda p: float(p.time))

    pcap_filename = generate_timestamped_filename(prefix="injected_attack_stream", output_dir=output_dir)
    json_filename = pcap_filename.replace(".pcap", "_telemetry.json")
    wrpcap(pcap_filename, combined)

    if attack_duration_minutes is not None:
        requested_burst_size = f"duration:{attack_duration_minutes}min"
    elif burst_size is not None:
        requested_burst_size = burst_size
    else:
        requested_burst_size = mutations[0].get("campaign_size", len(mutations))
    policy_violation_hits = sum(1 for m in mutations if m["semantic_precision"]["is_semantically_anomalous"])
    ground_truth = [
        {"seq": i + 1, "time": float(p.time), "is_attack": id(p) in attack_ids}
        for i, p in enumerate(combined)
    ]

    telemetry_data = {
        "experiment_type": "benign_plus_injected_qfi_qer_mismatch_attack",
        "attack_direction": direction,
        "model_name": "rule-based-script" if generation_mode == "script" else model_name,
        "timestamp": datetime.now().isoformat(),
        "pcap_file": pcap_filename,
        "background_pcap_file": benign_pcap,
        "background_packet_count": len(benign_packets),
        "attack_burst_size_requested": requested_burst_size,
        "attack_burst_size_generated": len(mutations),
        "attack_schema_valid_injected": len(attack_packets),
        "attack_schema_invalid_skipped": schema_invalid_skipped,
        "attack_schema_valid_rate": round(len(attack_packets) / len(mutations), 3) if mutations else 0.0,
        "attack_duration_minutes": attack_duration_minutes,
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
    print(f" Attack generated         : {len(mutations)} mutations")
    print(f" Schema-valid injected    : {len(attack_packets)}/{len(mutations)} "
          f"({schema_invalid_skipped} malformed skipped, rate={telemetry_data['attack_schema_valid_rate']})")
    print(f" Policy violations        : {policy_violation_hits}/{len(mutations)} generated mutations")
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
    parser.add_argument("--burst-size", type=int, default=None, help="Packets in the injected attack campaign. Default: unset — the model decides the campaign size itself. Mutually exclusive with --attack-duration.")
    parser.add_argument("--attack-duration", type=float, default=None, help="Attack length in MINUTES instead of a packet count: keep generating attack packets until this much of the campaign's own timing is covered. Mutually exclusive with --burst-size.")
    parser.add_argument("--attack-max-packets", type=int, default=500, help="Safety cap on attack packets in --attack-duration mode (each is one API call), so a small model-chosen inter_arrival_ms can't run the cost away (default: 500).")
    parser.add_argument("--injection-fraction", type=float, default=None, help="Where in the background stream to inject the attack, 0-1. Default: unset — the model decides where in the traffic to strike.")
    parser.add_argument("--direction", choices=["DL", "UL"], default="DL",
                        help="Attack orientation. 'UL' (uplink, pdu_type=1) is the QFI the UPF's own QoS-flow-ID verification is meant to reject; 'DL' (downlink, pdu_type=0, default) models a compromised-UPF egress.")
    parser.add_argument("--output-dir", type=str, default="pcap_files")
    parser.add_argument("--model", type=str, default=MODEL_VARIANT)
    parser.add_argument("--backend", choices=["ollama", "openai"], default="ollama")
    parser.add_argument("--max-output-tokens", type=int, default=None)
    parser.add_argument("--llm-batch-size", type=int, default=200, help="Packets requested per background LLM batch call (default: 200 — tested to sustain diversity/consistency across a single call).")
    parser.add_argument("--background-max-packets", type=int, default=None, help="Cap on background LLM-generated arrivals (not wire packets/segments), to bound LLM call cost (default: unbounded).")
    parser.add_argument("--background-num-ues", type=int, default=1, help="Number of concurrent benign UEs in the background crowd (default: 1). The attack rides UE 0; >1 hides the compromised UE among innocent sessions, the way a real UPF sees many UEs. Cost scales with N.")
    parser.add_argument("--generation-mode", choices=["llm", "script"], default="llm", help="Attack generator: 'llm' (default, openai/ollama) or 'script' (rule-based, no LLM — the non-LLM baseline; background is auto-sampled so the whole run is LLM-free).")
    args = parser.parse_args()

    create_injected_attack_stream(
        background_duration_minutes=args.background_duration,
        burst_size=args.burst_size,
        attack_duration_minutes=args.attack_duration,
        injection_fraction=args.injection_fraction,
        direction=args.direction,
        output_dir=args.output_dir,
        model_name=args.model,
        backend=args.backend,
        max_output_tokens=args.max_output_tokens,
        llm_batch_size=args.llm_batch_size,
        attack_max_packets=args.attack_max_packets,
        background_max_packets=args.background_max_packets,
        background_num_ues=args.background_num_ues,
        generation_mode=args.generation_mode,
    )
