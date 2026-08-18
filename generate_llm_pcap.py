"""Script to generate realistic GTP-U traffic streams and PCAP traces.

Supports:
1. Web Browsing benign baseline stream (5QI 6, LLM-driven, configurable duration).
2. LLM-driven adversarial attack stream (benign baseline + injected attack packets).
"""

import os
import json
import random
import time
from collections import Counter
from datetime import datetime
from typing import Optional, List, Dict

from scapy.all import IP, UDP, TCP, Raw, wrpcap
from llm_client import LLMClient
from session_context import SessionContext
from packet_model import GTP_U_Mutation
from gtpu_scapy import build_gtpu_packet_from_mutation, MODEL_VARIANT
import reference_models


# 3GPP TS 23.501 Table 5.7.4-1: 5QI 6 = Non-GBR, Priority 60, PDB 300ms,
# PER 1e-6; example services www, e-mail, chat, ftp, p2p.
# QFI is an arbitrary 0-63 flow identifier and need not equal the 5QI it maps
# to; making them differ removes a synthetic-looking artifact and matches the
# free5GC testbed convention (authorized QFI 1) used in the live study (#24).
WEB_BROWSING_QFI = 1
WEB_BROWSING_5QI = 6
WEB_BROWSING_DSCP = 0x00   # Best-effort outer DSCP for Non-GBR traffic
# Real N3 allocates a TEID per direction per PDU session, so downlink and uplink
# do not share one. Fixed here for reproducibility; small allocated-looking
# values in the style of the free5GC testbed (#24), not a magic word.
WEB_BROWSING_DL_TEID = 0x000000C9  # gNB-allocated: UPF sends downlink on this
WEB_BROWSING_UL_TEID = 0x000000CA  # UPF-allocated: gNB sends uplink on this


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
    """Return a fixed single-QFI session wired to 5QI 6 (Web Browsing).

    `teid` is the downlink TEID; the uplink request stream uses
    WEB_BROWSING_UL_TEID (see the flow loop).
    """
    return SessionContext(
        teid=WEB_BROWSING_DL_TEID,
        active_qfis=[WEB_BROWSING_QFI],
        qfi_to_5qi={WEB_BROWSING_QFI: WEB_BROWSING_5QI},
        qfi_to_qer={WEB_BROWSING_QFI: 1},
        reflective_qos_enabled_qfis=[],
        dscp_marking=WEB_BROWSING_DSCP,
        pdu_type=0,
    )


# Inner T-PDU endpoints. This stream is DOWNLINK (pdu_type=0 = DL PDU Session
# Information per TS 38.415), so the inner packet travels server -> UE and the
# outer GTP-U tunnel travels UPF -> gNB. Downlink is also the direction that
# carries the byte volume in web browsing: the uplink side is small HTTP
# requests, the downlink side is the large page/asset responses this stream
# models.
_UE_IP = "10.45.0.2"
_WEB_SERVER_IP = "93.184.216.34"
# Modern web browsing is overwhelmingly TLS on 443, not cleartext port 80 —
# which also makes the high-entropy payload below self-consistent (encrypted
# bytes are incompressible; cleartext HTTP would not be).
_WEB_SERVER_PORT = 443


_MTU = 1500
_MIN_PKT = 40  # IP + TCP headers, no data
# Fraction of intra-flow packets that are small (control/ACK-sized) rather than
# bulk. Keeps the wire size mix bimodal instead of an all-MTU spike; see
# DATASET_VALIDATION #23. The value is a modelling choice, not a measurement.
_SMALL_SEGMENT_PROB = 0.30
# An intra-flow gap is usually near-zero (back-to-back frames) but occasionally
# a larger pause (ACK clock / RAN scheduler); see DATASET_VALIDATION #18.
_INTRA_PAUSE_PROB = 0.10


def _split_mtu(total: int, mtu: int = _MTU, floor: int = _MIN_PKT) -> List[int]:
    """Split a byte total into inner-IP packets no larger than the MTU.

    Used for the uplink REQUEST: the LLM gives its total size but not its packet
    structure (the request is background, not the modelled downlink), so a
    bulk-then-remainder split is a plain packetization rule, not a model.
    """
    total = max(floor, int(total))
    chunks: List[int] = []
    while total > mtu:
        take = mtu if total - mtu >= floor else total - floor
        chunks.append(take)
        total -= take
    chunks.append(total)
    return chunks


def _fragment_flow(payload_size: int) -> tuple:
    """Split a downlink flow's total bytes into wire packets and their gaps.

    The LLM decides the flow's SIZE (scored) and leaves the packetization to
    this rule: bulk packets sit near the MTU, interspersed with smaller
    control-sized ones, and the sum is exactly `payload_size`. Gaps are mostly
    sub-millisecond with an occasional pause. This is a documented rendering
    rule — realistic in its marginal size/gap mix, not a per-object TCP model
    (see DATASET_VALIDATION #20, #23, #18) — not a copy of any real flow, so the
    reference dataset stays out of the generation path.

    Returns (sizes, gaps_ms) with gaps_ms[0] == 0.0 (the flow's first packet has
    no predecessor inside the flow).
    """
    if payload_size <= _MTU:
        sizes = [max(_MIN_PKT, int(payload_size))]
    else:
        sizes = []
        remaining = payload_size
        while remaining > _MTU:
            if random.random() < _SMALL_SEGMENT_PROB:
                seg = random.randint(_MIN_PKT, 400)
            else:
                seg = random.randint(1000, _MTU)
            seg = min(seg, remaining - _MIN_PKT)  # keep the remainder >= one header
            sizes.append(seg)
            remaining -= seg
        sizes.append(remaining)

    gaps = [0.0]
    for _ in range(len(sizes) - 1):
        if random.random() < _INTRA_PAUSE_PROB:
            gaps.append(round(random.uniform(5.0, 50.0), 2))
        else:
            gaps.append(round(random.uniform(0.01, 1.0), 2))
    return sizes, gaps


def _build_wire_packet(
    ctx: SessionContext,
    meta: Dict,
    gnodeb_ip: str,
    upf_ip: str,
    sim_time: float,
    gap_ms: float,
):
    """Render one telemetry record as a GTP-U wire packet.

    Direction-aware: a downlink G-PDU tunnels UPF -> gNB carrying server -> UE
    inner traffic (pdu_type 0); an uplink G-PDU tunnels gNB -> UPF carrying
    UE -> server (pdu_type 1). `gap_ms` is the spacing before this packet and
    sets its capture timestamp.
    """
    mutation = GTP_U_Mutation.from_json(ctx, meta)
    payload_size = mutation.payload_size if mutation.payload_size is not None else 250
    uplink = meta.get("direction") == "UL"

    if uplink:
        inner_src, inner_dst = _UE_IP, _WEB_SERVER_IP
        sport, dport = meta["tcp_port"], _WEB_SERVER_PORT
        outer_src, outer_dst = gnodeb_ip, upf_ip
    else:
        inner_src, inner_dst = _WEB_SERVER_IP, _UE_IP
        sport, dport = _WEB_SERVER_PORT, meta["tcp_port"]
        outer_src, outer_dst = upf_ip, gnodeb_ip

    inner_ip_tcp = (
        IP(src=inner_src, dst=inner_dst, id=random.randint(0, 0xFFFF), ttl=meta["inner_ttl"])
        / TCP(sport=sport, dport=dport, seq=meta["tcp_seq"], ack=meta["tcp_ack"],
              flags=meta["tcp_flags"])
    )
    pad_len = max(0, payload_size - len(inner_ip_tcp))
    # Random bytes, not repeated filler: this models TLS-encrypted application
    # data, which is incompressible/high-entropy. Constant filler leaves a
    # zero-entropy signature that an entropy- or compression-ratio-based
    # detector can separate on, independently of the QoS anomaly under study.
    actual_payload = inner_ip_tcp / Raw(load=os.urandom(pad_len)) if pad_len > 0 else inner_ip_tcp

    gtp_packet = build_gtpu_packet_from_mutation(mutation, payload=actual_payload)

    wire_packet = (
        IP(src=outer_src, dst=outer_dst, tos=ctx.dscp_marking << 2, id=random.randint(0, 0xFFFF))
        / UDP(sport=2152, dport=2152)
        / gtp_packet
    )
    wire_packet.time = sim_time + gap_ms / 1000.0
    return wire_packet, gap_ms, payload_size


def create_web_browsing_stream(
    duration_minutes: float = 15.0,
    output_dir: str = "pcap_files",
    gnodeb_ip: str = "192.168.100.10",
    upf_ip: str = "192.168.100.20",
    max_packets: Optional[int] = None,
    model_name: str = MODEL_VARIANT,
    backend: str = "ollama",
    max_output_tokens: Optional[int] = None,
    llm_batch_size: int = 200,
) -> tuple:
    target_duration_sec = duration_minutes * 60.0
    ctx = _make_web_browsing_session()
    llm = LLMClient(model_name=model_name, backend=backend, max_output_tokens=max_output_tokens)

    print(f"5G GTP-U Web Browsing Baseline Stream Generator (5QI {WEB_BROWSING_5QI}, backend={backend}, model={model_name})")
    print(f"Target simulated duration: {duration_minutes:.1f} minutes ({target_duration_sec:.0f} s)")
    if max_packets:
        print(f"Hard arrival cap: {max_packets} LLM-generated traffic arrivals (pre-MTU-segmentation)")
    print("=" * 70)
    print("\n[Session State Context]")
    print(ctx.to_prompt_block())

    pcap_filename = generate_timestamped_filename(prefix="web_browsing_benign", output_dir=output_dir)
    json_filename = pcap_filename.replace(".pcap", "_telemetry.json")

    packets: List = []
    telemetry_records: List[Dict] = []
    total_bytes = 0
    packet_count = 0
    llm_arrivals_count = 0  # all arrivals fetched from batch calls (incl. leftovers never consumed)
    llm_arrivals_used = 0   # arrivals actually turned into wire packets — this is what max_packets bounds
    policy_violation_counts: Counter = Counter()
    flows_violating = 0

    sim_elapsed_sec = 0.0
    start_wall_time = time.time()
    current_sim_time = start_wall_time
    seq = 0

    print(f"\n[Generating packets until {target_duration_sec:.0f} s of simulated traffic is covered...]\n")

    llm_pending_queue: List[Dict] = []
    # A persistent LLM outage (rate limit, auth, provider down) makes every
    # batch return empty. Without a guard the loop would advance sim time by a
    # 100 ms fallback and retry for the whole remaining duration — thousands of
    # doomed API calls that look like a hang. Abort after this many consecutive
    # empty batches and write whatever was produced so far.
    consecutive_batch_failures = 0
    MAX_CONSECUTIVE_BATCH_FAILURES = 3

    # The reference is not needed to generate — only to seed the prompt's
    # few-shot examples and, afterwards, to score the result.
    if reference_models.load_5gnidd() is None:
        print("[WARN] 5G-NIDD reference missing (run extract_5gnidd_reference.py) — "
              "the prompt will carry no few-shot examples.")

    while sim_elapsed_sec < target_duration_sec and (max_packets is None or llm_arrivals_used < max_packets):
        if not llm_pending_queue:
            tokens_before = llm.total_completion_tokens
            calls_before = llm.call_count
            llm_pending_queue = llm.generate_benign_batch(
                ctx, batch_size=llm_batch_size, max_retries=3,
            )
            if not llm_pending_queue:
                consecutive_batch_failures += 1
                if consecutive_batch_failures >= MAX_CONSECUTIVE_BATCH_FAILURES:
                    print(f"[ERROR] {consecutive_batch_failures} batch calls failed in a row "
                          f"(see the [WARN] litellm generation failed line above for the cause) — "
                          f"stopping and writing the {packet_count} packets produced so far.")
                    break
                print(f"[WARN] Batch call failed after retries "
                      f"({consecutive_batch_failures}/{MAX_CONSECUTIVE_BATCH_FAILURES}) — retrying.")
                continue
            consecutive_batch_failures = 0
            llm_arrivals_count += len(llm_pending_queue)
            call_completion_tokens = llm.total_completion_tokens - tokens_before
            if llm.call_count > calls_before:
                print(
                    f"[TELEMETRY] Batch call: {len(llm_pending_queue)} packets for "
                    f"{call_completion_tokens} completion tokens "
                    f"(~{call_completion_tokens / len(llm_pending_queue):.1f} tokens/packet)"
                )
        pkt_json = llm_pending_queue.pop(0)
        llm_arrivals_used += 1
        if pkt_json.get("policy_violations"):
            flows_violating += 1
            policy_violation_counts.update(pkt_json["policy_violations"])
        # The LLM owns the SCORED quantities — the flow's total downlink bytes,
        # its arrival gap, and the uplink request size. The generator owns the
        # mechanical split into wire packets (_fragment_flow), which the model
        # adds no information to. flow_total == payload_size by construction.
        flow_total = pkt_json["payload_size"]
        segments, intra_gaps = _fragment_flow(flow_total)
        qfi = pkt_json["extension_headers"][0].get("qfi", WEB_BROWSING_QFI)

        # One short-lived TCP connection per flow: a fresh ephemeral UE port and
        # two ISNs (one per direction). Downlink seq advances by each segment's
        # TCP data length so an analyzer sees a consistent byte stream. The
        # downlink response arrives with a TTL already decremented across the
        # path (drawn per connection, not a constant — DATASET_VALIDATION #19).
        ue_port = random.randint(1024, 65535)
        dl_isn = random.randint(0, 0xFFFFFFFF)
        ul_isn = random.randint(0, 0xFFFFFFFF)
        inner_ttl = random.randint(52, 62)

        # events: (size, gap_ms, is_flow_start, direction, meta), in wire order.
        events = []

        # UPLINK REQUEST. The flow begins when the UE sends its request, so the
        # request's first packet is the flow-start marker and carries the
        # flow-arrival gap (inter_arrival_ms). It travels gNB -> UPF (pdu_type 1,
        # uplink TEID), inner UE -> server, with a fresh (un-decremented) TTL.
        # The uplink container is QFI-only (no RQI/PPI). The ACK stream back to
        # the server is NOT modelled — that is part of the TCP-lifecycle gap
        # (DATASET_VALIDATION #20).
        ul_ext = [{"type": 133, "pdu_type": 1, "qfi": qfi, "rqi": 0, "ppi": 0}]
        ul_off = 0
        req_chunks = _split_mtu(pkt_json["request_bytes"])
        for i, rsz in enumerate(req_chunks):
            events.append((
                rsz,
                pkt_json["inter_arrival_ms"] if i == 0 else 0.0,
                i == 0,
                "UL",
                {
                    "teid": WEB_BROWSING_UL_TEID,
                    "extension_headers": ul_ext,
                    "outer_dscp": pkt_json["outer_dscp"],
                    "anomaly_type": "benign",
                    "reasoning": pkt_json.get("reasoning", ""),
                    "payload_size": rsz,
                    "direction": "UL",
                    "tcp_port": ue_port,
                    "tcp_seq": (ul_isn + ul_off) % 0x100000000,
                    "tcp_ack": 0,
                    "tcp_flags": "PA",
                    "inner_ttl": 64,
                },
            ))
            ul_off += max(0, rsz - 40)

        # DOWNLINK RESPONSE. The server's packets, from the generator's split of
        # the LLM's payload total. The first follows the request immediately
        # (server think-time is not separately modelled — a 0 first gap); the
        # rest carry _fragment_flow's intra-flow spacing.
        dl_base = {
            "teid": ctx.teid,  # downlink TEID
            "extension_headers": pkt_json["extension_headers"],
            "outer_dscp": pkt_json["outer_dscp"],
            "anomaly_type": "benign",
            "reasoning": pkt_json.get("reasoning", ""),
            "direction": "DL",
            "tcp_port": ue_port,
            "tcp_ack": pkt_json["request_bytes"],
            "inner_ttl": inner_ttl,
        }
        dl_off = 0
        for i, seg in enumerate(segments):
            is_last = i == len(segments) - 1
            events.append((
                seg,
                intra_gaps[i],
                False,
                "DL",
                {
                    **dl_base,
                    "payload_size": seg,
                    "tcp_seq": (dl_isn + dl_off) % 0x100000000,
                    "tcp_flags": "PA" if is_last else "A",
                    **({"flow_total_bytes": flow_total} if i == 0 else {}),
                },
            ))
            dl_off += max(0, seg - 40)

        for size, gap_ms, is_flow_start, direction, meta in events:
            seq += 1

            wire_packet, gap_ms, payload_size = _build_wire_packet(
                ctx, meta, gnodeb_ip, upf_ip, current_sim_time, gap_ms
            )
            packets.append(wire_packet)
            total_bytes += len(wire_packet)
            packet_count += 1

            sim_elapsed_sec += gap_ms / 1000.0
            current_sim_time += gap_ms / 1000.0

            telemetry_records.append({
                "seq": seq,
                "payload_size_bytes": payload_size,
                "inter_arrival_ms": gap_ms,
                "is_flow_start": is_flow_start,
                "direction": direction,
                "flow_total_bytes": meta.get("flow_total_bytes"),
                "sim_time_sec": round(sim_elapsed_sec, 3),
            })

            print(
                f"  Pkt #{seq:4d} | {direction} | size={payload_size:5d}B | gap={gap_ms:7.1f}ms"
                f" | sim={sim_elapsed_sec:7.1f}s / {target_duration_sec:.0f}s"
            )

    llm_arrivals_unused = len(llm_pending_queue)

    wrpcap(pcap_filename, packets)
    avg_payload = total_bytes / max(packet_count, 1)
    # Only a flow's first segment carries a real LLM-sampled gap; the rest are
    # sub-millisecond wire-segmentation gaps that would swamp the average.
    flow_start_records = [r for r in telemetry_records if r["is_flow_start"]]
    avg_iat_ms = (
        sum(r["inter_arrival_ms"] for r in flow_start_records) / len(flow_start_records)
        if flow_start_records else 0.0
    )
    # Direct throughput measure — not sensitive to segmentation granularity,
    # unlike an average of per-segment size/gap ratios.
    achieved_bps = (total_bytes * 8.0) / sim_elapsed_sec if sim_elapsed_sec > 0 else 0.0

    telemetry_data = {
        "experiment_type": "web_browsing_benign_llm_stream",
        "generation_mode": "llm",
        "model_name": model_name,
        "5qi": WEB_BROWSING_5QI,
        "qfi": WEB_BROWSING_QFI,
        "timestamp": datetime.now().isoformat(),
        "pcap_file": pcap_filename,
        "target_duration_minutes": duration_minutes,
        "simulated_duration_seconds": round(sim_elapsed_sec, 2),
        "packet_count": packet_count,
        "total_bytes": total_bytes,
        "avg_packet_size_bytes": round(avg_payload, 2),
        "avg_flow_inter_arrival_ms": round(avg_iat_ms, 2),
        "achieved_bitrate_bps": round(achieved_bps, 1),
        "benign_policy_violations": dict(policy_violation_counts) or None,
        "llm_usage": {
            "api_call_count": llm.call_count,
            "total_prompt_tokens": llm.total_prompt_tokens,
            "total_completion_tokens": llm.total_completion_tokens,
            "llm_arrivals_count": llm_arrivals_count,
            "llm_arrivals_used": llm_arrivals_used,
            "llm_arrivals_unused": llm_arrivals_unused,
            "avg_completion_tokens_per_packet": (
                round(llm.total_completion_tokens / llm_arrivals_count, 1) if llm_arrivals_count else None
            ),
            "avg_prompt_tokens_per_call": (
                round(llm.total_prompt_tokens / llm.call_count, 1) if llm.call_count else None
            ),
        },
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

    print(" WEB BROWSING STREAM COMPLETED \n")
    print(f" PCAP file          : {pcap_filename}")
    print(f" Telemetry JSON     : {json_filename}")
    print(f" Packets generated  : {packet_count}")
    print(f" Simulated duration : {sim_elapsed_sec:.1f} s ({sim_elapsed_sec/60:.2f} min)")
    print(f" Avg payload size   : {telemetry_data['avg_packet_size_bytes']} bytes")
    print(f" Avg flow IAT       : {telemetry_data['avg_flow_inter_arrival_ms']} ms")
    print(f" Achieved bitrate   : {achieved_bps/1e6:.2f} Mbps")
    if flows_violating:
        print(f" [WARN] Policy guard: {flows_violating}/{llm_arrivals_used} benign flows violated session policy")
        print(f"                      {dict(policy_violation_counts)}")
    if llm.call_count:
        print(
            f" LLM API calls      : {llm.call_count} "
            f"({llm.total_prompt_tokens} prompt / {llm.total_completion_tokens} completion tokens)"
        )
    if llm_arrivals_count:
        print(
            f" LLM arrivals       : {llm_arrivals_used} used / {llm_arrivals_count} generated "
            f"(~{telemetry_data['llm_usage']['avg_completion_tokens_per_packet']} completion "
            f"tokens/packet, ~{telemetry_data['llm_usage']['avg_prompt_tokens_per_call']} prompt tokens/call)"
        )
        if llm_arrivals_unused:
            print(
                f" [INFO] {llm_arrivals_unused} generated arrival(s) from the last batch call went "
                f"unused (duration/arrival cap hit mid-batch) — no extra API cost, but that "
                f"batch's diversity wasn't fully exploited."
            )
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
    parser.add_argument(
        "--max-packets",
        type=int,
        default=None,
        help=(
            "Stop after this many LLM-generated traffic arrivals (not wire "
            "packets/segments — a single arrival can still expand into several "
            "MTU-sized wire packets) regardless of --duration. Use this to bound "
            "the run to a predictable, small arrival/call count."
        ),
    )
    parser.add_argument(
        "--model",
        type=str,
        default=MODEL_VARIANT,
        help=(
            f"Model tag to use (default: {MODEL_VARIANT}). "
            "For --backend ollama this must already be pulled on the Ollama server "
            "(see `ollama list`). For --backend openai this is the OpenAI model id."
        ),
    )
    parser.add_argument(
        "--backend",
        choices=["ollama", "openai"],
        default="ollama",
        help=(
            "'ollama' (default): local self-hosted model at SELF_HOSTED_MODELS_URL. "
            "'openai': call the OpenAI API instead — requires OPENAI_API_KEY in the "
            "environment and --model set to a valid OpenAI model id."
        ),
    )
    parser.add_argument(
        "--max-output-tokens",
        type=int,
        default=None,
        help="Ceiling applied to every LLM call's max_tokens (e.g. 50000). Default: no extra ceiling.",
    )
    parser.add_argument(
        "--llm-batch-size",
        type=int,
        default=200,
        help=(
            "Packets requested per LLM call (default: 200 — tested to "
            "sustain diversity/consistency across a single call with no degradation). "
            "Set this >= --max-packets for a small test run to avoid a visible seam "
            "between batches."
        ),
    )

    args = parser.parse_args()
    create_web_browsing_stream(
        duration_minutes=args.duration,
        output_dir=args.output_dir,
        max_packets=args.max_packets,
        model_name=args.model,
        backend=args.backend,
        max_output_tokens=args.max_output_tokens,
        llm_batch_size=args.llm_batch_size,
    )
