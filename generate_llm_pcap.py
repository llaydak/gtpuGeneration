"""Script to generate realistic GTP-U traffic streams and PCAP traces.

Supports:
1. Web Browsing benign baseline stream (5QI 6, LLM-driven, configurable duration).
2. LLM-driven adversarial attack stream (benign baseline + injected attack packets).
"""

import os
import json
import random
import time
from datetime import datetime
from typing import Optional, List, Dict

from scapy.all import IP, UDP, TCP, Raw, wrpcap
from llm_client import LLMClient
from session_context import SessionContext
from packet_model import GTP_U_Mutation
from gtpu_scapy import build_gtpu_packet_from_mutation, MODEL_VARIANT

# Table II of the reference paper (Nikolaidis et al., NOMS 2023): per-5QI
# eMBB feature statistics. R5QI in bps, T5QI in ms, P5QI = R5QI*T5QI in bytes.
TABLE_II_5QI_STATS = {\
    
    3: {"name": "Online Gaming", "r_bps": 15_000_000, "t_ms": 20.0, "p_bytes": 37_500, "d_ms": 30, "a": 0.019},
    4: {"name": "Buffered Video", "r_bps": 12_000_000, "t_ms": 100.0, "p_bytes": 150_000, "d_ms": 280, "a": 0.13},
    6: {"name": "Web Browsing", "r_bps": 5_000_000, "t_ms": 100.0, "p_bytes": 62_500, "d_ms": 280, "a": 0.641},
}

# Max inner (TCP) payload per wire packet. 
_MAX_SEGMENT_BYTES = 1400

#1 Gbps is a typical gNB-to-UPF N3 backhaul rate.
_N3_LINK_BPS = 1_000_000_000
# Multiplicative jitter on serialization delay, standing in for queueing /
# scheduling variation so gaps aren't perfectly deterministic either. Widened
# from a near-constant band so the intra-burst spacing isn't a single spike a
# statistical IDS could separate on.
_INTRA_BURST_JITTER_RANGE = (1.0, 4.0)
# Occasional larger gap within a burst, modelling an ACK-clock / RAN-scheduler
# pause rather than an uninterrupted line-rate drain. Kept rare/small so the
# accumulated intra-burst time stays a low-single-digit % of the run and the
# achieved bitrate remains tied to the LLM's burst-arrival gaps.
_INTRA_BURST_PAUSE_PROB = 0.03
_INTRA_BURST_PAUSE_RANGE_MS = (0.2, 0.8)
# Floor so a tiny segment still can't produce a zero/degenerate gap.
_MIN_INTRA_BURST_GAP_MS = 0.005

# Real downlink web-browsing packet sizes are bimodal, not a single MTU spike:
# a dominant mode of large data segments plus a minority of small packets
# (small-object responses, TLS/HTTP-2 control records, response tails). Each
# burst's byte budget is re-sliced into that mix so the size histogram matches
# real traffic, while the burst TOTAL — and therefore the achieved bitrate — is
# preserved exactly.
_SMALL_SEGMENT_FRACTION = 0.25          # share of segments drawn from the small mode
_SMALL_SEGMENT_RANGE = (40, 400)        # bytes (40 ≈ header-only / ACK-sized)
_LARGE_SEGMENT_RANGE = (1000, _MAX_SEGMENT_BYTES)


def _segment_burst_sizes(total_bytes: int) -> List[int]:
    sizes: List[int] = []
    remaining = total_bytes
    while remaining > 0:
        if random.random() < _SMALL_SEGMENT_FRACTION:
            seg = random.randint(*_SMALL_SEGMENT_RANGE)
        else:
            seg = random.randint(*_LARGE_SEGMENT_RANGE)
        seg = min(seg, remaining)
        sizes.append(seg)
        remaining -= seg
    return sizes

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


def _build_wire_packet(
    ctx: SessionContext,
    pkt_json: Dict,
    gnodeb_ip: str,
    upf_ip: str,
    seq: int,
    sim_time: float,
):
    
    mutation = GTP_U_Mutation.from_json(ctx, pkt_json)

    payload_size = mutation.payload_size if mutation.payload_size else 250
    inner_ip_tcp = (
        IP(
            src=_WEB_SERVER_IP,
            dst=_UE_IP,
            id=random.randint(0, 0xFFFF),
            ttl=pkt_json["inner_ttl"],
        )
        / TCP(
            sport=_WEB_SERVER_PORT,
            dport=pkt_json["tcp_dport"],
            seq=pkt_json["tcp_seq"],
            ack=pkt_json["tcp_ack"],
            flags=pkt_json["tcp_flags"],
        )
    )
    pad_len = max(0, payload_size - len(inner_ip_tcp))
    # Random bytes, not repeated filler: this models TLS-encrypted application
    # data, which is incompressible/high-entropy. Constant filler leaves a
    # zero-entropy signature that an entropy- or compression-ratio-based
    # detector can separate on, independently of the QoS anomaly under study.
    actual_payload = inner_ip_tcp / Raw(load=os.urandom(pad_len)) if pad_len > 0 else inner_ip_tcp

    gtp_packet = build_gtpu_packet_from_mutation(mutation, payload=actual_payload)
    gtp_packet.seq = seq % 0x10000  # GTP sequence number is a 16-bit field

    inter_arrival_ms = mutation.inter_arrival_ms if mutation.inter_arrival_ms else _5QI6_NOMINAL_T_MS

    wire_packet = (
        IP(
            src=upf_ip,
            dst=gnodeb_ip,
            tos=ctx.dscp_marking << 2,
            id=random.randint(0, 0xFFFF),
        )
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

    sim_elapsed_sec = 0.0
    start_wall_time = time.time()
    current_sim_time = start_wall_time
    seq = 0

    print(f"\n[Generating packets until {target_duration_sec:.0f} s of simulated traffic is covered...]\n")

    llm_pending_queue: List[Dict] = []

    ref_stats = TABLE_II_5QI_STATS[WEB_BROWSING_5QI]

    while sim_elapsed_sec < target_duration_sec and (max_packets is None or llm_arrivals_used < max_packets):
        if not llm_pending_queue:
            tokens_before = llm.total_completion_tokens
            calls_before = llm.call_count
            llm_pending_queue = llm.generate_benign_batch(
                ctx, batch_size=llm_batch_size, max_retries=3,
            )
            if not llm_pending_queue:
                print(f"[WARN] Batch call failed after retries — skipping slot #{seq + 1}.")
                sim_elapsed_sec += _5QI6_NOMINAL_T_MS / 1000.0
                continue
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
        # Split the LLM's burst total into MTU-sized wire segments — a single
        # 50KB+ frame isn't a realistic wire packet. Only the fields
        # GTP_U_Mutation.from_json/telemetry actually read are carried per
        # segment — not a full pkt_json copy, which would be repeated on
        # every one of a burst's ~40-50 segments.
        segment_base = {
            "teid": pkt_json.get("teid", ctx.teid),
            "extension_headers": pkt_json["extension_headers"],
            "outer_dscp": pkt_json["outer_dscp"],
            "anomaly_type": pkt_json.get("anomaly_type", "benign"),
            "reasoning": pkt_json.get("reasoning", ""),
            "raw_llm_compliant": pkt_json.get("raw_llm_compliant"),
            "session_consistent": pkt_json.get("session_consistent"),
        }
        segments = _segment_burst_sizes(pkt_json["payload_size"])

        # Each arrival is its own TCP connection — real web browsing opens
        # many short-lived parallel connections rather than reusing one flow
        # — so it gets a fresh ephemeral UE-side port and initial sequence
        # number. The sequence number then advances across the burst's own
        # MTU segments by each segment's actual TCP data length (segment
        # size minus the fixed 40-byte IP/TCP header), so a packet analyzer
        # sees a normal, internally-consistent TCP byte stream instead of a
        # repeated static header. TTL is per-connection too: a real response
        # from an internet server arrives already decremented by the path's
        # hop count, and different servers/paths differ.
        tcp_dport = random.randint(1024, 65535)
        tcp_isn = random.randint(0, 0xFFFFFFFF)
        tcp_ack = random.randint(400, 2000)  # plausible HTTP request size
        inner_ttl = random.randint(52, 62)
        byte_offset = 0
        batch = []
        for i, seg in enumerate(segments):
            is_last = i == len(segments) - 1
            # First segment carries the real burst-arrival gap; the rest are
            # spaced by their own serialization time at N3 line rate plus
            # jitter (see _N3_LINK_BPS), not a fixed constant.
            if i == 0:
                gap_ms = pkt_json["inter_arrival_ms"]
            else:
                gap_ms = max(
                    _MIN_INTRA_BURST_GAP_MS,
                    (seg * 8.0 / _N3_LINK_BPS) * 1000.0
                    * random.uniform(*_INTRA_BURST_JITTER_RANGE),
                )
                if random.random() < _INTRA_BURST_PAUSE_PROB:
                    gap_ms += random.uniform(*_INTRA_BURST_PAUSE_RANGE_MS)
            batch.append((
                seg,
                gap_ms,
                i == 0,
                {
                    **segment_base,
                    "payload_size": seg,
                    "inter_arrival_ms": gap_ms,
                    "tcp_dport": tcp_dport,
                    "tcp_seq": (tcp_isn + byte_offset) % 0x100000000,
                    "tcp_ack": tcp_ack,
                    "tcp_flags": "PA" if is_last else "A",
                    "inner_ttl": inner_ttl,
                },
            ))
            byte_offset += max(0, seg - 40)

        for payload_size, inter_arrival_ms, is_burst_start, meta in batch:
            seq += 1

            wire_packet, inter_arrival_ms, payload_size = _build_wire_packet(
                ctx, meta, gnodeb_ip, upf_ip, seq, current_sim_time
            )
            packets.append(wire_packet)
            total_bytes += len(wire_packet)
            packet_count += 1

            sim_elapsed_sec += inter_arrival_ms / 1000.0
            current_sim_time += inter_arrival_ms / 1000.0

            telemetry_records.append({
                "seq": seq,
                "payload_size_bytes": payload_size,
                "inter_arrival_ms": inter_arrival_ms,
                "is_burst_start": is_burst_start,
                "sim_time_sec": round(sim_elapsed_sec, 3),
                "raw_llm_compliant": meta.get("raw_llm_compliant"),
                "session_consistent": meta.get("session_consistent"),
                "reasoning": meta.get("reasoning", ""),
            })

            print(
                f"  Pkt #{seq:4d} | size={payload_size:5d}B | iat={inter_arrival_ms:7.1f}ms"
                f" | sim={sim_elapsed_sec:7.1f}s / {target_duration_sec:.0f}s"
                f" | compliant={meta.get('raw_llm_compliant')}"
            )

    llm_arrivals_unused = len(llm_pending_queue)

    wrpcap(pcap_filename, packets)
    avg_payload = total_bytes / max(packet_count, 1)
    # Burst-arrival inter-arrival time (comparable to Table II's T5QI): only
    # each burst's first segment carries a real LLM-sampled gap. The rest are
    # sub-millisecond intra-burst wire-segmentation gaps (serialization at
    # _N3_LINK_BPS plus jitter/pauses) and would otherwise swamp the average.
    burst_start_records = [r for r in telemetry_records if r["is_burst_start"]]
    avg_iat_ms = (
        sum(r["inter_arrival_ms"] for r in burst_start_records) / len(burst_start_records)
        if burst_start_records else 0.0
    )
    # Direct throughput measure — not sensitive to segmentation granularity,
    # unlike an average of per-segment size/gap ratios.
    achieved_bps = (total_bytes * 8.0) / sim_elapsed_sec if sim_elapsed_sec > 0 else 0.0

    llm_judged = [r for r in telemetry_records if r["raw_llm_compliant"] is not None]

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
        "avg_burst_inter_arrival_ms": round(avg_iat_ms, 2),
        "achieved_bitrate_bps": round(achieved_bps, 1),
        "table_ii_reference": {
            "r_bps": ref_stats["r_bps"],
            "t_ms": ref_stats["t_ms"],
            "p_bytes": ref_stats["p_bytes"],
        },
        "llm_compliance_rate": (
            round(sum(1 for r in llm_judged if r["raw_llm_compliant"]) / len(llm_judged), 4)
            if llm_judged else None
        ),
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
    print(f" Avg burst IAT      : {telemetry_data['avg_burst_inter_arrival_ms']} ms (Table II T5QI={ref_stats['t_ms']:.0f} ms)")
    print(f" Achieved bitrate   : {achieved_bps/1e6:.2f} Mbps (Table II R5QI={ref_stats['r_bps']/1e6:.2f} Mbps)")
    if telemetry_data["llm_compliance_rate"] is not None:
        print(f" LLM compliance     : {telemetry_data['llm_compliance_rate']*100:.1f}% ({len(llm_judged)} sampled)")
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
