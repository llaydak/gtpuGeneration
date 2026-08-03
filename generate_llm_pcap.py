"""Script to generate realistic GTP-U traffic streams and PCAP traces.

Supports:
1. Web Browsing benign baseline stream (5QI 6, LLM-driven, configurable duration).
2. LLM-driven adversarial attack stream (benign baseline + injected attack packets).
"""

import os
import json
import math
import random
import struct
import time
from datetime import datetime
from typing import Optional, List, Dict

from scapy.all import IP, UDP, ICMP, Raw, wrpcap
from scapy.utils import PcapWriter
from mistral_client import MistralClient
from session_context import SessionContext
from packet_model import GTP_U_Mutation
from gtpu_scapy import build_gtpu_packet_from_mutation, MODEL_VARIANT

# Table II of the reference paper (Nikolaidis et al., NOMS 2023): per-5QI
# eMBB feature statistics. R5QI in bps, T5QI in ms, P5QI = R5QI*T5QI in bytes.
TABLE_II_5QI_STATS = {
    3: {"name": "Online Gaming", "r_bps": 15_000_000, "t_ms": 20.0, "p_bytes": 37_500, "d_ms": 30, "a": 0.019},
    4: {"name": "Buffered Video", "r_bps": 12_000_000, "t_ms": 100.0, "p_bytes": 150_000, "d_ms": 280, "a": 0.13},
    6: {"name": "Web Browsing", "r_bps": 5_000_000, "t_ms": 100.0, "p_bytes": 62_500, "d_ms": 280, "a": 0.641},
}

# Coefficient of variation for the per-arrival payload-size distribution.
# The paper treats Pu as a fixed per-class value (Sec. II); we instead draw
# each arrival's total size from a lognormal centered on P5QI so consecutive
# arrivals aren't byte-identical, while the long-run average still matches R5QI.
_PAYLOAD_SIZE_CV = 0.3

# Max inner (ICMP) payload per wire packet. P5QI for some 5QIs (e.g. 62.5 KB
# for web browsing) is far larger than a real Ethernet-MTU packet.
_MAX_SEGMENT_BYTES = 1400
# Gap between segments of the same burst (they arrive back-to-back on the wire).
_INTRA_BURST_GAP_MS = 1.0


def _sample_table_ii_burst(five_qi: int) -> list:
    """Sample one traffic arrival from the paper's Table II stats, split into
    MTU-sized wire segments.

    Returns a list of (payload_size_bytes, inter_arrival_ms) tuples: the first
    tuple's inter_arrival_ms is the gap since the previous arrival (~
    Exponential(mean=T5QI), per Eq. 2), the rest use a small fixed intra-burst
    gap. Segment sizes sum to a lognormal sample centered on P5QI, so the
    average bitrate over many arrivals converges to R5QI.
    """
    stats = TABLE_II_5QI_STATS[five_qi]
    inter_arrival_ms = random.expovariate(1.0 / stats["t_ms"])

    mean = stats["p_bytes"]
    sigma2 = math.log(1.0 + _PAYLOAD_SIZE_CV ** 2)
    mu = math.log(mean) - sigma2 / 2.0
    total_bytes = max(1, int(round(random.lognormvariate(mu, math.sqrt(sigma2)))))

    segments = []
    remaining = total_bytes
    while remaining > 0:
        seg = min(remaining, _MAX_SEGMENT_BYTES)
        segments.append(seg)
        remaining -= seg

    return [
        (seg, inter_arrival_ms if i == 0 else _INTRA_BURST_GAP_MS)
        for i, seg in enumerate(segments)
    ]


def _checksum16(data: bytes) -> int:
    """Standard 16-bit ones'-complement checksum (IPv4 header / ICMP)."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    total = (total & 0xFFFF) + (total >> 16)
    total += total >> 16
    return (~total) & 0xFFFF


class _FastSessionPacketBuilder:
    """Builds wire packets for a fixed benign session by byte-patching a
    prebuilt template instead of reconstructing the full Scapy layer stack
    per packet.

    For a single-QFI benign stream, QFI/RQI/PPI/DSCP/extension headers never
    change packet-to-packet within a session — only the payload size does. So
    only a handful of length/checksum fields actually need recomputing per
    packet. Rebuilding all ~6 Scapy layers from scratch for every packet is
    what made an earlier attempt at MTU-segmented bursts too slow at 250k+
    packets (multi-minute stall); this only touches ~20 bytes per packet.
    """

    _ICMP_HEADER_LEN = 8
    _INNER_IP_HEADER_LEN = 20
    _OUTER_IP_HEADER_LEN = 20
    _OUTER_UDP_HEADER_LEN = 8
    MIN_PAYLOAD_SIZE = _INNER_IP_HEADER_LEN + _ICMP_HEADER_LEN  # 28

    def __init__(self, ctx: SessionContext, gnodeb_ip: str, upf_ip: str):
        qfi = ctx.active_qfis[0]
        rqi = 1 if qfi in ctx.reflective_qos_enabled_qfis else 0
        mutation = GTP_U_Mutation.from_json(ctx, {
            "extension_headers": [{"type": 133, "pdu_type": 0, "qfi": qfi, "rqi": rqi, "ppi": 0}],
            "outer_dscp": ctx.dscp_marking,
            "anomaly_type": "benign",
        })
        base_inner_payload = IP(src="10.45.0.2", dst="8.8.8.8") / ICMP(type=8, code=0)
        gtp_packet = build_gtpu_packet_from_mutation(mutation, payload=base_inner_payload)
        template = (
            IP(src=gnodeb_ip, dst=upf_ip, tos=ctx.dscp_marking << 2)
            / UDP(sport=2152, dport=2152)
            / gtp_packet
        )
        template_bytes = bytes(template)

        self._gtp_start = self._OUTER_IP_HEADER_LEN + self._OUTER_UDP_HEADER_LEN
        gtp_and_inner_len = len(template_bytes) - self._gtp_start
        # Everything between the mandatory 8-byte GTP header and the T-PDU
        # (optional seq/npdu/next-ext fields + the extension header chain) is
        # fixed for this session, so measure it once from the built template
        # rather than hardcoding 3GPP field-length assumptions.
        self._gtp_prefix_len = gtp_and_inner_len - len(bytes(base_inner_payload))
        self._inner_start = self._gtp_start + self._gtp_prefix_len
        self._icmp_start = self._inner_start + self._INNER_IP_HEADER_LEN
        self._prefix = bytes(template_bytes[: self._icmp_start + self._ICMP_HEADER_LEN])

    def build(self, payload_size: int, seq: int) -> bytes:
        """Return the raw wire bytes (outer IP through inner ICMP+filler) for
        one segment. Returned as plain bytes rather than a Scapy Packet: a
        PcapWriter needs a registered Scapy class to infer linktype from a
        Packet object, which a bare Raw(...) doesn't have — passing bytes
        directly with an explicit linktype on the writer sidesteps that
        entirely, and also skips constructing ~270k Packet objects."""
        payload_size = max(payload_size, self.MIN_PAYLOAD_SIZE)
        filler_len = payload_size - self.MIN_PAYLOAD_SIZE

        buf = bytearray(self._prefix)
        buf += b"X" * filler_len

        inner_ip_total_len = self._INNER_IP_HEADER_LEN + self._ICMP_HEADER_LEN + filler_len
        gtp_length = (self._gtp_prefix_len - 8) + inner_ip_total_len  # bytes after mandatory 8B GTP header
        udp_len = self._OUTER_UDP_HEADER_LEN + 8 + gtp_length
        ip_total_len = self._OUTER_IP_HEADER_LEN + udp_len

        struct.pack_into("!H", buf, self._gtp_start + 8, seq % 0x10000)  # GTP sequence number (16-bit, wraps)
        struct.pack_into("!H", buf, self._gtp_start + 2, gtp_length)
        struct.pack_into("!H", buf, self._OUTER_IP_HEADER_LEN + 4, udp_len)
        struct.pack_into("!H", buf, self._OUTER_IP_HEADER_LEN + 6, 0)  # UDP checksum disabled (valid for IPv4)

        struct.pack_into("!H", buf, 2, ip_total_len)
        struct.pack_into("!H", buf, 10, 0)
        struct.pack_into("!H", buf, 10, _checksum16(bytes(buf[0:20])))

        struct.pack_into("!H", buf, self._inner_start + 2, inner_ip_total_len)
        struct.pack_into("!H", buf, self._inner_start + 10, 0)
        struct.pack_into(
            "!H", buf, self._inner_start + 10,
            _checksum16(bytes(buf[self._inner_start: self._inner_start + self._INNER_IP_HEADER_LEN])),
        )

        struct.pack_into("!H", buf, self._icmp_start + 2, 0)
        struct.pack_into("!H", buf, self._icmp_start + 2, _checksum16(bytes(buf[self._icmp_start:])))

        return bytes(buf)

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
    gtp_packet.seq = seq % 0x10000  # GTP sequence number is a 16-bit field

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
    mode: str = "stats",
    progress_every: int = 200,
    max_packets: Optional[int] = None,
    model_name: str = MODEL_VARIANT,
    backend: str = "ollama",
    max_output_tokens: Optional[int] = None,
    llm_batch_size: int = 20,
) -> tuple:
    """Generate a 5QI 6 (Web Browsing) benign GTP-U stream for the given duration.

    Two generation modes:
      - "stats" (default, fast): payload_size/inter_arrival_ms are sampled from
        the reference paper's Table II per-5QI statistics (see
        _sample_table_ii_packet). Session/header fields (QFI, RQI, DSCP) are
        deterministic from the session context. No LLM calls on the hot path,
        so 10+ minutes of simulated traffic generate in seconds.
      - "llm" (slow): payload_size and inter_arrival_ms come from LLM calls,
        llm_batch_size packets per call (see MistralClient.generate_benign_batch).
        Still much slower than "stats", so use max_packets to bound the run to
        a predictable packet/call count instead of targeting a full duration.

    Returns:
        tuple: (path_to_pcap_file, path_to_telemetry_json)
    """
    if mode not in ("stats", "llm"):
        raise ValueError(f"mode must be 'stats' or 'llm', got {mode!r}")

    target_duration_sec = duration_minutes * 60.0
    ctx = _make_web_browsing_session()
    mistral = MistralClient(model_name=model_name, backend=backend, max_output_tokens=max_output_tokens)

    print(f"5G GTP-U Web Browsing Baseline Stream Generator (5QI {WEB_BROWSING_5QI}, mode={mode}, backend={backend}, model={model_name})")
    print(f"Target simulated duration: {duration_minutes:.1f} minutes ({target_duration_sec:.0f} s)")
    if max_packets:
        print(f"Hard packet cap: {max_packets}")
    print("=" * 70)
    print("\n[Session State Context]")
    print(ctx.to_prompt_block())

    pcap_filename = generate_timestamped_filename(prefix="web_browsing_benign", output_dir=output_dir)
    json_filename = pcap_filename.replace(".pcap", "_telemetry.json")

    packets: List = []  # used only in "llm" mode (small counts, kept as Scapy objects)
    telemetry_records: List[Dict] = []
    base_inner_payload = IP(src="10.45.0.2", dst="8.8.8.8") / ICMP(type=8, code=0)
    fast_builder = _FastSessionPacketBuilder(ctx, gnodeb_ip, upf_ip) if mode == "stats" else None
    # "stats" mode writes raw bytes straight to disk as it goes (see
    # _FastSessionPacketBuilder.build docstring) instead of accumulating a
    # Python list of ~270k packet objects for a 15-min run.
    pcap_writer = PcapWriter(pcap_filename, linktype=101) if mode == "stats" else None
    if pcap_writer is not None:
        # write_packet() alone never emits the global pcap header — only the
        # higher-level write() does that on its first call. Since we call
        # write_packet() directly (to control timestamps per segment), the
        # header has to be written explicitly or the file is corrupt.
        pcap_writer.write_header(None)
    total_bytes = 0
    packet_count = 0

    sim_elapsed_sec = 0.0
    start_wall_time = time.time()
    current_sim_time = start_wall_time
    seq = 0

    print(f"\n[Generating packets until {target_duration_sec:.0f} s of simulated traffic is covered...]\n")

    llm_pending_queue: List[Dict] = []  # only used when llm_batch_size > 0

    ref_stats = TABLE_II_5QI_STATS[WEB_BROWSING_5QI]

    try:
        while sim_elapsed_sec < target_duration_sec and (max_packets is None or seq < max_packets):
            if mode == "llm":
                if not llm_pending_queue:
                    llm_pending_queue = mistral.generate_benign_batch(
                        ctx, batch_size=llm_batch_size, max_retries=3,
                        reference_bitrate_bps=ref_stats["r_bps"],
                        reference_inter_arrival_ms=ref_stats["t_ms"],
                    )
                    if not llm_pending_queue:
                        print(f"[WARN] Batch call failed after retries — skipping slot #{seq + 1}.")
                        sim_elapsed_sec += _5QI6_NOMINAL_T_MS / 1000.0
                        continue
                pkt_json = llm_pending_queue.pop(0)
                # Split the LLM's burst total into MTU-sized wire segments,
                # same as _sample_table_ii_burst does for "stats" mode — a
                # single 50KB+ frame isn't a realistic wire packet. Only the
                # fields GTP_U_Mutation.from_json/telemetry actually read are
                # carried per segment — not a full pkt_json copy (which would
                # duplicate its sanitization_log/raw_model_output on every
                # one of a burst's ~40-50 segments).
                segment_base = {
                    "teid": pkt_json.get("teid", ctx.teid),
                    "extension_headers": pkt_json["extension_headers"],
                    "outer_dscp": pkt_json["outer_dscp"],
                    "anomaly_type": pkt_json.get("anomaly_type", "benign"),
                    "reasoning": pkt_json.get("reasoning", ""),
                    "raw_llm_compliant": pkt_json.get("raw_llm_compliant"),
                    "session_consistent": pkt_json.get("session_consistent"),
                }
                segments = []
                remaining = pkt_json["payload_size"]
                while remaining > 0:
                    seg = min(remaining, _MAX_SEGMENT_BYTES)
                    segments.append(seg)
                    remaining -= seg
                batch = [
                    (
                        seg,
                        pkt_json["inter_arrival_ms"] if i == 0 else _INTRA_BURST_GAP_MS,
                        {
                            **segment_base,
                            "payload_size": seg,
                            "inter_arrival_ms": pkt_json["inter_arrival_ms"] if i == 0 else _INTRA_BURST_GAP_MS,
                        },
                    )
                    for i, seg in enumerate(segments)
                ]
            else:
                stats_meta = {
                    "raw_llm_compliant": None,
                    "session_consistent": True,
                    "reasoning": f"Sampled from Table II stats for 5QI {WEB_BROWSING_5QI} (no LLM call).",
                }
                batch = [
                    (size, iat, stats_meta) for size, iat in _sample_table_ii_burst(WEB_BROWSING_5QI)
                ]

            for payload_size, inter_arrival_ms, meta in batch:
                seq += 1

                if mode == "llm":
                    wire_packet, inter_arrival_ms, payload_size = _build_wire_packet(
                        ctx, meta, base_inner_payload, gnodeb_ip, upf_ip, seq, current_sim_time
                    )
                    packets.append(wire_packet)
                    total_bytes += len(wire_packet)
                else:
                    pkt_time = current_sim_time + inter_arrival_ms / 1000.0
                    raw_bytes = fast_builder.build(payload_size, seq)
                    pcap_writer.write_packet(
                        raw_bytes, sec=int(pkt_time), usec=int(round((pkt_time % 1) * 1_000_000))
                    )
                    total_bytes += len(raw_bytes)
                packet_count += 1

                sim_elapsed_sec += inter_arrival_ms / 1000.0
                current_sim_time += inter_arrival_ms / 1000.0

                telemetry_records.append({
                    "seq": seq,
                    "payload_size_bytes": payload_size,
                    "inter_arrival_ms": inter_arrival_ms,
                    "sim_time_sec": round(sim_elapsed_sec, 3),
                    "raw_llm_compliant": meta.get("raw_llm_compliant"),
                    "session_consistent": meta.get("session_consistent"),
                    "reasoning": meta.get("reasoning", ""),
                })

                if mode == "llm" or seq % progress_every == 0:
                    print(
                        f"  Pkt #{seq:4d} | size={payload_size:5d}B | iat={inter_arrival_ms:7.1f}ms"
                        f" | sim={sim_elapsed_sec:7.1f}s / {target_duration_sec:.0f}s"
                        f" | compliant={meta.get('raw_llm_compliant')}"
                    )
    finally:
        if pcap_writer is not None:
            pcap_writer.close()

    if mode == "llm":
        wrpcap(pcap_filename, packets)
    avg_payload = total_bytes / max(packet_count, 1)
    avg_iat_ms = sum(r["inter_arrival_ms"] for r in telemetry_records) / max(len(telemetry_records), 1)
    achieved_bps = (avg_payload * 8.0) / (avg_iat_ms / 1000.0) if avg_iat_ms > 0 else 0.0

    llm_judged = [r for r in telemetry_records if r["raw_llm_compliant"] is not None]

    telemetry_data = {
        "experiment_type": "web_browsing_benign_llm_stream",
        "generation_mode": mode,
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
        "avg_inter_arrival_ms": round(avg_iat_ms, 2),
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
    print(f" Avg inter-arrival  : {telemetry_data['avg_inter_arrival_ms']} ms")
    print(f" Achieved bitrate   : {achieved_bps/1e6:.2f} Mbps (Table II R5QI={ref_stats['r_bps']/1e6:.2f} Mbps)")
    if telemetry_data["llm_compliance_rate"] is not None:
        print(f" LLM compliance     : {telemetry_data['llm_compliance_rate']*100:.1f}% ({len(llm_judged)} sampled)")
    if mistral.call_count:
        print(
            f" LLM API calls      : {mistral.call_count} "
            f"({mistral.total_prompt_tokens} prompt / {mistral.total_completion_tokens} completion tokens)"
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
        "--mode",
        choices=["stats", "llm"],
        default="stats",
        help=(
            "'stats' (default): fast, payload/timing sampled from the paper's Table II "
            "per-5QI stats, no LLM in the hot loop. 'llm': slower, packet fields come "
            "from LLM batch calls (impractical beyond small demo runs)."
        ),
    )
    parser.add_argument(
        "--max-packets",
        type=int,
        default=None,
        help=(
            "Stop after this many packets regardless of --duration. Use this with "
            "--mode llm to bound the run to a predictable, small packet/call count."
        ),
    )
    parser.add_argument(
        "--model",
        type=str,
        default=MODEL_VARIANT,
        help=(
            f"Model tag to use in --mode llm (default: {MODEL_VARIANT}). "
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
        default=20,
        help=(
            "In --mode llm, packets requested per LLM call (default: 20). Set this >= "
            "--max-packets for a small test run to avoid a visible seam between batches."
        ),
    )

    args = parser.parse_args()
    create_web_browsing_stream(
        duration_minutes=args.duration,
        output_dir=args.output_dir,
        mode=args.mode,
        max_packets=args.max_packets,
        model_name=args.model,
        backend=args.backend,
        max_output_tokens=args.max_output_tokens,
        llm_batch_size=args.llm_batch_size,
    )
