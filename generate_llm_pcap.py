"""Script to generate realistic GTP-U traffic streams and PCAP traces.

Supports:
1. Web Browsing benign baseline stream (5QI 6, LLM-driven, configurable duration).
2. LLM-driven adversarial attack stream (benign baseline + injected attack packets).
"""

import os
import json
import random
import time
import numpy as np
from collections import Counter
from datetime import datetime
from typing import Optional, List, Dict

from scapy.all import IP, UDP, TCP, Raw, wrpcap
from llm_client import LLMClient, MODEL_VARIANT
from session_context import SessionContext
from gtpu import GTP_U_Mutation, build_gtpu_packet_from_mutation
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
# N3 tunnel endpoints (outer IP). Fixed testbed values; no CLI knob varies them.
_GNODEB_IP = "192.168.100.10"
_UPF_IP = "192.168.100.20"
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
    structure.
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
    """ The LLM decides the flow's size and leaves the packetization to
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


def assemble_gpdu(mutation, *, inner_src, inner_dst, sport, dport, seq, ack, flags,
                  ttl, payload_size, outer_src, outer_dst):
    """Assemble one GTP-U G-PDU (caller sets .time). Shared by the benign and
    attack builders so both wrap payloads identically.

    Inner IP/TCP padded to payload_size with os.urandom, not constant filler:
    this models incompressible TLS application data, so an entropy/compression
    IDS can't separate benign from attack on the padding (DATASET_VALIDATION #17).
    The outer ToS carries the mutation's OWN outer_dscp, not the session value,
    so a marking anomaly actually reaches the wire (#3)."""
    inner = (
        IP(src=inner_src, dst=inner_dst, id=random.randint(0, 0xFFFF), ttl=ttl)
        / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
    )
    pad_len = max(0, payload_size - len(inner))
    payload = inner / Raw(load=os.urandom(pad_len)) if pad_len > 0 else inner
    return (
        IP(src=outer_src, dst=outer_dst, tos=mutation.outer_dscp << 2, id=random.randint(0, 0xFFFF))
        / UDP(sport=2152, dport=2152)
        / build_gtpu_packet_from_mutation(mutation, payload=payload)
    )


def _build_wire_packet(
    ctx: SessionContext,
    meta: Dict,
    sim_time: float,
    gap_ms: float,
    ue_ip: str = _UE_IP,
):
    """Render one telemetry record as a GTP-U wire packet.

    Direction-aware: a downlink G-PDU tunnels UPF -> gNB carrying server -> UE
    inner traffic (pdu_type 0); an uplink G-PDU tunnels gNB -> UPF carrying
    UE -> server (pdu_type 1). `gap_ms` is the spacing before this packet and
    sets its capture timestamp. `ue_ip` is this UE's inner address.
    """
    mutation = GTP_U_Mutation.from_json(ctx, meta)
    payload_size = mutation.payload_size if mutation.payload_size is not None else 250

    if meta.get("direction") == "UL":
        inner_src, inner_dst = ue_ip, _WEB_SERVER_IP
        sport, dport = meta["tcp_port"], _WEB_SERVER_PORT
        outer_src, outer_dst = _GNODEB_IP, _UPF_IP
    else:
        inner_src, inner_dst = _WEB_SERVER_IP, ue_ip
        sport, dport = _WEB_SERVER_PORT, meta["tcp_port"]
        outer_src, outer_dst = _UPF_IP, _GNODEB_IP

    wire_packet = assemble_gpdu(
        mutation, inner_src=inner_src, inner_dst=inner_dst, sport=sport, dport=dport,
        seq=meta["tcp_seq"], ack=meta["tcp_ack"], flags=meta["tcp_flags"],
        ttl=meta["inner_ttl"], payload_size=payload_size,
        outer_src=outer_src, outer_dst=outer_dst,
    )
    wire_packet.time = sim_time + gap_ms / 1000.0
    return wire_packet, gap_ms, payload_size


def _ue_identity(index: int) -> tuple:
    """Distinct (dl_teid, ul_teid, ue_ip) per background UE. TEIDs are spaced by
    2 so DL/UL never collide across UEs; inner UE IPs walk 10.45.0.2+ (fine up to
    ~250 UEs, beyond which the last octet would need to carry)."""
    return (WEB_BROWSING_DL_TEID + 2 * index,
            WEB_BROWSING_UL_TEID + 2 * index,
            f"10.45.0.{2 + index}")


def _sampled_benign_batch(ctx, n, rng):
    """No-LLM baseline: n benign flows drawn straight from the 5G-NIDD distributions
    (payload/IAT/request). Same dict shape as LLMClient.generate_benign_batch, so
    the rest of the pipeline is identical — the only variable is LLM vs sampling."""
    s = reference_models.sample_benign_flow_scalars(n, rng)
    if s is None:
        return []
    qfi = ctx.active_qfis[0]
    return [{
        "extension_headers": [{"type": 133, "pdu_type": 0, "qfi": qfi, "rqi": 0, "ppi": 0}],
        "outer_dscp": ctx.dscp_marking,
        "payload_size": int(max(1, s["payload"][i])),
        "inter_arrival_ms": float(max(1.0, s["iat_ms"][i])),
        "request_bytes": int(max(1, s["request"][i])),
        "policy_violations": [],
        "reasoning": "sampled directly from 5G-NIDD (no LLM)",
    } for i in range(n)]


def _generate_ue_stream(llm, ctx, ul_teid, ue_ip, ue_index,
                        t0, target_duration_sec, max_packets, llm_batch_size,
                        generation_mode="llm", sample_rng=None):
    """Generate ONE UE's benign flow stream over [t0, t0+duration].
    """
    events: List = []
    total_bytes = packet_count = 0
    llm_arrivals_count = llm_arrivals_used = flows_violating = 0
    malformed_flows = batch_failures = 0
    policy_violation_counts: Counter = Counter()
    sim_elapsed_sec = 0.0
    current_sim_time = t0
    llm_pending_queue: List[Dict] = []
    consecutive_batch_failures = 0
    MAX_CONSECUTIVE_BATCH_FAILURES = 3

    while sim_elapsed_sec < target_duration_sec and (max_packets is None or llm_arrivals_used < max_packets):
        if not llm_pending_queue:
            if generation_mode == "sampled":
                llm_pending_queue = _sampled_benign_batch(ctx, llm_batch_size, sample_rng)
            else:
                llm_pending_queue = llm.generate_benign_batch(ctx, batch_size=llm_batch_size, max_retries=3)
            if not llm_pending_queue:
                consecutive_batch_failures += 1
                batch_failures += 1
                if consecutive_batch_failures >= MAX_CONSECUTIVE_BATCH_FAILURES:
                    print(f"[ERROR] UE{ue_index}: {consecutive_batch_failures} batch calls failed in a row — "
                          f"stopping this UE with {packet_count} packets so far.")
                    break
                continue
            consecutive_batch_failures = 0
            llm_arrivals_count += len(llm_pending_queue)
        pkt_json = llm_pending_queue.pop(0)
        if not pkt_json.get("extension_headers"):
            malformed_flows += 1
            print(f"[WARN] UE{ue_index}: skipping benign flow with no extension header (incomplete model output).")
            continue
        llm_arrivals_used += 1
        if pkt_json.get("policy_violations"):
            flows_violating += 1
            policy_violation_counts.update(pkt_json["policy_violations"])
        flow_total = pkt_json["payload_size"]
        segments, intra_gaps = _fragment_flow(flow_total)
        qfi = pkt_json["extension_headers"][0].get("qfi", WEB_BROWSING_QFI)

        ue_port = random.randint(1024, 65535)
        dl_isn = random.randint(0, 0xFFFFFFFF)
        ul_isn = random.randint(0, 0xFFFFFFFF)
        inner_ttl = random.randint(52, 62)
        flow_events = []

        # UPLINK REQUEST: flow-start marker carries the flow-arrival gap.
        ul_ext = [{"type": 133, "pdu_type": 1, "qfi": qfi, "rqi": 0, "ppi": 0}]
        ul_off = 0
        for i, rsz in enumerate(_split_mtu(pkt_json["request_bytes"])):
            flow_events.append((rsz, pkt_json["inter_arrival_ms"] if i == 0 else 0.0, i == 0, "UL", {
                "teid": ul_teid, "extension_headers": ul_ext, "outer_dscp": pkt_json["outer_dscp"],
                "anomaly_type": "benign", "reasoning": pkt_json.get("reasoning", ""),
                "payload_size": rsz, "direction": "UL", "tcp_port": ue_port,
                "tcp_seq": (ul_isn + ul_off) % 0x100000000, "tcp_ack": 0, "tcp_flags": "PA", "inner_ttl": 64,
            }))
            ul_off += max(0, rsz - 40)

        # DOWNLINK RESPONSE: the server's segments of the LLM's payload total.
        dl_base = {
            "teid": ctx.teid, "extension_headers": pkt_json["extension_headers"],
            "outer_dscp": pkt_json["outer_dscp"], "anomaly_type": "benign",
            "reasoning": pkt_json.get("reasoning", ""), "direction": "DL",
            "tcp_port": ue_port, "tcp_ack": pkt_json["request_bytes"], "inner_ttl": inner_ttl,
        }
        dl_off = 0
        for i, seg in enumerate(segments):
            flow_events.append((seg, intra_gaps[i], False, "DL", {
                **dl_base, "payload_size": seg, "tcp_seq": (dl_isn + dl_off) % 0x100000000,
                "tcp_flags": "PA" if i == len(segments) - 1 else "A",
                **({"flow_total_bytes": flow_total} if i == 0 else {}),
            }))
            dl_off += max(0, seg - 40)

        for size, gap_ms, is_flow_start, direction, meta in flow_events:
            wire_packet, gap_ms, payload_size = _build_wire_packet(
                ctx, meta, current_sim_time, gap_ms, ue_ip=ue_ip
            )
            sim_elapsed_sec += gap_ms / 1000.0
            current_sim_time += gap_ms / 1000.0
            total_bytes += len(wire_packet)
            packet_count += 1
            events.append((wire_packet, {
                "payload_size_bytes": payload_size, "inter_arrival_ms": gap_ms,
                "is_flow_start": is_flow_start, "direction": direction,
                "flow_total_bytes": meta.get("flow_total_bytes"), "ue": ue_index,
            }))

    stats = {
        "total_bytes": total_bytes, "packet_count": packet_count,
        "sim_elapsed_sec": sim_elapsed_sec, "llm_arrivals_count": llm_arrivals_count,
        "llm_arrivals_used": llm_arrivals_used, "llm_arrivals_unused": len(llm_pending_queue),
        "flows_violating": flows_violating, "policy_violation_counts": policy_violation_counts,
        "malformed_flows": malformed_flows, "batch_failures": batch_failures,
    }
    return events, stats


def create_web_browsing_stream(
    duration_minutes: float = 15.0,
    output_dir: str = "pcap_files",
    max_packets: Optional[int] = None,
    model_name: str = MODEL_VARIANT,
    backend: str = "ollama",
    max_output_tokens: Optional[int] = None,
    llm_batch_size: int = 200,
    num_ues: int = 1,
    generation_mode: str = "llm",
) -> tuple:
    target_duration_sec = duration_minutes * 60.0
    # "sampled" is the no-LLM baseline: no client, no API key needed.
    llm = LLMClient(model_name=model_name, backend=backend, max_output_tokens=max_output_tokens) \
        if generation_mode == "llm" else None
    sample_rng = np.random.default_rng() if generation_mode == "sampled" else None
    src = model_name if generation_mode == "llm" else "5G-NIDD direct sampling (no LLM)"

    print(f"5G GTP-U Web Browsing Baseline Stream Generator (5QI {WEB_BROWSING_5QI}, mode={generation_mode}, src={src})")
    print(f"Target simulated duration: {duration_minutes:.1f} minutes ({target_duration_sec:.0f} s)  |  UEs: {num_ues}")
    if max_packets:
        print(f"Per-UE arrival cap: {max_packets} LLM-generated traffic arrivals (pre-MTU-segmentation)")
    print("=" * 70)

    pcap_filename = generate_timestamped_filename(prefix="web_browsing_benign", output_dir=output_dir)
    json_filename = pcap_filename.replace(".pcap", "_telemetry.json")

    if reference_models.load_5gnidd() is None:
        print("[WARN] 5G-NIDD reference missing (run extract_5gnidd_reference.py) — "
              "LLM prompt loses few-shot examples; 'sampled' mode cannot run at all.")

    # Every UE shares one capture start t0 so their independent per-UE arrival
    # timelines overlap into one crowd, the way a real UPF sees many sessions.
    t0 = time.time()
    all_events: List = []
    total_bytes = packet_count = 0
    llm_arrivals_count = llm_arrivals_used = llm_arrivals_unused = flows_violating = 0
    malformed_flows = batch_failures = 0
    policy_violation_counts: Counter = Counter()
    ue_ids = []
    for u in range(num_ues):
        dl_teid, ul_teid, ue_ip = _ue_identity(u)
        ue_ids.append({"ue": u, "dl_teid": hex(dl_teid), "ul_teid": hex(ul_teid), "ue_ip": ue_ip})
        ctx = _make_web_browsing_session()
        ctx.teid = dl_teid
        print(f"\n[UE {u}] teid={hex(dl_teid)} ip={ue_ip} — generating up to {target_duration_sec:.0f}s...")
        events, st = _generate_ue_stream(
            llm, ctx, ul_teid, ue_ip, u, t0,
            target_duration_sec, max_packets, llm_batch_size,
            generation_mode=generation_mode, sample_rng=sample_rng,
        )
        all_events += events
        total_bytes += st["total_bytes"]; packet_count += st["packet_count"]
        llm_arrivals_count += st["llm_arrivals_count"]; llm_arrivals_used += st["llm_arrivals_used"]
        llm_arrivals_unused += st["llm_arrivals_unused"]; flows_violating += st["flows_violating"]
        malformed_flows += st["malformed_flows"]; batch_failures += st["batch_failures"]
        policy_violation_counts += st["policy_violation_counts"]
        print(f"[UE {u}] done: {st['packet_count']} packets, {st['llm_arrivals_used']} flows.")

    # Merge all UEs by wire time into one crowd, then assign the global order.
    all_events.sort(key=lambda ev: float(ev[0].time))
    packets: List = []
    telemetry_records: List[Dict] = []
    for seq, (pkt, rec) in enumerate(all_events, start=1):
        rec["seq"] = seq
        rec["sim_time_sec"] = round(float(pkt.time) - t0, 3)
        packets.append(pkt)
        telemetry_records.append(rec)

    sim_elapsed_sec = (float(packets[-1].time) - t0) if packets else 0.0
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

    api_calls = llm.call_count if llm else 0
    prompt_tokens = llm.total_prompt_tokens if llm else 0
    completion_tokens = llm.total_completion_tokens if llm else 0

    telemetry_data = {
        "experiment_type": "web_browsing_benign_llm_stream",
        "generation_mode": generation_mode,
        "model_name": model_name if generation_mode == "llm" else "5g-nidd-sampled",
        "5qi": WEB_BROWSING_5QI,
        "qfi": WEB_BROWSING_QFI,
        "timestamp": datetime.now().isoformat(),
        "pcap_file": pcap_filename,
        "target_duration_minutes": duration_minutes,
        "num_ues": num_ues,
        "simulated_duration_seconds": round(sim_elapsed_sec, 2),
        "packet_count": packet_count,
        "total_bytes": total_bytes,
        "avg_packet_size_bytes": round(avg_payload, 2),
        "avg_flow_inter_arrival_ms": round(avg_iat_ms, 2),
        "achieved_bitrate_bps": round(achieved_bps, 1),
        "benign_policy_violations": dict(policy_violation_counts) or None,
        "llm_usage": {
            "api_call_count": api_calls,
            "total_prompt_tokens": prompt_tokens,
            "total_completion_tokens": completion_tokens,
            "llm_arrivals_count": llm_arrivals_count,
            "llm_arrivals_used": llm_arrivals_used,
            "llm_arrivals_unused": llm_arrivals_unused,
            "avg_completion_tokens_per_packet": (
                round(completion_tokens / llm_arrivals_count, 1) if llm_arrivals_count else None
            ),
            "avg_prompt_tokens_per_call": (
                round(prompt_tokens / api_calls, 1) if api_calls else None
            ),
        },
        "generation_reliability": {
            "flows_generated": llm_arrivals_used,
            "flows_malformed_skipped": malformed_flows,
            "batch_failures": batch_failures,
            "flows_per_api_call": round(llm_arrivals_used / api_calls, 2) if api_calls else None,
            "malformed_rate": round(malformed_flows / (llm_arrivals_used + malformed_flows), 3)
                              if (llm_arrivals_used + malformed_flows) else 0.0,
        },
        "session_context": {
            "active_qfis": [WEB_BROWSING_QFI],
            "qfi_to_5qi": {WEB_BROWSING_QFI: WEB_BROWSING_5QI},
            "dscp_marking": hex(WEB_BROWSING_DSCP),
            "ues": ue_ids,
        },
        "packet_records": telemetry_records,
    }

    with open(json_filename, "w") as f:
        json.dump(telemetry_data, f, indent=2)

    print(" WEB BROWSING STREAM COMPLETED \n")
    print(f" PCAP file          : {pcap_filename}")
    print(f" Telemetry JSON     : {json_filename}")
    print(f" UEs                : {num_ues}")
    print(f" Packets generated  : {packet_count}")
    print(f" Simulated duration : {sim_elapsed_sec:.1f} s ({sim_elapsed_sec/60:.2f} min)")
    print(f" Avg payload size   : {telemetry_data['avg_packet_size_bytes']} bytes")
    print(f" Avg flow IAT       : {telemetry_data['avg_flow_inter_arrival_ms']} ms")
    print(f" Achieved bitrate   : {achieved_bps/1e6:.2f} Mbps")
    print(f" Generation mode    : {generation_mode}")
    if flows_violating:
        print(f" [WARN] Policy guard: {flows_violating}/{llm_arrivals_used} benign flows violated session policy")
        print(f"                      {dict(policy_violation_counts)}")
    if api_calls:
        print(
            f" LLM API calls      : {api_calls} "
            f"({prompt_tokens} prompt / {completion_tokens} completion tokens)"
        )
        r = telemetry_data["generation_reliability"]
        print(
            f" Reliability        : {r['flows_generated']} flows / {api_calls} calls "
            f"= {r['flows_per_api_call']} flows/call | {malformed_flows} malformed skipped "
            f"({r['malformed_rate']*100:.1f}%) | {batch_failures} batch failures"
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
    parser.add_argument(
        "--num-ues",
        type=int,
        default=1,
        help=(
            "Number of concurrent UEs (distinct sessions/TEIDs/IPs) to interleave "
            "into one UPF-facing stream (default: 1). Each UE has a realistic ~2-9 "
            "flows/min; N UEs give N times the density — a crowd the way a real UPF "
            "sees it. Cost scales with N (each UE's flows are separate LLM batches)."
        ),
    )
    parser.add_argument(
        "--generation-mode",
        choices=["llm", "sampled"],
        default="llm",
        help=(
            "'llm' (default): the LLM writes each flow's payload/IAT/request. "
            "'sampled': the no-LLM baseline that draws them straight from the 5G-NIDD "
            "distributions — no API calls, no key. Use it as the SOTA lower bound the "
            "LLM is compared against on the goodness-of-fit plots."
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
        num_ues=args.num_ues,
        generation_mode=args.generation_mode,
    )
