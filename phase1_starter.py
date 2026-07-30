"""Main execution entrypoint for GTP-U generation and testing campaign.

This module orchestrates benign baseline generation and adversarial mutation campaigns,
and re-exports core classes to preserve backward compatibility.
"""

from gtpu_scapy import (
    SELF_HOSTED_MODELS_URL,
    MODEL_VARIANT,
    KNOWN_EXTENSION_TYPES,
    ALLOWED_ANOMALIES,
    build_gtpu_packet,
    build_gtpu_packet_from_mutation,
    GTP_U_Header,
    GTPUPDUSessionContainer,
    export_campaign_to_pcap,
)
from session_context import SessionContext
from packet_model import ExtensionHeader, GTP_U_Mutation
from mistral_client import MistralClient
from upf_monitor import UPF_Telemetry, UPF_Monitor

def main(save_pcap: bool = True):
    print("=" * 70)
    print("session-aware mutation + chained extension headers")

    mistral = MistralClient(model_name=MODEL_VARIANT)

    ctx = SessionContext.random_synthetic(seed=42)
    print("\n[Session context]")
    print(ctx.to_prompt_block())

    all_proposals = []

    # --- Benign baseline (run first, before any attack mutations) ---
    print("\n[Benign baseline — 5 packets, same session]")
    benign_batch = mistral.generate_benign_batch(ctx, batch_size=5)
    if benign_batch:
        all_proposals.extend(benign_batch)
        for i, bpkt in enumerate(benign_batch):
            h = bpkt["extension_headers"][0]
            m = GTP_U_Mutation.from_json(ctx, bpkt)
            pkt_bytes = bytes(build_gtpu_packet_from_mutation(m))
            print(f"  [{i+1}] qfi={h['qfi']} rqi={h['rqi']} ppi={h['ppi']} "
                  f"session_consistent={bpkt['session_consistent']} "
                  f"{' '.join(f'{b:02x}' for b in pkt_bytes)}")
        consistent_count = sum(1 for b in benign_batch if b["session_consistent"])
        print(f"  Compliance: {consistent_count}/{len(benign_batch)} packets session-consistent")
    else:
        print("  [WARN] No benign packets generated (LLM unavailable)")

    # --- Attack mutations ---
    print("\n[Single mutation]")
    mut_json = mistral.generate_mutation(ctx, known_anomalies=[], previous_mutations=[])
    if mut_json:
        all_proposals.append(mut_json)
        mutation = GTP_U_Mutation.from_json(ctx, mut_json)
        print(f"Requested anomaly: {mut_json.get('requested_anomaly_type')} | Resolved: {mut_json.get('anomaly_type')}")
        print(f"Raw schema valid: {mut_json.get('raw_schema_valid')} | Sanitization log: {mut_json.get('sanitization_log', {}).get('clamped_fields', [])}")
        print(f"Reasoning: {mutation.reasoning}")
        pkt_bytes = bytes(build_gtpu_packet_from_mutation(mutation))
        print(f"Packet: {' '.join(f'{b:02x}' for b in pkt_bytes)}")
    else:
        print("[WARN] Generation failed, falling back to a default mutation")
        mutation = GTP_U_Mutation(teid=ctx.teid)
        pkt_bytes = bytes(build_gtpu_packet_from_mutation(mutation))
        print(f"Packet: {' '.join(f'{b:02x}' for b in pkt_bytes)}")

    print("\n[Burst campaign — 5 packets, same session]")
    burst = mistral.generate_burst(ctx, burst_size=5)
    if burst:
        all_proposals.extend(burst)
        for i, mj in enumerate(burst):
            m = GTP_U_Mutation.from_json(ctx, mj)
            pkt_b = bytes(build_gtpu_packet_from_mutation(m))
            print(f"  [{i+1}] requested={mj.get('requested_anomaly_type')} resolved={mj.get('anomaly_type')} raw_valid={mj.get('raw_schema_valid')} {' '.join(f'{b:02x}' for b in pkt_b)}")

    # --- Automatic PCAP export ---
    if save_pcap and all_proposals:
        pcap_file = export_campaign_to_pcap(all_proposals, output_filename="llm_gtpu_campaign.pcap")
        print(f"\n Exported {len(all_proposals)} campaign packets to '{pcap_file}'!")


if __name__ == "__main__":
    main()