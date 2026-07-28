"""Script to generate an LLM-driven GTP-U traffic stream PCAP file.

Orchestrates MistralClient to generate:
1. Benign GTP-U traffic baseline (JSON proposals)
2. Adversarial zero-day GTP-U attack mutation (JSON proposal)
3. Benign GTP-U traffic stream resumption
Converts all LLM JSON outputs into Scapy wire packets and saves to a .pcap trace.
"""

from scapy.all import IP, UDP, ICMP, wrpcap
from phase1_starter import (
    MistralClient,
    SessionContext,
    GTP_U_Mutation,
    build_gtpu_packet_from_mutation,
    MODEL_VARIANT,
)


def create_llm_pcap_stream(pcap_filename: str = "llm_gtpu_attack_stream.pcap"):
    mistral = MistralClient(model_name=MODEL_VARIANT)
    ctx = SessionContext.random_synthetic(seed=42)

    print("=" * 70)
    print("5G GTP-U LLM Zero-Day Attack & Baseline PCAP Generator")
    print("=" * 70)
    print("\n[Session State Context]")
    print(ctx.to_prompt_block())

    # Step 1: LLM Generates Benign Traffic Stream (Packets #1 - #4)
    print("\n[1/3] Generating Benign Traffic Stream with LLM...")
    benign_json_list = mistral.generate_benign_batch(ctx, batch_size=4)

    # Step 2: LLM Generates Adversarial Zero-Day Attack Packet (Packet #5)
    print("\n[2/3] Generating Adversarial Attack Mutation with LLM...")
    attack_json = mistral.generate_mutation(ctx, known_anomalies=[], previous_mutations=[])

    # Step 3: LLM Resumes Benign Traffic Stream (Packets #6 - #8)
    print("\n[3/3] Resuming Benign Traffic Stream with LLM...")
    resume_json_list = mistral.generate_benign_batch(ctx, batch_size=3)
  
    # Combine into single campaign stream
    all_json_proposals = benign_json_list + ([attack_json] if attack_json else []) + resume_json_list

    outer_ip_src = "192.168.100.10"  # gNodeB IP
    outer_ip_dst = "192.168.100.20"  # UPF IP
    inner_payload = IP(src="10.45.0.2", dst="8.8.8.8") / ICMP(type=8, code=0)

    packets = []
    print("\n[Packaging LLM Proposals into Wire-level PCAP Trace]")
    for seq, mut_json in enumerate(all_json_proposals, start=1):
        if not mut_json:
            continue

        mutation = GTP_U_Mutation.from_json(ctx, mut_json)
        gtp_packet = build_gtpu_packet_from_mutation(mutation, payload=inner_payload)
        gtp_packet.seq = seq

        full_wire_packet = (
            IP(src=outer_ip_src, dst=outer_ip_dst)
            / UDP(sport=2152, dport=2152)
            / gtp_packet
        )
        packets.append(full_wire_packet)

        is_attack = mut_json.get("traffic_class") != "benign"
        status_tag = f"[ATTACK INJECTED - {mut_json.get('anomaly_type')}]" if is_attack else "[BENIGN]"
        print(f"  Packet #{seq} {status_tag} Reasoning: {mut_json.get('reasoning')}")

    wrpcap(pcap_filename, packets)
    print(f"\n Saved {len(packets)} LLM-generated GTP-U packets to '{pcap_filename}'!")


if __name__ == "__main__":
    create_llm_pcap_stream()
