from phase1_starter import MistralClient, SessionContext


def test_reasoning_fidelity_detects_field_conflicts():
    client = MistralClient.__new__(MistralClient)
    ctx = SessionContext(
        teid=1,
        active_qfis=[2, 48],
        qfi_to_5qi={2: 7, 48: 9},
        qfi_to_qer={2: 1, 48: 2},
        reflective_qos_enabled_qfis=[48],
        dscp_marking=0x28,
    )
    headers = [{"type": 0x85, "qfi": 48, "rqi": 1, "ppi": 0}]

    result = client._check_reasoning_fidelity(
        "QFI=7 is mapped to QER=15 and DSCP=0x28",
        headers,
        ctx,
    )

    assert result["consistency_conflicts"]
    assert any("qfi" in item for item in result["consistency_conflicts"])


def test_diversity_tracking_detects_duplicate_structure():
    client = MistralClient.__new__(MistralClient)
    ctx = SessionContext(
        teid=1,
        active_qfis=[2, 48],
        qfi_to_5qi={2: 7, 48: 9},
        qfi_to_qer={2: 1, 48: 2},
        reflective_qos_enabled_qfis=[48],
        dscp_marking=0x28,
    )

    previous = [{
        "extension_headers": [{"type": 0x85, "qfi": 48, "rqi": 1, "ppi": 0}],
        "anomaly_type": "qfi_qer_mismatch",
    }]
    mutation = {
        "extension_headers": [{"type": 0x85, "qfi": 48, "rqi": 1, "ppi": 0}],
        "outer_dscp": 0x28,
        "anomaly_type": "qfi_qer_mismatch",
        "reasoning": "Same structure as before",
    }

    result = client._ensure_diverse_structure(mutation, ctx, previous_mutations=previous)

    # Should not rewrite the LLM's QFI 48, but correctly flag it as not unique (duplicate)
    assert result["extension_headers"][0]["qfi"] == 48
    assert result["structural_diversity_is_unique"] is False


def test_gtpu_mutation_adapter_builds_scapy_packet():
    from phase1_starter import GTP_U_Mutation, ExtensionHeader, GTP_U_Packet_Builder
    from gtpu_scapy import build_gtpu_packet_from_mutation, GTPUPDUSessionContainer

    mutation = GTP_U_Mutation(
        teid=0x12345678,
        extension_headers=[ExtensionHeader(ext_type=0x85, qfi=48, rqi=1, ppi=0)],
        sequence_number=5,
    )

    builder = GTP_U_Packet_Builder()
    pkt = builder.build_packet(mutation)

    assert pkt.teid == 0x12345678
    assert pkt.seq == 5
    assert pkt.next_ex == 0x85
    assert pkt[GTPUPDUSessionContainer].QFI == 48


def test_gtpu_dict_adapter_builds_scapy_packet():
    from gtpu_scapy import build_gtpu_packet_from_mutation, GTPUPDUSessionContainer

    raw_dict = {
        "teid": 0x87654321,
        "sequence_number": 12,
        "pdu_type": 0,
        "extension_headers": [{"type": 0x85, "qfi": 15, "rqi": 1, "ppi": 3}],
    }

    pkt = build_gtpu_packet_from_mutation(raw_dict)

    assert pkt.teid == 0x87654321
    assert pkt.seq == 12
    assert pkt[GTPUPDUSessionContainer].QFI == 15
    assert pkt[GTPUPDUSessionContainer].RQI == 1

