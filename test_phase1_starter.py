"""Unit test suite for GTP-U generation, session context rules, and PCAP export."""

# pyrefly: ignore [missing-import]
import pytest
from phase1_starter import (
    MistralClient,
    SessionContext,
    GTP_U_Mutation,
    ExtensionHeader,
    build_gtpu_packet,
    build_gtpu_packet_from_mutation,
    export_campaign_to_pcap,
    GTPUPDUSessionContainer,
)


def test_semantic_precision_evaluates_policy_violations():
    client = MistralClient.__new__(MistralClient)
    ctx = SessionContext(
        teid=1,
        active_qfis=[2, 48],
        qfi_to_5qi={2: 7, 48: 9},
        qfi_to_qer={2: 1, 48: 2},
        reflective_qos_enabled_qfis=[48],
        dscp_marking=0x28,
    )
    headers = [{"type": 0x85, "qfi": 99, "rqi": 1, "ppi": 0}]

    result = client._evaluate_semantic_precision(
        headers=headers,
        dscp=0x28,
        ctx=ctx,
    )

    assert result["violates_active_qfis"] is True
    assert result["is_semantically_anomalous"] is True
    assert result["semantic_precision_score"] == 1.0


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

    assert result["extension_headers"][0]["qfi"] == 48
    assert result["structural_diversity_is_unique"] is False


def test_gtpu_mutation_adapter_builds_scapy_packet():
    mutation = GTP_U_Mutation(
        teid=0x12345678,
        extension_headers=[ExtensionHeader(ext_type=0x85, qfi=48, rqi=1, ppi=0)],
        sequence_number=5,
    )

    pkt = build_gtpu_packet_from_mutation(mutation)

    assert pkt.teid == 0x12345678
    assert pkt.seq == 5
    assert pkt.next_ex == 0x85
    assert pkt[GTPUPDUSessionContainer].QFI == 48
    assert pkt[GTPUPDUSessionContainer].RQI == 1


def test_gtpu_dict_adapter_builds_scapy_packet():
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
    assert pkt[GTPUPDUSessionContainer].PPI == 3
    assert pkt[GTPUPDUSessionContainer].PPP == 1


def test_gtpu_mutation_rqi_regression_and_ppp_auto_set():
    mutation = GTP_U_Mutation(
        teid=0x12345678,
        extension_headers=[ExtensionHeader(ext_type=0x85, qfi=48, rqi=1, ppi=3)],
    )

    pkt = build_gtpu_packet_from_mutation(mutation)

    assert pkt[GTPUPDUSessionContainer].RQI == 1
    assert pkt[GTPUPDUSessionContainer].PPI == 3
    assert pkt[GTPUPDUSessionContainer].PPP == 1

    ctx = SessionContext.random_synthetic(42)
    mut_json = {
        "teid": 0x11223344,
        "extension_headers": [{"type": 0x85, "qfi": 10, "rqi": 1, "ppi": 5, "pdu_type": 0}],
    }
    mut_from_json = GTP_U_Mutation.from_json(ctx, mut_json)
    assert mut_from_json.extension_headers[0].pdu_type == 0
    pkt_json = build_gtpu_packet_from_mutation(mut_from_json)
    assert pkt_json[GTPUPDUSessionContainer].RQI == 1
    assert pkt_json[GTPUPDUSessionContainer].PPI == 5
    assert pkt_json[GTPUPDUSessionContainer].PPP == 1


def test_build_gtpu_packet_raises_value_error_on_ul_rqi_ppi():
    with pytest.raises(ValueError, match="RQI and PPI fields are downlink"):
        build_gtpu_packet(teid=1234, qfi=48, rqi=1, pdu_type=1)

    with pytest.raises(ValueError, match="RQI and PPI fields are downlink"):
        build_gtpu_packet(teid=1234, qfi=48, ppi=3, pdu_type=1)


def test_export_campaign_to_pcap(tmp_path):
    mutations = [
        {"teid": 0x1234, "extension_headers": [{"type": 0x85, "qfi": 2, "rqi": 0}]},
        {"teid": 0x1234, "extension_headers": [{"type": 0x85, "qfi": 48, "rqi": 1}]},
    ]
    pcap_file = str(tmp_path / "test_campaign.pcap")
    res = export_campaign_to_pcap(mutations, output_filename=pcap_file)
    assert res == pcap_file


def test_multi_anomaly_detection():
    client = MistralClient.__new__(MistralClient)
    ctx = SessionContext(
        teid=1,
        active_qfis=[2, 48],
        qfi_to_5qi={2: 7, 48: 9},
        qfi_to_qer={2: 1, 48: 2},
        reflective_qos_enabled_qfis=[2],
        dscp_marking=0x00,
    )
    # Packet contains BOTH timing window race request AND invalid QFI (99)
    headers = [{"type": 0x85, "qfi": 99, "rqi": 0, "ppi": 0}]
    
    res = client._infer_anomaly_type(headers, ctx, requested_type="timing_window_race")
    
    assert res["primary_anomaly"] == "timing_window_race"
    assert "timing_window_race" in res["detected_anomalies"]
    assert "qfi_qer_mismatch" in res["detected_anomalies"]
    assert res["is_compound_anomaly"] is True
