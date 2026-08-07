"""Unit test suite for GTP-U packet construction and session context rules."""

# pyrefly: ignore [missing-import]
import pytest
from llm_client import LLMClient
from session_context import SessionContext
from packet_model import GTP_U_Mutation, ExtensionHeader
from gtpu_scapy import (
    build_gtpu_packet,
    build_gtpu_packet_from_mutation,
    GTPUPDUSessionContainer,
)


def test_semantic_precision_evaluates_policy_violations():
    client = LLMClient.__new__(LLMClient)
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


def test_ul_semantic_precision_only_qfi_is_upf_enforced():
    """Uplink: an unauthorized QFI is the UPF-verified anomaly; RQI/DSCP are not."""
    client = LLMClient.__new__(LLMClient)
    ctx = SessionContext(
        teid=1,
        active_qfis=[6],
        qfi_to_5qi={6: 6},
        qfi_to_qer={6: 1},
        reflective_qos_enabled_qfis=[],
        dscp_marking=0x00,
    )

    # QFI not in the active set -> UPF QoS-flow-ID verification anomaly.
    bad = client._evaluate_semantic_precision([{"qfi": 9, "rqi": 0}], dscp=0x00, ctx=ctx, direction="UL")
    assert bad["violates_active_qfis"] is True
    assert bad["is_semantically_anomalous"] is True
    assert bad["enforcement_point"].startswith("UPF")

    # An authorized-QFI uplink packet is NOT flagged, even with a mismatched
    # DSCP — the UPF does not semantically verify the uplink transport marking.
    ok = client._evaluate_semantic_precision([{"qfi": 6, "rqi": 0}], dscp=0x2E, ctx=ctx, direction="UL")
    assert ok["is_semantically_anomalous"] is False


def test_ul_mutation_builds_uplink_container():
    """A pdu_type=1 mutation serializes as a UL PDU Session Container (QFI only)."""
    raw_dict = {
        "teid": 0xDEADBEEF,
        "extension_headers": [{"type": 0x85, "qfi": 9, "rqi": 0, "ppi": 0, "pdu_type": 1}],
    }
    pkt = build_gtpu_packet_from_mutation(raw_dict)
    assert pkt[GTPUPDUSessionContainer].type == 1  # UL PDU SESSION INFORMATION
    assert pkt[GTPUPDUSessionContainer].QFI == 9


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
