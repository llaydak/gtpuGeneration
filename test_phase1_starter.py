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


def test_diversity_guard_rewrites_duplicate_structure():
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

    adjusted = client._ensure_diverse_structure(mutation, ctx, previous_mutations=previous)

    assert adjusted["extension_headers"][0]["qfi"] != 48
