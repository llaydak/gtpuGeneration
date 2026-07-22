# Semantics Paper Mapping

**How to adapt CONSET methodology for your work.**

## 1. Specification Grounding

### Semantics (5G RRC)
```
Input:        TS 38.331 (RRC Protocol) + TS 38.2xx family (procedures)
Scope:        Pre-authentication phase, downlink RRC messages
Fields:       Information Elements (IEs), nested structures
Constraints:  Field value ranges, presence rules, cross-field dependencies
```

### Your Study (GTP-U User Plane)
```
Input:        TS 29.281 (GTP-U) + TS 29.244 (PFCP/N4 interface)
Scope:        User-plane data tunnels, 5G-native extensions (QFI, RQI, PPI)
Fields:       PDU Session Container extension headers
Constraints:  QFI-QER associations, header chaining rules, QoS enforcement
```

## 2. Constraint Taxonomy

### Semantics' Four Classes

| Class | RRC Example | GTP-U Equivalent |
|---|---|---|
| **Field Value Range** | `startPosition: 0..5` | `QFI: 0..63`, `RQI: 0..1`, `PPI: 0..7` |
| **Field Presence** | Need_M, Need_R codes | Extension header optionality (RQI/PPI based on PDU type) |
| **Intra-IE Dependency** | `N_SRS_symb ≥ l_offset − 1` (within srs-Config) | `QFI + active_QER_ID` (within PDUH) |
| **Inter-IE Dependency** | `SearchSpace.coresetId == ControlResourceSet.id` | `QFI in packet == QER ID in N4 state` (cross-interface) |

**Your Constraint Taxonomy** (for Phase 2):

```python
constraints = {
    "value_range": [
        {"field": "QFI", "range": (0, 63), "severity": "high"},
        {"field": "RQI", "range": (0, 1), "severity": "medium"},
        {"field": "PPI", "range": (0, 7), "severity": "medium"},
    ],
    "presence": [
        {"field": "RQI", "condition": "PDU_type has bit X", "action": "include"},
        {"field": "PPI", "condition": "QoS flow requires paging", "action": "include"},
    ],
    "intra_ie": [
        {"fields": ["QFI", "PDU_type"], "relation": "QFI valid for PDU_type"},
    ],
    "inter_ie": [
        {"fields": ["QFI", "active_QER_IDs"], "relation": "QFI must match one QER_ID"},
        {"fields": ["extension_chain", "next_header"], "relation": "chaining must be valid"},
    ]
}
```

---

## 3. Deterministic Constraint Extraction

### Semantics' Approach
```
Schema-derived (ASN.1):
  - Value ranges:  TS 38.331 type definitions → direct parsing
  - Presence:      Need_M/Need_R annotations → deterministic
  
Prose-derived (requires LLM):
  - Intra-IE:      TS 38.2xx normative text ("when X, then Y")
  - Inter-IE:      TS 38.2xx across multiple documents
```

### Your Approach
```
Schema-derived (TS 29.281 ASN.1 equiv):
  - Value ranges:  Hardcoded (QFI: 0-63, RQI: 0-1, PPI: 0-7)
  - Presence:      PDU type bits (bit 7 = UL/DL, bits 4-6 = options)
  
Prose-derived (requires Mistral):
  - Intra-IE:      "QFI and RQI together imply...", "PPI valid when..."
  - Inter-IE:      "QFI in packet must match QER established on N4"
```

**Implementation** (phase1_starter.py already has this):
```python
# Deterministic
schema_rules = {
    "qfi": {"min": 0, "max": 63},
    "rqi": {"min": 0, "max": 1},
    "ppi": {"min": 0, "max": 7},
}

# LLM-derived (Phase 2 knowledge graph)
semantic_rules = {
    "qfi_qer_binding": "QFI value must correspond to an active QER ID",
    "rqi_packing": "RQI bit set only if QER has reflective QoS enabled",
    "ppi_class_alignment": "PPI must match traffic class in QER"
}
```

---

## 4. LLM-Based Dependency Extraction

### Semantics' Method
```
1. Evidence Extraction:
   - Keyword scan: "shall", "must", "only if", "depends on"
   - Context window: ±2 lines around keyword
   - Field mapping: Multi-pattern matching (handle aliases)
   
2. DSL Rule Induction:
   - Input: ASN.1 blocks + normative snippets + target fields
   - Prompt: "Decide if there's a valid dependency"
   - Output: DSL rule or NO_RULE
   - Validation: Field binding, literal checking, canonicalization
   
3. Admission Gates:
   - Evidence must be from normative prose
   - Must cite source
   - Must stay within ASN.1 domains
   - Must be checkable (not vague)
```

### Your Adaptation
```
1. Evidence Extraction:
   - Scan TS 29.281 + 29.244 for QFI/RQI/PPI mentions
   - Keywords: "QFI", "QER", "enforcement", "valid", "shall", "must"
   - Extract sentences linking fields + 3GPP reference
   
2. Mistral-Based Reasoning:
   - Input: Spec snippet + field names + current session state
   - Prompt: "Is [mutation] a valid semantic anomaly per TS 29.281?"
   - Output: JSON with {valid: bool, anomaly_type: str, reasoning: str}
   
3. Validation Gates:
   - Must reference TS 29.281 or 29.244 explicitly
   - Anomaly type must be in taxonomy
   - Fields must be in valid ranges
```

**Example Prompt** (Phase 2 refinement):

```
From TS 29.281 Section 5.1.6:
"The QoS Flow Identifier (QFI) identifies a QoS flow within a PDU session."

From TS 29.244 Section 7.5.2:
"The QoS Enforcement Rule specifies QFI-based enforcement parameters."

Session state:
- Active QER IDs: [0, 15, 20]
- Received packet QFI: 45

Question: Is this a valid GTP-U packet per 3GPP?
Should the UPF accept QFI=45 if no QER with ID=45 exists?

Answer: NO, this is a semantic anomaly (orphaned QFI).
Anomaly type: qfi_qer_mismatch
Severity: Should trigger QoS enforcement error
```

---

## 5. DSL & Rule Normalization

### Semantics' DSL
```python
# Value relations
ValueDependency: {
    "EQ(field1, field2)": "equality",
    "NE(field1, field2)": "inequality",
    "IN(field, set)": "membership",
    "MAP(field_a, field_b)": "enumeration mapping",
    "MOD(field, divisor)": "modular relation",
}

# Range relations
RangeAlignment: {
    "LT(field1, field2)": "less than",
    "LE(field1, field2)": "less or equal",
    "GT(field1, field2)": "greater than",
    "GE(field1, field2)": "greater or equal",
}

# Scope: intra-IE or inter-IE
```

### Your GTP-U DSL (Phase 2)
```python
# Simplified GTP-U DSL
GTP_U_Rules = {
    "value_relations": {
        "QFI_IN_ACTIVE_QERS": "EQ(packet.QFI, session.active_QER_IDs)",
        "RQI_VALIDITY": "IMPLIES(packet.RQI=1, session.QER[packet.QFI].reflective=true)",
        "PPI_CLASS_MATCH": "EQ(packet.PPI, map_class_to_ppi(session.traffic_class))",
    },
    "range_relations": {
        "QFI_BOUNDS": "GE(packet.QFI, 0) AND LE(packet.QFI, 63)",
        "CHAIN_LENGTH": "LE(header_chain.length, 255)",
    }
}

# Example violation:
# { "qfi": 45, "active_qers": [0, 15, 20] }
# → VIOLATED: QFI_IN_ACTIVE_QERS
# → Generate test packet with this violation
```

---

## 6. Test Case Generation & Mutation

### Semantics' Approach
```
Minimal Edits:
  - Change only fields involved in violated constraint
  - Keep message otherwise valid
  - Re-encode with pycrate to verify syntax
  
Example:
  Original: SearchSpace.coresetId=2, ControlResourceSet.id=2  (valid)
  Mutated:  SearchSpace.coresetId=2, ControlResourceSet.id=11 (invalid relation)
  Result:   Packet is syntactically valid but semantically broken
```

### Your Approach
```
Minimal Edits:
  - Modify one or two GTP-U fields per mutation
  - Keep packet structure valid (GTP header, length fields)
  - Re-encode with Scapy builder
  
Examples:
  Mutation 1 (QFI-QER mismatch):
    Original: QFI=15 (matches active QER 15) ✓
    Mutated:  QFI=99 (no QER 99 exists) ✗
    Testbed:  Should trigger QoS enforcement error
  
  Mutation 2 (RQI without reflective QoS):
    Original: RQI=0 (no reflective QoS needed) ✓
    Mutated:  RQI=1 (but QER doesn't have reflective bit) ✗
    Testbed:  Should cause inconsistency
  
  Mutation 3 (Invalid header chain):
    Original: next_header = 0x00 (valid terminator) ✓
    Mutated:  next_header = 0xFF (undefined) ✗
    Testbed:  Should trigger parsing error
```

**Code** (already in phase1_starter.py):
```python
class GTP_U_Packet_Builder:
    def build_packet_bytes(self, mutation: GTP_U_Mutation) -> bytes:
        # Construct minimal valid GTP-U header
        # Insert QFI, RQI, PPI from mutation
        # Re-validate lengths, checksums
        # Return bytes ready for transmission
```

---

## 7. Test Case Execution

### Semantics' Setup
```
Over-the-air (OTA):
  - SDR testbed (USRP B210)
  - Rogue gNodeB with modified downlink hook
  - Target: Commercial 5G phones + OAI UE simulator
  - Monitoring: ADB logcat, GDB backtraces, device restart
  - Result: Modem crashes, attach failures, assertion traces
```

### Your Setup
```
Testbed (isolated lab):
  - free5GC or Open5GS in Docker/VM
  - gtp5g kernel module (for free5GC)
  - Target: UPF process
  - Monitoring: psutil (CPU/mem), dmesg (kernel errors), packet capture
  - Result: Crashes, resource exhaustion, QoS anomalies, latency spikes
  
Execution Path:
  1. Establish clean N4 PFCP session with known QER IDs
  2. Send GTP-U packet with mutation
  3. Monitor for: crash, resource spike, dropped packets, latency
  4. Log outcome → feedback to knowledge graph
  5. Next mutation refinement
```

---

## 8. Evaluation Metrics

### Semantics' Metrics
```
Schema validity:       % of messages that parse correctly
Policy consistency:    % of test cases that violate intended constraint
Novelty:              % not in 5G-Attacks dataset or prior CVEs
Repetition rate:      Duplicate messages within run
Test fidelity:        Statistical distribution vs. real traffic
Effect rate:          % causing modem crash/assertion
Detection evasion:    % effects not caught by baseline IDS
```

### Your Metrics
```
Schema validity:       % packets re-encoded correctly (should be 100%)
Policy consistency:    % mutations that violate QFI-QER binding
Novelty:              % mutations NOT in 5G-Attacks or known CVEs
Repetition rate:       Duplicates per 100 generations
Statistical fidelity:  Packet headers look normal (outer layers)
Testbed effect rate:   % causing observable UPF anomaly
Detection evasion:     % anomalies not caught by signature IDS
Graph coverage:        % of knowledge graph explored

Tabulation (Phase 6):
┌─────────────────────┬──────────────┬──────────┬─────────┐
│ Attack Type         │ Packets Gen. │ Effects  │ Novelty │
├─────────────────────┼──────────────┼──────────┼─────────┤
│ QFI-QER mismatch    │      45      │   23     │  91%    │
│ Ext. hdr chaining   │      38      │   15     │  87%    │
│ Cross-flow interf.  │      52      │   18     │  85%    │
│ PDU Set abuse       │      40      │    8     │  94%    │
│ Timing window       │      25      │   12     │ 100%    │
└─────────────────────┴──────────────┴──────────┴─────────┘
```

---

## 9. Comparison with Baselines

### Semantics' Baselines
```
1. Exhaustive enumeration:  All valid field pairs
2. Grammar-based fuzzing:   Random valid mutations (no semantic logic)
3. Prior CVE replay:        Known attacks only
```

### Your Baselines
```
1. Grammar fuzzer:    Random QFI/RQI/PPI in valid ranges
2. GAN generator:     Learned but non-reasoning model
3. Known attack replay: CVE-2023-23846, CVE-2025-29646
```

**Expected Result**:
```
Condition A (Grammar):     200 packets, 12 effects (6%)
Condition B (LLM+RAG):     200 packets, 58 effects (29%) ← Your method
Condition C (Fine-tuned):  200 packets, 65+ effects (32%+)

Improvement: LLM+RAG finds 4.8× more effects than grammar alone
```

---

## 10. Knowledge Graph Structure (Phase 2)

### Build This
```json
{
  "nodes": {
    "qfi": {
      "type": "protocol_field",
      "range": [0, 63],
      "spec": "TS 29.281 § 5.1.6",
      "depends_on": ["active_qer_ids", "pdu_session"]
    },
    "qer_association": {
      "type": "semantic_relation",
      "fields": ["qfi", "active_qer_ids"],
      "rule": "QFI must be in active_qer_ids",
      "taxonomy": "policy_bypass"
    },
    "cve_2023_23846": {
      "type": "precedent",
      "vulnerability": "infinite_loop",
      "trigger": "malformed_extension_header",
      "relates_to": ["extension_header", "chain_validity"]
    }
  },
  "edges": [
    {"from": "qfi", "to": "qer_association", "label": "participates_in"},
    {"from": "qer_association", "to": "cve_2023_23846", "label": "similar_domain"}
  ]
}
```

### Query It
```python
# Find unexplored regions near QFI:
paths = kg.get_neighbors("qfi", depth=2)
# → [qer_association, extension_chain, session_binding]
# → Prioritize: which haven't been fuzzed yet?

# Find related precedents:
precedents = kg.get_precedents("qfi")
# → [cve_2023_23846, related_github_issues]
```

---

## 11. Mistral Configuration

### Evidence Boundedness
```
✓ GOOD:
  - Prompt includes exact TS 29.281 section text
  - Prompt includes current session state
  - Prompt specifies valid field ranges
  - Prompt asks for structured JSON
  - Output validated against domains

✗ BAD:
  - Allowing Mistral to invent field values outside ranges
  - Not specifying that answer must cite spec
  - Letting LLM reason without evidence packs
```

### Your Prompt Template (Phase 2)
```python
prompt = f"""
You are a 5G GTP-U protocol expert.

SPECIFICATION (TS 29.281 Section 5.1.6):
{spec_fragment}

SESSION STATE:
- Active QER IDs: {active_qers}
- Current QFI-to-QER mapping: {mapping}

QUESTION:
Is a GTP-U packet with QFI={test_qfi}, RQI={test_rqi}, PPI={test_ppi} 
valid according to TS 29.281?

If INVALID, explain the semantic anomaly (max 1 sentence).
If VALID, respond "NO_ANOMALY".

Respond ONLY with JSON:
{{"is_valid": bool, "anomaly_type": "str or null", "reasoning": "str"}}
"""
```

---

## 12. Timeline Mapping

| Semantics Timeline | Your Timeline (12 weeks) | Task |
|---|---|---|
| **Phase 1**: Message decoding | **Weeks 1-2** | Mistral + Scapy baseline |
| **Phase 2**: Constraint extraction | **Weeks 3-4** | Knowledge graph + RAG setup |
| **Phase 3**: DSL normalization | **Weeks 5-6** | Agentic feedback loop |
| **Phase 4**: Test generation | **Weeks 7-8** | Baseline comparisons |
| **Phase 5**: Execution & evaluation | **Weeks 9-10** | Prompt strategy comparison |
| **Paper + results** | **Weeks 11-12** | Evaluation framework + reporting |

---

## Summary: How Semantics Informs Your Work

| CONSET Component | Your Adaptation |
|---|---|
| Spec grounding | TS 29.281 + 29.244 (GTP-U + PFCP) |
| Constraint taxonomy | QFI/RQI/PPI + extension headers |
| Deterministic extraction | Hardcoded value ranges |
| LLM-based reasoning | Mistral for semantic anomaly detection |
| DSL normalization | Simple JSON rules for mutations |
| Minimal mutations | Single/dual field edits |
| Test execution | UPF testbed instead of OTA |
| Evaluation | Effect rate + novelty + coverage |
| Baselines | Grammar + GAN + known attacks |

**Key Insight**: You're not copying Semantics—you're applying its **methodology** (evidence-bounded LLM, DSL, dual abstraction, agentic feedback) to a **different protocol layer** (user-plane vs. control-plane) with a **different platform** (testbed vs. OTA) and **different threat model** (semantic GTP-U vs. pre-auth RRC).

