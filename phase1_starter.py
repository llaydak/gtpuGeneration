"""
Phase 1: spec-correct GTP-U builder, session-context-aware
mutation generation, chained extension headers, PDU Set marker, burst campaigns.

Covers 5 scope-extension directions discussed for Report 1:
  1. Session context as a real input dimension (QFI<->QER/FAR mapping, 5QI)
  2. Chained extension headers (not just a single PDU Session Container)
  3. Rel-18 PDU Set Information extension header (unsupported-header handling test)
  4. Burst/campaign generation (multi-packet sequences for cross-flow / resource
     exhaustion anomaly types, which cannot be expressed by a single packet)
  5. Inner IP/UDP payload used only for DSCP<->QFI *consistency* checks, not
     free-ranging IP fuzzing (keeps the study UPF/GTP-U-native)

IMPORTANT — verify before pointing at a real testbed:
  The exact bit layout of the PDU Session Container content octet(s) (RQI/PPI bit
  positions for DL vs UL PDU Type) should be cross-checked against TS 38.415
  section 5.5.3.x (or the Wireshark packet-gtpv1.c dissector source) before this
  is used against free5GC/gtp5g or Open5GS. The framing fix below (mandatory
  Sequence Number / N-PDU Number / Next-Extension-Header-Type octets after TEID,
  and the extension-header chain terminator) is the part I'm confident about;
  the exact RQI/PPI sub-byte bit positions are the one thing worth a second pair
  of eyes against the spec text itself.
"""

import json
import random
import re
import time
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, List, Any
import sys

try:
    from litellm import completion as litellm_completion
except Exception:
    litellm_completion = None

SELF_HOSTED_MODELS_URL = "http://192.168.100.38:11434"
MODEL_VARIANT = "mistral:7b"

# Known 5G-native GTP-U extension header types (3GPP TS 29.281 / 38.415).
# Only real, spec-defined types are exposed to the LLM — free-ranging
# extension-type fuzzing belongs in the grammar-based baseline, not here.
KNOWN_EXTENSION_TYPES = {
    0x85: "pdu_session_container",     # QFI / RQI / PPI
    0x83: "long_pdcp_pdu_number",
    0x84: "xw_ran_container",
    0xC0: "nr_ran_container",
    0xC1: "pdu_set_marker",            # Rel-18, unsupported by current OSS UPFs
}

ALLOWED_ANOMALIES = {
    "qfi_qer_mismatch",
    "invalid_chain",
    "duplicate_extension",
    "unsupported_extension_injection",
    "orphaned_flow",
    "resource_exhaustion",
    "cross_flow_interference",
    "dscp_qfi_inconsistency",
}


# ============================================================================
# PART 0: Session Context — the dimension that makes QFI/RQI/PPI meaningful
# ============================================================================

@dataclass
class SessionContext:
    """A synthetic PDU session state, as it would exist after PFCP/N4 setup.

    Mutations are only semantically meaningful *relative to* a session's
    QER/FAR mapping — so this is generated first and fed into every prompt,
    instead of mutating against a single fixed reference session.
    """
    teid: int
    active_qfis: List[int]                # QFIs legitimately provisioned for this session
    qfi_to_5qi: Dict[int, int]             # which 5QI each QFI is supposed to map to
    qfi_to_qer: Dict[int, int]             # which QER enforces each QFI
    reflective_qos_enabled_qfis: List[int]  # QFIs where RQI=1 is actually valid
    dscp_marking: int                      # expected outer DSCP for this session's default flow

    @classmethod
    def random_synthetic(cls, seed: Optional[int] = None) -> "SessionContext":
        rng = random.Random(seed)
        teid = rng.randint(1, 0xFFFFFFF)
        qfis = sorted(rng.sample(range(1, 64), k=rng.randint(2, 4)))
        return cls(
            teid=teid,
            active_qfis=qfis,
            qfi_to_5qi={q: rng.choice([1, 5, 7, 9, 69, 79]) for q in qfis},
            qfi_to_qer={q: rng.randint(1, 32) for q in qfis},
            reflective_qos_enabled_qfis=rng.sample(qfis, k=max(1, len(qfis) // 2)),
            dscp_marking=rng.choice([0x00, 0x08, 0x28, 0x2E]),
        )

    def to_prompt_block(self) -> str:
        return (
            f"- TEID: {self.teid}\n"
            f"- Active QFIs for this session: {self.active_qfis}\n"
            f"- QFI -> 5QI mapping: {self.qfi_to_5qi}\n"
            f"- QFI -> QER mapping: {self.qfi_to_qer}\n"
            f"- QFIs where Reflective QoS (RQI=1) is legitimately allowed: "
            f"{self.reflective_qos_enabled_qfis}\n"
            f"- Session's expected outer DSCP marking: 0x{self.dscp_marking:02x}"
        )


# ============================================================================
# PART 1: Mistral Offline Model Interface
# ============================================================================

class MistralClient:
    """Wrapper for offline Mistral/LLM usage via local Ollama or litellm."""

    def __init__(self, base_url=SELF_HOSTED_MODELS_URL, model_name=MODEL_VARIANT):
        self.base_url = base_url
        self.model_name = model_name
        self.endpoint = f"{base_url}/api/generate"

    def health_check(self) -> bool:
        if litellm_completion is not None:
            try:
                response = litellm_completion(
                    model=self.model_name,
                    custom_llm_provider="ollama",
                    messages=[{"role": "user", "content": "hi"}],
                    api_base=self.base_url,
                    temperature=0.7,
                    max_tokens=5,
                )
                return bool(getattr(response, "choices", None))
            except Exception as e:
                print(f"[WARN] litellm health check failed: {e}")
        return False

    def generate(self, prompt: str, system: str, temperature: float = 0.6,
                 max_tokens: int = 2000) -> str:
        if litellm_completion is not None:
            try:
                response = litellm_completion(
                    model=self.model_name,
                    custom_llm_provider="ollama",
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": prompt},
                    ],
                    api_base=self.base_url,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                return response.choices[0].message.content.strip()
            except Exception as e:
                print(f"[WARN] litellm generation failed: {e}")
        return ""

    def _sanitize_ext_header(self, raw: Dict) -> Optional[Dict]:
        try:
            ext_type = int(raw.get("type", 0x85))
        except (TypeError, ValueError):
            ext_type = 0x85
        if ext_type not in KNOWN_EXTENSION_TYPES:
            ext_type = 0x85

        def clamp(name, default, lo, hi):
            try:
                v = int(raw.get(name, default))
            except (TypeError, ValueError):
                v = default
            return max(lo, min(hi, v))

        return {
            "type": ext_type,
            "qfi": clamp("qfi", 0, 0, 63),
            "rqi": 1 if clamp("rqi", 0, 0, 1) >= 1 else 0,
            "ppi": clamp("ppi", 0, 0, 7),
        }

    def _infer_anomaly_type(self, headers: List[Dict], ctx: SessionContext,
                            requested_type: str,
                            previous_mutations: Optional[List[Dict]] = None) -> str:
        ext_types = [h.get("type", 0x85) for h in headers]
        qfis = [h.get("qfi", 0) for h in headers]

        if len(headers) >= 2 and len(set(ext_types)) < len(ext_types):
            return "duplicate_extension"
        if len(headers) >= 2 and any(t == 0xC1 for t in ext_types):
            return "unsupported_extension_injection"
        if requested_type == "cross_flow_interference" and previous_mutations:
            prev_qfis = []
            for prev in previous_mutations[-2:]:
                prev_qfis.extend([h.get("qfi", 0) for h in prev.get("extension_headers", [])])
            if any(q not in ctx.active_qfis for q in qfis) and prev_qfis and set(qfis) != set(prev_qfis):
                return "cross_flow_interference"
        if requested_type == "dscp_qfi_inconsistency":
            return "dscp_qfi_inconsistency"
        if requested_type == "qfi_qer_mismatch" and any(q not in ctx.active_qfis for q in qfis):
            return "qfi_qer_mismatch"
        if requested_type in ALLOWED_ANOMALIES:
            return requested_type
        return "qfi_qer_mismatch"

    def _structure_signature(self, mutation: Dict[str, Any]) -> tuple:
        headers = mutation.get("extension_headers", [])
        return (
            len(headers),
            tuple(h.get("type", 0x85) for h in headers),
            tuple(h.get("qfi", 0) for h in headers),
            tuple(h.get("rqi", 0) for h in headers),
            tuple(h.get("ppi", 0) for h in headers),
            mutation.get("anomaly_type", ""),
        )

    def _ensure_diverse_structure(self, mutation: Dict[str, Any], ctx: SessionContext,
                                  previous_mutations: Optional[List[Dict]] = None) -> Dict[str, Any]:
        if not mutation or not previous_mutations:
            return mutation

        prev_mut = previous_mutations[-1]
        if self._structure_signature(mutation) != self._structure_signature(prev_mut):
            return mutation

        headers = list(mutation.get("extension_headers", []))
        if not headers:
            headers = [{"type": 0x85, "qfi": 0, "rqi": 0, "ppi": 0}]

        prev_qfis = {h.get("qfi", 0) for h in prev_mut.get("extension_headers", [])}
        preferred_qfis = [q for q in ctx.active_qfis if q not in prev_qfis]
        if preferred_qfis:
            headers[0]["qfi"] = preferred_qfis[0]
        else:
            headers[0]["qfi"] = 1 if headers[0].get("qfi", 0) != 1 else 63

        if len(headers) < 2:
            headers.append({"type": 0xC1, "qfi": 0, "rqi": 0, "ppi": 0})
        else:
            headers[0]["type"] = 0xC0 if headers[0].get("type", 0x85) != 0xC0 else 0xC1

        mutation["extension_headers"] = headers
        if mutation.get("anomaly_type") == prev_mut.get("anomaly_type"):
            mutation["anomaly_type"] = "unsupported_extension_injection" if any(h.get("type") == 0xC1 for h in headers) else "invalid_chain"
        return mutation

    def _build_reasoning(self, mutation: Dict[str, Any], ctx: SessionContext) -> str:
        headers = mutation.get("extension_headers", [])
        if not headers:
            return "Session-context anomaly produced within schema bounds."

        first = headers[0]
        qfi = first.get("qfi", 0)
        rqi = first.get("rqi", 0)
        dscp = mutation.get("outer_dscp", ctx.dscp_marking)

        if any(h.get("type") == 0xC1 for h in headers):
            return "Injected an unsupported PDU Set Marker header into a session context that has no matching policy basis."
        if qfi not in ctx.active_qfis:
            return f"QFI {qfi} is not provisioned for this session's active QFI set {ctx.active_qfis}."
        if rqi and qfi not in ctx.reflective_qos_enabled_qfis:
            return f"RQI=1 on QFI {qfi} is outside the reflective-QoS allow-list for this session."
        if dscp != ctx.dscp_marking:
            return f"Outer DSCP {dscp} conflicts with the session's expected DSCP 0x{ctx.dscp_marking:02x}."
        return "Header-chain composition is semantically inconsistent with the session context despite remaining schema-valid."

    def _check_reasoning_fidelity(self, reasoning: str, headers: List[Dict], ctx: SessionContext) -> Dict[str, Any]:
        """Compare free-form reasoning against the actual field values in the mutation."""
        result = {
            "mentions_qfi": False,
            "mentions_rqi": False,
            "mentions_dscp": False,
            "mentions_qer": False,
            "mentions_5qi": False,
            "matched_fields": [],
            "consistency_conflicts": [],
            "fidelity_score": 1.0,
        }

        lowered = reasoning.lower()
        if "qfi" in lowered:
            result["mentions_qfi"] = True
        if "rqi" in lowered:
            result["mentions_rqi"] = True
        if "dscp" in lowered:
            result["mentions_dscp"] = True
        if "qer" in lowered:
            result["mentions_qer"] = True
        if "5qi" in lowered or "5qi" in reasoning:
            result["mentions_5qi"] = True

        qfi_claims = [int(v) for v in re.findall(r"\bqfi\s*[:=]?\s*(\d+)", lowered)]
        qer_claims = [int(v) for v in re.findall(r"\bqer\s*[:=]?\s*(\d+)", lowered)]
        dscp_claims = [int(v, 16) if str(v).startswith("0x") else int(v)
                      for v in re.findall(r"\bdscp\s*[:=]?\s*(0x[0-9a-f]+|\d+)", lowered)]

        for h in headers:
            qfi = h.get("qfi", 0)
            rqi = h.get("rqi", 0)
            if str(qfi) in reasoning and "qfi" in lowered:
                result["matched_fields"].append(f"qfi={qfi}")
            if str(rqi) in reasoning and "rqi" in lowered:
                result["matched_fields"].append(f"rqi={rqi}")

        for claimed_qfi in qfi_claims:
            header_qfis = [h.get("qfi", 0) for h in headers]
            if claimed_qfi not in header_qfis:
                result["consistency_conflicts"].append(f"qfi claim {claimed_qfi} conflicts with packet qfis {header_qfis}")

        for claimed_qer in qer_claims:
            if any(h.get("qfi", 0) in ctx.qfi_to_qer and ctx.qfi_to_qer[h.get("qfi", 0)] != claimed_qer for h in headers):
                result["consistency_conflicts"].append(f"qer claim {claimed_qer} conflicts with session mapping {ctx.qfi_to_qer}")

        for claimed_dscp in dscp_claims:
            if claimed_dscp != ctx.dscp_marking:
                result["consistency_conflicts"].append(f"dscp claim {claimed_dscp} conflicts with expected dscp {ctx.dscp_marking}")

        if result["consistency_conflicts"]:
            result["fidelity_score"] = 0.0
        return result

    def _sanitize_mutation(self, raw: Any, ctx: SessionContext,
                           previous_mutations: Optional[List[Dict]] = None) -> Optional[Dict[str, Any]]:
        if not isinstance(raw, dict):
            return None

        ext_headers_raw = raw.get("extension_headers", [])
        if not isinstance(ext_headers_raw, list) or not ext_headers_raw:
            ext_headers_raw = [{"type": 0x85, "qfi": raw.get("qfi", 0),
                                 "rqi": raw.get("rqi", 0), "ppi": raw.get("ppi", 0)}]

        sanitization_log: Dict[str, Any] = {
            "clamped_fields": [],
            "raw_model_output": raw,
            "raw_schema_valid": True,
        }

        sanitized_headers: List[Dict] = []
        for idx, h in enumerate(ext_headers_raw[:4]):
            if not isinstance(h, dict):
                continue
            try:
                ext_type = int(h.get("type", 0x85))
            except (TypeError, ValueError):
                ext_type = 0x85
            if ext_type not in KNOWN_EXTENSION_TYPES:
                sanitization_log["clamped_fields"].append(f"extension_headers[{idx}].type")
                ext_type = 0x85
                sanitization_log["raw_schema_valid"] = False

            def clamp(name, default, lo, hi):
                try:
                    v = int(h.get(name, default))
                except (TypeError, ValueError):
                    v = default
                if not (lo <= v <= hi):
                    sanitization_log["clamped_fields"].append(f"extension_headers[{idx}].{name}")
                    sanitization_log["raw_schema_valid"] = False
                    return max(lo, min(hi, v))
                return v

            qfi = clamp("qfi", 0, 0, 63)
            rqi = 1 if clamp("rqi", 0, 0, 1) >= 1 else 0
            ppi = clamp("ppi", 0, 0, 7)
            sanitized_headers.append({
                "type": ext_type,
                "qfi": qfi,
                "rqi": rqi,
                "ppi": ppi,
            })

        if not sanitized_headers:
            sanitized_headers = [{"type": 0x85, "qfi": 0, "rqi": 0, "ppi": 0}]

        requested_type = raw.get("anomaly_type", "qfi_qer_mismatch")
        if requested_type not in ALLOWED_ANOMALIES:
            requested_type = "qfi_qer_mismatch"

        try:
            dscp = int(raw.get("outer_dscp", ctx.dscp_marking))
        except (TypeError, ValueError):
            dscp = ctx.dscp_marking
        if not (0 <= dscp <= 0x3F):
            sanitization_log["clamped_fields"].append("outer_dscp")
            sanitization_log["raw_schema_valid"] = False
            dscp = max(0, min(0x3F, dscp))

        reasoning = str(raw.get("reasoning", "")) or "Semantic anomaly within schema bounds."
        resolved_type = self._infer_anomaly_type(sanitized_headers, ctx, requested_type, previous_mutations)
        mutation_dict = {
            "teid": ctx.teid,
            "extension_headers": sanitized_headers,
            "outer_dscp": dscp,
            "anomaly_type": resolved_type,
            "requested_anomaly_type": requested_type,
            "raw_schema_valid": sanitization_log["raw_schema_valid"],
            "sanitization_log": sanitization_log,
            "reasoning": reasoning,
        }
        mutation_dict = self._ensure_diverse_structure(mutation_dict, ctx, previous_mutations)
        mutation_dict["reasoning"] = self._build_reasoning(mutation_dict, ctx)
        reasoning_fidelity = self._check_reasoning_fidelity(mutation_dict["reasoning"], mutation_dict["extension_headers"], ctx)

        mutation_dict["reasoning_fidelity"] = reasoning_fidelity
        return mutation_dict

    def generate_mutation(self, ctx: SessionContext, known_anomalies: List[str],
                          previous_mutations: Optional[List[Dict]] = None) -> Optional[Dict]:
        """Generate ONE schema-valid, session-context-aware GTP-U mutation."""

        system = (
            "You are a 5G core network security researcher. You reason about "
            "3GPP-defined GTP-U PDU Session Container semantics (TS 29.281, TS 38.415) "
            "relative to a specific session's QER/FAR state. You never invent field "
            "values outside the schema bounds given to you."
        )

        previous_context_block = ""
        if previous_mutations:
            previous_context_block = "\n".join(
                f"Previous packet #{i+1}: {json.dumps(mut, sort_keys=True)}"
                for i, mut in enumerate(previous_mutations[-2:])
            )
            previous_context_block = "\n\nPrevious packets in this campaign (use them as dependency context):\n" + previous_context_block

        prompt = f"""Session state (this mutation must be evaluated AGAINST this specific session,
not in isolation):
{ctx.to_prompt_block()}

Previously explored anomaly types for this campaign: {known_anomalies}
{previous_context_block}

Known 5G-native GTP-U extension header types you may use (do not invent others):
{json.dumps(KNOWN_EXTENSION_TYPES, indent=2)}

Propose ONE mutation: a chain of 1-3 extension headers (schema-valid individually)
whose COMBINATION is semantically inconsistent with the session state above —
for example a QFI paired with an RQI=1 that isn't in the allowed list, a QFI whose
implied 5QI contradicts the session's QER mapping, a duplicated or out-of-order
extension header type, or an injected 0xC1 (PDU Set Marker) header that this
session's session state gives no basis for.

If you are generating a cross-flow interference mutation, make the new packet
conflict structurally with the previous packet in this campaign by using a different
QFI or a different header ordering than the last example. The previous packet's
full JSON must be treated as a dependency context for the next generation step.
Do not repeat the exact same header type sequence, QFI sequence, or RQI/PPi tuple
as the previous packet in this campaign; prefer a different structural signature.

Field bounds:
- qfi: 0-63, rqi: 0-1, ppi: 0-7
- extension_headers: 1-3 entries, each {{"type": <one of the known types>, "qfi": int, "rqi": int, "ppi": int}}
- outer_dscp: 0-63 (set deliberately inconsistent with the session's expected DSCP
  if anomaly_type is "dscp_qfi_inconsistency")

RESPOND ONLY WITH VALID JSON, NO MARKDOWN, NO EXPLANATION:
{{
  "extension_headers": [{{"type": <int>, "qfi": <int>, "rqi": <int>, "ppi": <int>}}, ...],
  "outer_dscp": <int 0-63>,
  "anomaly_type": "<one of: {sorted(ALLOWED_ANOMALIES)}>",
  "reasoning": "<1 sentence, must reference the session state above>"
}}
"""
        response = self.generate(prompt, system, temperature=0.8, max_tokens=2000)
        try:
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            if json_start >= 0 and json_end > json_start:
                parsed = json.loads(response[json_start:json_end])
                return self._sanitize_mutation(parsed, ctx, previous_mutations=previous_mutations)
        except json.JSONDecodeError:
            print(f"[WARN] Failed to parse JSON from Mistral: {response}")
        return None

    def generate_burst(self, ctx: SessionContext, burst_size: int = 5) -> List[Dict]:
        """Generate a multi-packet campaign for cross-flow / resource-exhaustion
        anomaly types, which are inherently not expressible as a single packet."""
        known: List[str] = []
        burst = []
        previous_mutations: List[Dict] = []
        for _ in range(burst_size):
            mut = self.generate_mutation(ctx, known, previous_mutations=previous_mutations)
            if mut:
                known.append(mut["anomaly_type"])
                previous_mutations.append(mut)
                burst.append(mut)
        return burst


# ============================================================================
# PART 2: GTP-U Packet Model + Spec-Correct Builder
# ============================================================================

@dataclass
class ExtensionHeader:
    ext_type: int      # e.g. 0x85 PDU Session Container, 0xC1 PDU Set Marker
    qfi: int = 0
    rqi: int = 0
    ppi: int = 0

    def is_valid_schema(self) -> bool:
        return (self.ext_type in KNOWN_EXTENSION_TYPES and
                0 <= self.qfi <= 63 and self.rqi in {0, 1} and 0 <= self.ppi <= 7)


@dataclass
class GTP_U_Mutation:
    teid: int
    extension_headers: List[ExtensionHeader] = field(default_factory=lambda: [ExtensionHeader(0x85)])
    outer_dscp: int = 0
    anomaly_type: str = "qfi_qer_mismatch"
    reasoning: str = ""
    seq_flag: int = 0
    npdu_flag: int = 0
    sequence_number: int = 0
    npdu_number: int = 0
    timestamp: Optional[float] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()

    def is_valid_schema(self) -> bool:
        return (0 <= self.teid <= 0xFFFFFFFF and
                0 <= self.outer_dscp <= 0x3F and
                1 <= len(self.extension_headers) <= 3 and
                all(h.is_valid_schema() for h in self.extension_headers))

    def to_dict(self) -> Dict:
        d = asdict(self)
        return d

    @classmethod
    def from_json(cls, ctx: SessionContext, mut_json: Dict) -> "GTP_U_Mutation":
        headers = [ExtensionHeader(h["type"], h["qfi"], h["rqi"], h["ppi"])
                   for h in mut_json["extension_headers"]]
        return cls(
            teid=mut_json.get("teid", ctx.teid),
            extension_headers=headers,
            outer_dscp=mut_json.get("outer_dscp", ctx.dscp_marking),
            anomaly_type=mut_json.get("anomaly_type", "qfi_qer_mismatch"),
            reasoning=mut_json.get("reasoning", ""),
        )


class GTP_U_Packet_Builder:
    """Spec-correct GTP-U + chained extension header builder.

    Fixes vs. the earlier draft:
      - Mandatory Sequence Number (2B) / N-PDU Number (1B) / Next-Extension-
        Header-Type (1B) octets are now included whenever E, S, or PN is set,
        as required by TS 29.281 Section 5.1 (they're present even when the
        corresponding flag is 0 and the field is unused).
      - Extension headers are chained properly: each is
        [Length(1B, in 4-octet units)] [content, padded to Length*4-2 octets]
        [Next-Extension-Header-Type(1B)], with the LAST header's next-type = 0x00.
      - PDU Type / Length are separate octets, not packed into one nibble-pair.
    """

    def __init__(self):
        self.version = 1
        self.pt = 1

    def _build_extension_chain(self, headers: List[ExtensionHeader]) -> bytes:
        chain = bytearray()
        for i, h in enumerate(headers):
            if h.ext_type == 0x85:
                content = bytearray([0x00, h.qfi & 0x3F, (h.rqi << 7) | (h.ppi & 0x07)])
            else:
                # For non-PDU Session Container types, keep a minimal, type-specific stub payload.
                # This avoids mis-encoding a container like 0xC0 as if it were a PDU Session Container.
                content = bytearray([0x00, 0x00])

            total_len = 1 + len(content) + 1
            pad = (-total_len) % 4
            content.extend([0x00] * pad)
            length_words = max(1, (total_len + 3) // 4)

            next_type = headers[i + 1].ext_type if i + 1 < len(headers) else 0x00

            chain.append(length_words & 0xFF)
            chain.extend(content)
            chain.append(next_type & 0xFF)
        return bytes(chain)

    def build_packet_bytes(self, mutation: GTP_U_Mutation) -> bytes:
        pkt = bytearray()

        e_flag = 1 if mutation.extension_headers else 0
        s_flag = mutation.seq_flag
        pn_flag = mutation.npdu_flag

        byte0 = (self.version << 5) | (self.pt << 4) | (0 << 3) | \
                (e_flag << 2) | (s_flag << 1) | pn_flag
        pkt.append(byte0)
        pkt.append(255)  # G-PDU

        length_offset = len(pkt)
        pkt.extend([0x00, 0x00])
        pkt.extend(mutation.teid.to_bytes(4, 'big'))

        if e_flag or s_flag or pn_flag:
            pkt.extend(mutation.sequence_number.to_bytes(2, 'big'))
            pkt.append(mutation.npdu_number & 0xFF)
            first_ext_type = mutation.extension_headers[0].ext_type if e_flag else 0x00
            pkt.append(first_ext_type & 0xFF)
            if e_flag:
                pkt.extend(self._build_extension_chain(mutation.extension_headers))

        payload_length = len(pkt) - 8
        pkt[length_offset:length_offset + 2] = payload_length.to_bytes(2, 'big')
        return bytes(pkt)

    def build_packet_debug(self, mutation: GTP_U_Mutation) -> str:
        return " ".join(f"{b:02x}" for b in self.build_packet_bytes(mutation))


# ============================================================================
# PART 3: UPF Monitoring (unchanged from prior draft — still a stub for
# kernel_errors / actual transmission; see review notes from earlier)
# ============================================================================

@dataclass
class UPF_Telemetry:
    timestamp: float
    memory_mb: float
    cpu_percent: float
    process_alive: bool
    kernel_errors: int
    anomaly_detected: Optional[str] = None


class UPF_Monitor:
    def __init__(self, upf_pid: Optional[int] = None):
        self.upf_pid = upf_pid
        self.baseline_memory = None
        self.baseline_cpu = None
        self.measurements: List[UPF_Telemetry] = []
        if upf_pid:
            self._init_baseline()

    def _init_baseline(self):
        try:
            import psutil
            proc = psutil.Process(self.upf_pid)
            self.baseline_memory = proc.memory_info().rss / (1024 * 1024)
            self.baseline_cpu = proc.cpu_percent(interval=0.1)
        except ImportError:
            print("[WARN] psutil not installed")

    def send_packet(self, pkt_bytes: bytes, duration: float = 1.0, interval: float = 0.1):
        print(f"[SEND] {len(pkt_bytes)} bytes: {' '.join(f'{b:02x}' for b in pkt_bytes)}")
        measurements = []
        start = time.time()
        while time.time() - start < duration:
            measurements.append((time.time(), 0, 0, True))
            time.sleep(interval)
        return measurements


# ============================================================================
# PART 4: Demo — session-aware single mutation + a burst campaign
# ============================================================================

def main():
    print("=" * 70)
    print("Phase 1 (extended): session-aware mutation + chained extension headers")
    print("=" * 70)

    mistral = MistralClient(model_name=MODEL_VARIANT)
    if not mistral.health_check():
        print("[ERROR] Mistral not running (ollama serve / ollama pull mistral)")
        sys.exit(1)

    ctx = SessionContext.random_synthetic(seed=42)
    print("\n[Session context]")
    print(ctx.to_prompt_block())

    print("\n[Single mutation]")
    mut_json = mistral.generate_mutation(ctx, known_anomalies=[], previous_mutations=[])
    builder = GTP_U_Packet_Builder()
    if mut_json:
        mutation = GTP_U_Mutation.from_json(ctx, mut_json)
        print(f"Requested anomaly: {mut_json.get('requested_anomaly_type')} | Resolved: {mut_json.get('anomaly_type')}")
        print(f"Raw schema valid: {mut_json.get('raw_schema_valid')} | Sanitization log: {mut_json.get('sanitization_log', {}).get('clamped_fields', [])}")
        print(f"Reasoning: {mutation.reasoning}")
        print(f"Reasoning fidelity: {mut_json.get('reasoning_fidelity', {})}")
        print(f"Packet: {builder.build_packet_debug(mutation)}")
    else:
        print("[WARN] Generation failed, falling back to a default mutation")
        mutation = GTP_U_Mutation(teid=ctx.teid)
        print(f"Packet: {builder.build_packet_debug(mutation)}")

    print("\n[Burst campaign — 5 packets, same session]")
    burst = mistral.generate_burst(ctx, burst_size=5)
    for i, mj in enumerate(burst):
        m = GTP_U_Mutation.from_json(ctx, mj)
        print(f"  [{i+1}] requested={mj.get('requested_anomaly_type')} resolved={mj.get('anomaly_type')} raw_valid={mj.get('raw_schema_valid')} fidelity={mj.get('reasoning_fidelity', {})}  {builder.build_packet_debug(m)}")


if __name__ == "__main__":
    main()