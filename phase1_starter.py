import json
import random
import re
import time
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, List, Any
import sys

from gtpu_scapy import build_gtpu_packet, build_gtpu_packet_from_mutation, GTP_U_Header

try:
    # pyrefly: ignore [missing-import]
    from litellm import completion as litellm_completion
except Exception:
    litellm_completion = None

SELF_HOSTED_MODELS_URL = "http://192.168.100.38:11434"
MODEL_VARIANT = "mistral:7b"

# Known GTP-U extension header types (3GPP TS 29.281 / 38.415 / 38.425 / 36.425).
# Complete & exhaustive set of all 3GPP spec-defined extension header types.
KNOWN_EXTENSION_TYPES = {
    0x03: "udp_port",                  # UDP Port encapsulation
    0x40: "pdcp_pdu_number",           # 16-bit PDCP Sequence Number (Handover/Dual Connectivity)
    0x81: "suspend_request",           # Cellular IoT Suspend Request
    0x82: "suspend_response",          # Cellular IoT Suspend Response
    0x83: "long_pdcp_pdu_number",      # Long PDCP SN (NR/LTE Dual Connectivity)
    0x84: "xw_ran_container",          # WLAN/LTE Interworking
    0x85: "pdu_session_container",     # 5G Core QFI / RQI / PPI (N3/N9)
    0xC0: "nr_ran_container",          # 5G RAN User Plane Control (Xn-U/F1-U)
    0xC1: "pdu_set_marker",            # Rel-18 Extended Reality (XR)
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
    QER/FAR mapping so this is generated first and fed into every prompt,
    instead of mutating against a single fixed reference session.
    """
    teid: int
    active_qfis: List[int]                # QFIs legitimately provisioned for this session
    qfi_to_5qi: Dict[int, int]             # which 5QI each QFI is supposed to map to
    qfi_to_qer: Dict[int, int]             # which QER enforces each QFI
    reflective_qos_enabled_qfis: List[int]  # QFIs where RQI=1 is actually valid
    dscp_marking: int                      # expected outer DSCP for this session's default flow
    pdu_type: int = 0                      # 0: DL (Downlink), 1: UL (Uplink)

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
            pdu_type=rng.choice([0, 1]),
        )

    def to_prompt_block(self) -> str:
        direction_str = "DL (Downlink)" if self.pdu_type == 0 else "UL (Uplink)"
        return (
            f"- TEID: {self.teid}\n"
            f"- Session Direction: {direction_str} (pdu_type={self.pdu_type})\n"
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
    """Wrapper for offline LLM usage via local Ollama and LiteLLM."""

    def __init__(self, base_url=SELF_HOSTED_MODELS_URL, model_name=MODEL_VARIANT):
        self.base_url = base_url
        self.model_name = model_name if model_name.startswith("ollama/") else f"ollama/{model_name}"

    def health_check(self) -> bool:
        if litellm_completion is not None:
            try:
                response = litellm_completion(
                    model=self.model_name,
                    messages=[{"role": "user", "content": "hi"}],
                    api_base=self.base_url,
                    temperature=0.7,
                    max_tokens=5,
                )
                return bool(getattr(response, "choices", None))
            except Exception as e:
                print(f"[WARN] litellm health check failed: {e}")
        return False

    def generate(self, prompt: str, system: str, temperature: float = 0.7,
                 max_tokens: int = 2000) -> str:
        if litellm_completion is not None:
            try:
                response = litellm_completion(
                    model=self.model_name,
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
        """Evaluates whether the LLM generated a novel structure relative to previous campaign packets."""
        if not mutation or not previous_mutations:
            mutation["structural_diversity_is_unique"] = True 
            return mutation

        prev_mut = previous_mutations[-1]
        is_duplicate = (self._structure_signature(mutation) == self._structure_signature(prev_mut))
        mutation["structural_diversity_is_unique"] = not is_duplicate
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

    def _evaluate_semantic_precision(self, headers: List[Dict], dscp: int, ctx: SessionContext) -> Dict[str, Any]:
        """Deterministically check if the generated packet violates session policy bounds."""
        first_qfi = headers[0].get("qfi", 0) if headers else 0
        first_rqi = headers[0].get("rqi", 0) if headers else 0
        has_unsupported = any(h.get("type") == 0xC1 for h in headers)

        violates_qfis = first_qfi not in ctx.active_qfis
        violates_rqi = (first_rqi == 1 and first_qfi not in ctx.reflective_qos_enabled_qfis)
        violates_dscp = (dscp != ctx.dscp_marking)

        is_anomalous = violates_qfis or violates_rqi or violates_dscp or has_unsupported

        return {
            "violates_active_qfis": violates_qfis,
            "violates_rqi_allowlist": violates_rqi,
            "violates_dscp_marking": violates_dscp,
            "contains_unsupported_header": has_unsupported,
            "is_semantically_anomalous": is_anomalous,
            "semantic_precision_score": 1.0 if is_anomalous else 0.0,
        }

    def _evaluate_structured_claims(self, claims: Optional[Dict], headers: List[Dict], ctx: SessionContext) -> Dict[str, Any]:
        """Compare optional structured JSON claims from model against packet fields deterministically."""
        if not isinstance(claims, dict):
            return {"has_structured_claims": False, "claims_alignment_score": 1.0}

        target_qfi = claims.get("target_qfi")
        header_qfis = [h.get("qfi", 0) for h in headers]

        is_aligned = True
        if target_qfi is not None and target_qfi not in header_qfis:
            is_aligned = False

        return {
            "has_structured_claims": True,
            "claimed_target_qfi": target_qfi,
            "claims_aligned": is_aligned,
            "claims_alignment_score": 1.0 if is_aligned else 0.0,
        }

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
                sanitization_log["raw_schema_valid"] = False
                ext_type = 0x85

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
            pdu_type = clamp("pdu_type", 0, 0, 1)
            sanitized_headers.append({"type": ext_type, "pdu_type": pdu_type, "qfi": qfi, "rqi": rqi, "ppi": ppi})

        if not sanitized_headers:
            sanitized_headers = [{"type": 0x85, "pdu_type": 0, "qfi": 0, "rqi": 0, "ppi": 0}]

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
        
        mutation_dict["semantic_precision"] = self._evaluate_semantic_precision(
            mutation_dict["extension_headers"], dscp, ctx
        )
        mutation_dict["structured_claims_eval"] = self._evaluate_structured_claims(
            raw.get("claims"), mutation_dict["extension_headers"], ctx
        )

        return mutation_dict

    def generate_mutation(self, ctx: SessionContext, known_anomalies: List[str],
                          previous_mutations: Optional[List[Dict]] = None) -> Optional[Dict]:

        system = (
            "You are a 5G core network security researcher. You reason about "
            "3GPP-defined GTP-U PDU Session Container semantics (TS 29.281, TS 38.415) "
            "relative to a specific session's QER/FAR state."
        )

        previous_context_block = ""
        if previous_mutations:
            previous_context_block = "\n".join(
                f"Previous packet #{i+1}: {json.dumps(mut, sort_keys=True)}"
                for i, mut in enumerate(previous_mutations[-2:])
            )
            previous_context_block = "\n\nPrevious packets in this campaign (use them as dependency context):\n" + previous_context_block

        prompt = f"""Session state (evaluate mutation AGAINST this session state):
{ctx.to_prompt_block()}

Previously explored anomaly types in this campaign: {known_anomalies}
{previous_context_block}

Known 3GPP extension header type codes:
{json.dumps(KNOWN_EXTENSION_TYPES, indent=2)}

Task: Propose ONE mutation (a chain of 1-3 extension headers) that violates the session state rules above.

NOTE: RQI and PPI are only meaningful when pdu_type=0 (downlink). If you set rqi or ppi to a nonzero value, you MUST also set pdu_type=0, or those fields will be silently dropped from the wire packet.

CAMPAIGN DIVERSITY REQUIREMENT:
If previous packets are shown above, your new packet MUST explore a different header order, QFI, or flag state.

Field bounds:
- pdu_type: 0 (DL / Downlink) or 1 (UL / Uplink)
- qfi: 0-63, rqi: 0-1, ppi: 0-7, outer_dscp: 0-63
- extension_headers: 1-3 entries

RESPOND ONLY WITH VALID JSON (no markdown formatting):
{{
  "extension_headers": [
    {{"type": <int e.g. 133 or 0x85>, "pdu_type": <0 or 1>, "qfi": <int 0-63>, "rqi": <int 0-1>, "ppi": <int 0-7>}}
  ],
  "outer_dscp": <int 0-63>,
  "anomaly_type": "<one of: {sorted(ALLOWED_ANOMALIES)}>",
  "claims": {{"target_qfi": <int>}},
  "reasoning": "<1 concise sentence explaining the policy violation>"
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
    pdu_type: int = 0

    def is_valid_schema(self) -> bool:
        return (self.ext_type in KNOWN_EXTENSION_TYPES and
                0 <= self.qfi <= 63 and self.rqi in {0, 1} and 0 <= self.ppi <= 7 and
                self.pdu_type in {0, 1})


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
        headers = [ExtensionHeader(
                       ext_type=h.get("type", h.get("ext_type", 0x85)),
                       qfi=h.get("qfi", 0),
                       rqi=h.get("rqi", 0),
                       ppi=h.get("ppi", 0),
                       pdu_type=h.get("pdu_type", 0)
                   )
                   for h in mut_json["extension_headers"]]
        return cls(
            teid=mut_json.get("teid", ctx.teid),
            extension_headers=headers,
            outer_dscp=mut_json.get("outer_dscp", ctx.dscp_marking),
            anomaly_type=mut_json.get("anomaly_type", "qfi_qer_mismatch"),
            reasoning=mut_json.get("reasoning", ""),
        )


# ============================================================================
# PART 3: UPF Monitoring
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


def main():
    print("=" * 70)
    print("session-aware mutation + chained extension headers")

    mistral = MistralClient(model_name=MODEL_VARIANT)
    if not mistral.health_check():
        print("Mistral is not running")
        sys.exit(1)

    ctx = SessionContext.random_synthetic(seed=42)
    print("\n[Session context]")
    print(ctx.to_prompt_block())

    print("\n[Single mutation]")
    mut_json = mistral.generate_mutation(ctx, known_anomalies=[], previous_mutations=[])
    if mut_json:
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
    for i, mj in enumerate(burst):
        m = GTP_U_Mutation.from_json(ctx, mj)
        pkt_b = bytes(build_gtpu_packet_from_mutation(m))
        print(f"  [{i+1}] requested={mj.get('requested_anomaly_type')} resolved={mj.get('anomaly_type')} raw_valid={mj.get('raw_schema_valid')} {' '.join(f'{b:02x}' for b in pkt_b)}")


if __name__ == "__main__":
    main()