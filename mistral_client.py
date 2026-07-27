"""Mistral LLM offline client for GTP-U benign baseline & adversarial mutation generation."""

import json
import re
from typing import Optional, Dict, List, Any

from gtpu_scapy import (
    SELF_HOSTED_MODELS_URL,
    MODEL_VARIANT,
    KNOWN_EXTENSION_TYPES,
    ALLOWED_ANOMALIES,
)
from session_context import SessionContext

try:
    # pyrefly: ignore [missing-import]
    from litellm import completion as litellm_completion
except Exception:
    litellm_completion = None


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
                    response_format={"type": "json_object"},
                )
                return response.choices[0].message.content.strip()
            except Exception as e:
                print(f"[WARN] litellm generation failed: {e}")
        return ""

    def _infer_anomaly_type(self, headers: List[Dict], ctx: SessionContext,
                            requested_type: str,
                            previous_mutations: Optional[List[Dict]] = None) -> str:
        """Resolve the actual anomaly type from packet structure and session context.

        Only the four architecturally distinct attack types are recognized:
        - unsupported_extension_injection: exotic header (e.g. 0xC1) present
        - cross_flow_interference: burst-based, QFIs diverge across campaign packets
        - qfi_qer_mismatch: QFI not in session's active set or QER rule violation
        - timing_window_race: two-stage (handled separately, not inferred here)
        """
        ext_types = [h.get("type", 0x85) for h in headers]
        qfis = [h.get("qfi", 0) for h in headers]

        # Structural: exotic / unsupported extension header present
        if any(t != 0x85 for t in ext_types):
            return "unsupported_extension_injection"

        # Burst-based: cross-flow interference requires campaign context
        if requested_type == "cross_flow_interference" and previous_mutations:
            prev_qfis = []
            for prev in previous_mutations[-2:]:
                prev_qfis.extend([h.get("qfi", 0) for h in prev.get("extension_headers", [])])
            if any(q not in ctx.active_qfis for q in qfis) and prev_qfis and set(qfis) != set(prev_qfis):
                return "cross_flow_interference"

        # Semantic: QFI not provisioned for this session
        if any(q not in ctx.active_qfis for q in qfis):
            return "qfi_qer_mismatch"

        # Fall back to the requested type if it's in the allowed set
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
    {{"type": <int e.g. 133>, "pdu_type": <0 or 1>, "qfi": <int 0-63>, "rqi": <int 0-1>, "ppi": <int 0-7>}}
  ],
  "outer_dscp": <int 0-63>,
  "anomaly_type": "<one of: {sorted(ALLOWED_ANOMALIES)}>",
  "claims": {{"target_qfi": <int>}},
  "reasoning": "<1 concise sentence explaining the policy violation>"
}}

CRITICAL: Use ONLY base-10 decimal integers (e.g. 0, 1, 133). DO NOT use hex notation like 0x00 or 0x85.
"""
        response = self.generate(prompt, system, temperature=0.8, max_tokens=2000)
        try:
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            if json_start >= 0 and json_end > json_start:
                raw_json_str = response[json_start:json_end]
                raw_json_str = re.sub(r'\b0x[0-9a-fA-F]+\b', lambda m: str(int(m.group(0), 16)), raw_json_str)
                parsed = json.loads(raw_json_str)
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

    # ------------------------------------------------------------------
    # Benign (baseline) traffic generation
    # ------------------------------------------------------------------

    def _sanitize_benign(self, raw: Any, ctx: SessionContext) -> Optional[Dict[str, Any]]:
        """Sanitize LLM output for benign traffic, reusing the schema-clamping
        logic but enforcing session-consistency instead of anomaly classification."""
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
            pdu_type = clamp("pdu_type", ctx.pdu_type, 0, 1)
            # 3GPP TS 38.415: RQI and PPI are DL-only fields
            if pdu_type == 1:
                rqi = 0
                ppi = 0
            sanitized_headers.append({"type": ext_type, "pdu_type": pdu_type, "qfi": qfi, "rqi": rqi, "ppi": ppi})

        if not sanitized_headers:
            sanitized_headers = [{"type": 0x85, "pdu_type": ctx.pdu_type,
                                  "qfi": ctx.active_qfis[0], "rqi": 0, "ppi": 0}]

        try:
            dscp = int(raw.get("outer_dscp", ctx.dscp_marking))
        except (TypeError, ValueError):
            dscp = ctx.dscp_marking
        if not (0 <= dscp <= 0x3F):
            sanitization_log["clamped_fields"].append("outer_dscp")
            sanitization_log["raw_schema_valid"] = False
            dscp = max(0, min(0x3F, dscp))

        # Session-consistency checks (deterministic, not LLM-dependent)
        first = sanitized_headers[0]
        qfi_consistent = first["qfi"] in ctx.active_qfis
        rqi_consistent = (first["rqi"] == 0 or first["qfi"] in ctx.reflective_qos_enabled_qfis)
        dscp_consistent = (dscp == ctx.dscp_marking)
        no_exotic_headers = all(h["type"] == 0x85 for h in sanitized_headers)
        session_consistent = qfi_consistent and rqi_consistent and dscp_consistent and no_exotic_headers

        reasoning = str(raw.get("reasoning", "")) or "Normal traffic consistent with session QoS policy."

        return {
            "teid": ctx.teid,
            "extension_headers": sanitized_headers,
            "outer_dscp": dscp,
            "traffic_class": "benign",
            "session_consistent": session_consistent,
            "consistency_detail": {
                "qfi_in_active_set": qfi_consistent,
                "rqi_matches_allowlist": rqi_consistent,
                "dscp_matches_session": dscp_consistent,
                "no_exotic_headers": no_exotic_headers,
            },
            "raw_schema_valid": sanitization_log["raw_schema_valid"],
            "sanitization_log": sanitization_log,
            "reasoning": reasoning,
        }

    def generate_benign(self, ctx: SessionContext) -> Optional[Dict]:
        """Generate a single benign, session-consistent GTP-U packet via LLM."""

        system = (
            "You are a 5G core network engineer. Your task is to produce "
            "normal, legitimate GTP-U PDU Session Container traffic that is "
            "FULLY CONSISTENT with the given session's QoS policy state. "
            "Do NOT introduce any anomaly or policy violation."
        )

        prompt = f"""Session state (your packet MUST be consistent with this):
{ctx.to_prompt_block()}

Task: Produce ONE normal, legitimate GTP-U packet that a real UPF would accept without any policy violation.

STRICT RULES — you must follow ALL of these:
1. extension_headers must contain exactly ONE entry with type 133 (PDU Session Container).
2. qfi MUST be one of the session's active QFIs: {ctx.active_qfis}
3. rqi may ONLY be 1 if the chosen QFI is in the reflective QoS allow-list: {ctx.reflective_qos_enabled_qfis}. Otherwise rqi MUST be 0.
4. If pdu_type is 1 (UL/Uplink), rqi and ppi MUST both be 0.
5. outer_dscp MUST be {ctx.dscp_marking} (the session's expected DSCP).
6. pdu_type should be {ctx.pdu_type} to match the session direction.

RESPOND ONLY WITH VALID JSON (no markdown formatting):
{{
  "extension_headers": [
    {{"type": 133, "pdu_type": {ctx.pdu_type}, "qfi": <one of {ctx.active_qfis}>, "rqi": <0 or 1>, "ppi": <0-7>}}
  ],
  "outer_dscp": {ctx.dscp_marking},
  "reasoning": "<1 sentence explaining why this packet is policy-compliant>"
}}

CRITICAL: Use ONLY base-10 decimal integers. DO NOT use hex notation.
"""
        response = self.generate(prompt, system, temperature=0.4, max_tokens=500)
        try:
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            if json_start >= 0 and json_end > json_start:
                raw_json_str = response[json_start:json_end]
                raw_json_str = re.sub(r'\b0x[0-9a-fA-F]+\b', lambda m: str(int(m.group(0), 16)), raw_json_str)
                parsed = json.loads(raw_json_str)
                return self._sanitize_benign(parsed, ctx)
        except json.JSONDecodeError:
            print(f"[WARN] Failed to parse benign JSON from Mistral: {response}")
        return None

    def generate_benign_batch(self, ctx: SessionContext, batch_size: int = 5) -> List[Dict]:
        """Generate a batch of benign baseline packets for the given session."""
        batch = []
        for _ in range(batch_size):
            pkt = self.generate_benign(ctx)
            if pkt:
                batch.append(pkt)
        return batch
