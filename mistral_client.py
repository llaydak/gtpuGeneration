"""Mistral LLM offline client for GTP-U benign baseline & adversarial mutation generation."""

import json
import os
import random
import re
from typing import Optional, Dict, List, Any

from gtpu_scapy import (
    SELF_HOSTED_MODELS_URL,
    MODEL_VARIANT,
    KNOWN_EXTENSION_TYPES,
    ALLOWED_ANOMALIES,
    FIELD_BOUNDS,
)
from session_context import SessionContext

try:
    # pyrefly: ignore [missing-import]
    from litellm import completion as litellm_completion
except Exception:
    litellm_completion = None

_5QI_3GPP_REFERENCE = {
    2: "GBR, Conversational Video (Live Streaming)",
    3: "GBR, Real-Time Gaming, V2X messages",
    4: "GBR, Non-Conversational Video (Buffered Streaming)",
    6: "Non-GBR, TCP-based apps (www, email, chat, ftp, p2p file sharing) — i.e. web browsing, NOT voice/video",
    8: "Non-GBR, video (buffered streaming), TCP-based apps",
}


class MistralClient:
    """Wrapper for LLM usage via LiteLLM, backed by either a local Ollama
    server (default, offline) or the OpenAI API (backend="openai")."""

    def __init__(self, base_url=SELF_HOSTED_MODELS_URL, model_name=MODEL_VARIANT,
                 backend: str = "ollama", api_key: Optional[str] = None,
                 max_output_tokens: Optional[int] = None):
        self.backend = backend
        # Ceiling applied to every generate() call's max_tokens, regardless of
        # backend; None (default) leaves each call site's own value untouched.
        self.max_output_tokens = max_output_tokens
        self.call_count = 0
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0

        if backend == "openai":
            self.base_url = None  # api_base is for the self-hosted Ollama server only
            self.model_name = model_name if model_name.startswith("openai/") else f"openai/{model_name}"
            self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
            if not self.api_key:
                raise ValueError(
                    "backend='openai' requires an API key: set OPENAI_API_KEY or pass api_key="
                )
        elif backend == "ollama":
            self.base_url = base_url
            self.model_name = model_name if model_name.startswith("ollama/") else f"ollama/{model_name}"
            self.api_key = None
        else:
            raise ValueError(f"Unknown backend {backend!r}, expected 'ollama' or 'openai'")

    def generate(self, prompt: str, system: str, max_tokens: int = 2000) -> str:
        if self.max_output_tokens is not None:
            max_tokens = min(max_tokens, self.max_output_tokens)
        if litellm_completion is not None:
            try:
                kwargs = dict(
                    model=self.model_name,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": prompt},
                    ],
                    max_tokens=max_tokens,
                    response_format={"type": "json_object"},
                )
                if self.base_url is not None:
                    kwargs["api_base"] = self.base_url
                if self.api_key is not None:
                    kwargs["api_key"] = self.api_key
                response = litellm_completion(**kwargs)

                self.call_count += 1
                usage = getattr(response, "usage", None)
                prompt_tokens = getattr(usage, "prompt_tokens", 0) or 0
                completion_tokens = getattr(usage, "completion_tokens", 0) or 0
                self.total_prompt_tokens += prompt_tokens
                self.total_completion_tokens += completion_tokens
                print(
                    f"[API CALL #{self.call_count}] model={self.model_name} "
                    f"prompt_tokens={prompt_tokens} completion_tokens={completion_tokens} "
                    f"(running total: {self.total_prompt_tokens} prompt / {self.total_completion_tokens} completion)"
                )

                return response.choices[0].message.content.strip()
            except Exception as e:
                print(f"[WARN] litellm generation failed: {e}")
        return ""

    def _infer_anomaly_type(self, headers: List[Dict], ctx: SessionContext,
                            requested_type: str,
                            previous_mutations: Optional[List[Dict]] = None,
                            outer_dscp: Optional[int] = None) -> Dict[str, Any]:
        """Resolve primary anomaly type and all detected secondary anomaly types from packet fields.
        """
        qfis = [h.get("qfi", 0) for h in headers]
        rqis = [h.get("rqi", 0) for h in headers]

        detected = []

        # Check 1: Cross-Flow Interference (Campaign Context: QFIs diverge across burst packets)
        if previous_mutations:
            prev_qfis = []
            for prev in previous_mutations[-2:]:
                prev_qfis.extend([h.get("qfi", 0) for h in prev.get("extension_headers", [])])
            if prev_qfis and set(qfis) != set(prev_qfis):
                detected.append("cross_flow_interference")

        # Check 2: Two-Stage Timing Window Race Condition
        if requested_type == "timing_window_race":
            detected.append("timing_window_race")

        # Check 3: QFI / QER / DSCP Semantic Policy Mismatch
        unprovisioned_qfi = any(q not in ctx.active_qfis for q in qfis)
        invalid_rqi = any(rqi == 1 and q not in ctx.reflective_qos_enabled_qfis for q, rqi in zip(qfis, rqis))
        invalid_dscp = (outer_dscp is not None and outer_dscp != ctx.dscp_marking)

        if unprovisioned_qfi or invalid_rqi or invalid_dscp:
            detected.append("qfi_qer_mismatch")

        # Deduplicate detected anomalies list while preserving order
        detected = list(dict.fromkeys(detected))

        # Determine primary anomaly: prioritize requested_type if it was detected
        if requested_type in detected:
            primary = requested_type
        elif detected:
            primary = detected[0]
        else:
            primary = requested_type if requested_type in ALLOWED_ANOMALIES else "qfi_qer_mismatch"

        if not detected:
            detected = [primary]

        return {
            "primary_anomaly": primary,
            "detected_anomalies": detected,
            "is_compound_anomaly": len(detected) > 1,
        }

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
        violates_qfis = first_qfi not in ctx.active_qfis
        violates_rqi = (first_rqi == 1) and (first_qfi not in ctx.reflective_qos_enabled_qfis)
        violates_dscp = dscp != ctx.dscp_marking
        is_anomalous = violates_qfis or violates_rqi or violates_dscp

        return {
            "violates_active_qfis": violates_qfis,
            "violates_rqi_allowlist": violates_rqi,
            "violates_dscp_marking": violates_dscp,
            "is_semantically_anomalous": is_anomalous,
            "semantic_precision_score": 1.0 if is_anomalous else 0.0,
        }

    def _evaluate_structured_claims(self, claims: Optional[Dict], headers: List[Dict], ctx: SessionContext) -> Dict[str, Any]:
        """Evaluation metric only: compare optional structured JSON claims from model against packet fields.

        This check is logged in the mutation dict for research evaluation purposes.
        It does not modify or gate any packet; it is never called in the benign path.
        """
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

    def _parse_json_response(self, response: str) -> Optional[Dict[str, Any]]:
        """Extract and parse a JSON dictionary from LLM text response, normalizing hex literals."""
        if not response:
            return None
        try:
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            if json_start >= 0 and json_end > json_start:
                raw_json_str = response[json_start:json_end]
                raw_json_str = re.sub(r'\b0x[0-9a-fA-F]+\b', lambda m: str(int(m.group(0), 16)), raw_json_str)
                return json.loads(raw_json_str)
        except json.JSONDecodeError:
            pass
        return None

    def _clamp_extension_headers(self, ext_headers_raw: Any, default_qfi: int = 0) -> tuple[List[Dict], Dict[str, Any]]:
        """Parse raw extension headers from LLM JSON and clamp fields to 3GPP bounds."""
        if not isinstance(ext_headers_raw, list) or not ext_headers_raw:
            ext_headers_raw = [{"type": 0x85, "qfi": default_qfi, "rqi": 0, "ppi": 0}]

        sanitization_log: Dict[str, Any] = {
            "clamped_fields": [],
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

            qfi = clamp("qfi", default_qfi, FIELD_BOUNDS["qfi"]["min"], FIELD_BOUNDS["qfi"]["max"])
            rqi = 1 if clamp("rqi", 0, FIELD_BOUNDS["rqi"]["min"], FIELD_BOUNDS["rqi"]["max"]) >= 1 else 0
            ppi = clamp("ppi", 0, FIELD_BOUNDS["ppi"]["min"], FIELD_BOUNDS["ppi"]["max"])
            pdu_type = clamp("pdu_type", 0, FIELD_BOUNDS["pdu_type"]["min"], FIELD_BOUNDS["pdu_type"]["max"])

            if pdu_type == 1:
                # 3GPP TS 38.415: RQI/PPI fields are structurally absent in UL containers
                rqi = 0
                ppi = 0

            sanitized_headers.append({"type": ext_type, "pdu_type": pdu_type, "qfi": qfi, "rqi": rqi, "ppi": ppi})

        if not sanitized_headers:
            sanitized_headers = [{"type": 0x85, "pdu_type": 0, "qfi": default_qfi, "rqi": 0, "ppi": 0}]

        return sanitized_headers, sanitization_log

    def _sanitize_mutation(self, raw: Any, ctx: SessionContext,
                           previous_mutations: Optional[List[Dict]] = None) -> Optional[Dict[str, Any]]:
        if not isinstance(raw, dict):
            return None

        ext_headers_raw = raw.get("extension_headers", [])
        sanitized_headers, sanitization_log = self._clamp_extension_headers(ext_headers_raw, default_qfi=0)
        sanitization_log["raw_model_output"] = raw

        requested_type = raw.get("anomaly_type", "qfi_qer_mismatch")
        if requested_type not in ALLOWED_ANOMALIES:
            requested_type = "qfi_qer_mismatch"

        try:
            dscp = int(raw.get("outer_dscp", ctx.dscp_marking))
        except (TypeError, ValueError):
            dscp = ctx.dscp_marking
        if not (FIELD_BOUNDS["outer_dscp"]["min"] <= dscp <= FIELD_BOUNDS["outer_dscp"]["max"]):
            sanitization_log["clamped_fields"].append("outer_dscp")
            sanitization_log["raw_schema_valid"] = False
            dscp = max(FIELD_BOUNDS["outer_dscp"]["min"], min(FIELD_BOUNDS["outer_dscp"]["max"], dscp))

        eval_res = self._infer_anomaly_type(sanitized_headers, ctx, requested_type, previous_mutations, outer_dscp=dscp)
        resolved_type = eval_res["primary_anomaly"]

        try:
            payload_size = int(raw.get("payload_size", 100))
        except (TypeError, ValueError):
            payload_size = 100

        try:
            inter_arrival_ms = float(raw.get("inter_arrival_ms", 20.0))
        except (TypeError, ValueError):
            inter_arrival_ms = 20.0

        # Record raw LLM intent alignment metric BEFORE any clamping repair occurred
        no_clamping_needed = (len(sanitization_log["clamped_fields"]) == 0 and sanitization_log["raw_schema_valid"])
        intent_matches_resolved = (requested_type in eval_res["detected_anomalies"])
        raw_llm_intent_aligned = (no_clamping_needed and intent_matches_resolved)

        mutation_dict = {
            "teid": ctx.teid,
            "extension_headers": sanitized_headers,
            "outer_dscp": dscp,
            "anomaly_type": resolved_type,
            "primary_anomaly": resolved_type,
            "detected_anomalies": eval_res["detected_anomalies"],
            "is_compound_anomaly": eval_res["is_compound_anomaly"],
            "requested_anomaly_type": requested_type,
            "raw_schema_valid": sanitization_log["raw_schema_valid"],
            "raw_llm_intent_aligned": raw_llm_intent_aligned,
            "sanitization_log": sanitization_log,
            "payload_size": payload_size,
            "inter_arrival_ms": inter_arrival_ms,
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
                          previous_mutations: Optional[List[Dict]] = None,
                          max_retries: int = 3) -> Optional[Dict]:

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

Task: Propose ONE mutation that violates the session state rules above.

NOTE: RQI and PPI are only meaningful when pdu_type=0 (downlink). If you set rqi or ppi to a nonzero value, you MUST also set pdu_type=0, or those fields will be silently dropped from the wire packet.

CAMPAIGN DIVERSITY REQUIREMENT:
If previous packets are shown above, your new packet MUST explore a different header order, QFI, or flag state.

Traffic Modeling:
Based on the chosen QFI's 5QI from {ctx.qfi_to_5qi}, you MUST estimate and output realistic `payload_size` (int, bytes) and `inter_arrival_ms` (float, milliseconds) in your JSON output.
Do not use generic values; apply your knowledge of 3GPP TS 23.501 traffic characteristics for the specific 5QI.

Field bounds:
- pdu_type: {FIELD_BOUNDS['pdu_type']['min']} (DL / Downlink) or {FIELD_BOUNDS['pdu_type']['max']} (UL / Uplink)
- qfi: {FIELD_BOUNDS['qfi']['min']}-{FIELD_BOUNDS['qfi']['max']}, rqi: {FIELD_BOUNDS['rqi']['min']}-{FIELD_BOUNDS['rqi']['max']}, ppi: {FIELD_BOUNDS['ppi']['min']}-{FIELD_BOUNDS['ppi']['max']}, outer_dscp: {FIELD_BOUNDS['outer_dscp']['min']}-{FIELD_BOUNDS['outer_dscp']['max']}

RESPOND ONLY WITH VALID JSON (no markdown formatting):
{{
  "extension_headers": [
    {{"type": <int e.g. 133>, "pdu_type": <0 or 1>, "qfi": <int {FIELD_BOUNDS['qfi']['min']}-{FIELD_BOUNDS['qfi']['max']}>, "rqi": <int {FIELD_BOUNDS['rqi']['min']}-{FIELD_BOUNDS['rqi']['max']}>, "ppi": <int {FIELD_BOUNDS['ppi']['min']}-{FIELD_BOUNDS['ppi']['max']}>}}
  ],
  "outer_dscp": <int {FIELD_BOUNDS['outer_dscp']['min']}-{FIELD_BOUNDS['outer_dscp']['max']}>,
  "anomaly_type": "<one of: {sorted(ALLOWED_ANOMALIES)}>",
  "claims": {{"target_qfi": <int>}},
  "reasoning": "<1 concise sentence explaining the policy violation>",
  "payload_size": <int>,
  "inter_arrival_ms": <float>
}}

CRITICAL: Use ONLY base-10 decimal integers (e.g. 0, 1, 133). DO NOT use hex notation like 0x00 or 0x85.
"""
        for attempt in range(1, max_retries + 1):
            response = self.generate(prompt, system, max_tokens=2000)
            parsed = self._parse_json_response(response)
            if parsed:
                return self._sanitize_mutation(parsed, ctx, previous_mutations=previous_mutations)
            print(f"[WARN] Failed to generate/parse mutation JSON from Mistral on attempt {attempt}/{max_retries}")

        print(f"[ERROR] Failed to generate valid mutation packet after {max_retries} attempts.")
        return None

    def generate_burst(self, ctx: SessionContext, burst_size: int = 5, max_retries_per_pkt: int = 3) -> List[Dict]:
        """Generate a multi-packet campaign for cross-flow / resource-exhaustion
        anomaly types, enforcing retries per packet slot to ensure full burst completion."""
        known: List[str] = []
        burst = []
        previous_mutations: List[Dict] = []
        for slot in range(burst_size):
            mut = self.generate_mutation(ctx, known, previous_mutations=previous_mutations, max_retries=max_retries_per_pkt)
            if mut:
                known.append(mut["anomaly_type"])
                previous_mutations.append(mut)
                burst.append(mut)
            else:
                print(f"[WARN] Burst campaign slot {slot+1}/{burst_size} failed after {max_retries_per_pkt} retries.")

        if len(burst) < burst_size:
            print(f"[TELEMETRY] Burst campaign completed with reduced size: {len(burst)}/{burst_size} packets generated.")
        return burst

    def _sanitize_benign(self, raw: Any, ctx: SessionContext,
                         reference_bitrate_bps: Optional[float] = None,
                         reference_inter_arrival_ms: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """Sanitize LLM output for benign traffic, recording raw LLM compliance
        to track model adherence metrics without hiding failures behind clamping."""
        if not isinstance(raw, dict):
            return None

        ext_headers_raw = raw.get("extension_headers", [])
        sanitized_headers, sanitization_log = self._clamp_extension_headers(ext_headers_raw, default_qfi=ctx.active_qfis[0])
        sanitization_log["raw_model_output"] = raw

        try:
            dscp = int(raw.get("outer_dscp", ctx.dscp_marking))
        except (TypeError, ValueError):
            dscp = ctx.dscp_marking
        if not (FIELD_BOUNDS["outer_dscp"]["min"] <= dscp <= FIELD_BOUNDS["outer_dscp"]["max"]):
            sanitization_log["clamped_fields"].append("outer_dscp")
            sanitization_log["raw_schema_valid"] = False
            dscp = max(FIELD_BOUNDS["outer_dscp"]["min"], min(FIELD_BOUNDS["outer_dscp"]["max"], dscp))

        # Check raw LLM compliance BEFORE any clamping/repair occurred
        raw_first_header = ext_headers_raw[0] if (isinstance(ext_headers_raw, list) and ext_headers_raw and isinstance(ext_headers_raw[0], dict)) else {}
        raw_qfi = raw_first_header.get("qfi")
        raw_rqi = raw_first_header.get("rqi", 0)
        raw_dscp_val = raw.get("outer_dscp")
        
        raw_qfi_compliant = (raw_qfi in ctx.active_qfis)
        raw_rqi_compliant = (raw_rqi == 0 or raw_qfi in ctx.reflective_qos_enabled_qfis)
        raw_dscp_compliant = (raw_dscp_val == ctx.dscp_marking)
        raw_llm_compliant = (raw_qfi_compliant and raw_rqi_compliant and raw_dscp_compliant and 
                             len(sanitization_log["clamped_fields"]) == 0)

        # Deterministic session-consistency checks on sanitized result
        first = sanitized_headers[0]
        qfi_consistent = first["qfi"] in ctx.active_qfis
        rqi_consistent = (first["rqi"] == 0 or first["qfi"] in ctx.reflective_qos_enabled_qfis)
        dscp_consistent = (dscp == ctx.dscp_marking)
        no_exotic_headers = all(h["type"] == 0x85 for h in sanitized_headers)
        session_consistent = qfi_consistent and rqi_consistent and dscp_consistent and no_exotic_headers

        reasoning = str(raw.get("reasoning", "")) or "Normal traffic consistent with session QoS policy."

        try:
            target_bitrate_bps = float(raw["target_bitrate_bps"])
        except (KeyError, TypeError, ValueError) as e:
            raise ValueError(f"LLM returned non-numeric or missing target_bitrate_bps: {raw.get('target_bitrate_bps')!r}") from e
        if target_bitrate_bps <= 0:
            raise ValueError(f"LLM returned non-positive target_bitrate_bps: {target_bitrate_bps}")

        try:
            inter_arrival_ms = float(raw["inter_arrival_ms"])
        except (KeyError, TypeError, ValueError) as e:
            raise ValueError(f"LLM returned non-numeric or missing inter_arrival_ms: {raw.get('inter_arrival_ms')!r}") from e
        if inter_arrival_ms <= 0:
            raise ValueError(f"LLM returned non-positive inter_arrival_ms: {inter_arrival_ms}")

        # This is a burst's TOTAL byte count (the caller splits it into
        # MTU-sized wire segments), not one packet's size. Bound it relative
        # to the session's own reference traffic profile rather than a fixed
        # number, so the check scales with whatever 5QI is actually in play.
        # The prompt allows bitrate and inter_arrival_ms to each independently
        # go up to ~3-4x their reference (real outliers on each axis) — since
        # payload_size = bitrate * iat, two simultaneous outliers compound
        # multiplicatively, so the ceiling needs headroom for ~12x, not 5x.
        payload_size = round(target_bitrate_bps * (inter_arrival_ms / 1000.0) / 8.0)
        if reference_bitrate_bps and reference_inter_arrival_ms:
            reference_payload_size = reference_bitrate_bps * (reference_inter_arrival_ms / 1000.0) / 8.0
            max_payload_size = max(1000, round(reference_payload_size * 15))
        else:
            max_payload_size = 1_000_000
        if not (1 <= payload_size <= max_payload_size):
            raise ValueError(
                f"Derived payload_size out of valid range: {payload_size} "
                f"(from target_bitrate_bps={target_bitrate_bps}, inter_arrival_ms={inter_arrival_ms}, "
                f"max allowed={max_payload_size})"
            )

        return {
            "teid": ctx.teid,
            "extension_headers": sanitized_headers,
            "outer_dscp": dscp,
            "traffic_class": "benign",
            "anomaly_type": "benign",  # Explicit sentinel label to prevent mislabeling in GTP_U_Mutation.from_json
            "raw_llm_compliant": raw_llm_compliant,  # Surfaced as explicit evaluation metric
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
            "payload_size": payload_size,
            "inter_arrival_ms": inter_arrival_ms,
            "target_bitrate_bps": target_bitrate_bps,
        }

    def generate_benign_batch(self, ctx: SessionContext, batch_size: int = 50,
                               max_retries: int = 3,
                               reference_bitrate_bps: Optional[float] = None,
                               reference_inter_arrival_ms: Optional[float] = None) -> List[Dict]:
        """Generate up to `batch_size` benign baseline packets in a SINGLE LLM
        call. Each call's output is capped by self.max_output_tokens (or a
        batch_size-based guess if unset), so pick batch_size accordingly
        (roughly 150-250 tokens per packet).

        reference_bitrate_bps / reference_inter_arrival_ms, if given, anchor
        the model's per-packet estimates to a known real-world value (e.g.
        Table II of the reference paper) instead of its own unguided recall.
        """

        system = (
            "You are a 5G core network engineer. Your task is to produce "
            "normal, legitimate GTP-U PDU Session Container traffic that is "
            "FULLY CONSISTENT with the given session's QoS policy state. "
            "Do NOT introduce any anomaly or policy violation."
        )

        sample_qfi = random.choice(ctx.active_qfis)
        sample_rqi = 1 if sample_qfi in ctx.reflective_qos_enabled_qfis else 0
        sample_5qi = ctx.qfi_to_5qi.get(sample_qfi)

        qfi_5qi_reference = "\n".join(
            f"  5QI {five_qi}: {_5QI_3GPP_REFERENCE.get(five_qi, 'unlisted — use your own TS 23.501 knowledge')}"
            for five_qi in sorted(set(ctx.qfi_to_5qi.values()))
        )

        reference_block = ""
        if reference_bitrate_bps is not None and reference_inter_arrival_ms is not None:
            reference_block = f"""
Reference measurement for this 5QI (Table II, published traffic model — anchor
to this, don't invent your own order of magnitude): mean sustained bitrate ~=
{reference_bitrate_bps:.0f} bps, mean inter-arrival ~= {reference_inter_arrival_ms:.1f} ms.
Real traffic at these means is NOT uniform around them — match these shapes,
don't clip to a narrow band:
- inter_arrival_ms behaves like a memoryless (exponential) process: most gaps
  cluster near or below the mean, but roughly 1 in 6-8 packets should have a
  gap 2-4x the mean — genuine outliers, not softened.
- target_bitrate_bps (and thus burst size) is right-skewed (log-normal,
  coefficient of variation ~0.3): most values within about +/-30% of the
  mean, but roughly 1 in 8-10 packets should be noticeably larger, up to 2-3x
  the mean — real bursts do get that big.
"""

        prompt = f"""Session state (every packet you produce MUST be consistent with this):
- TEID: {ctx.teid}
- Session Direction: DL (Downlink) (pdu_type=0)
- Active QFIs for this session: {ctx.active_qfis}
- QFI -> 5QI mapping: {ctx.qfi_to_5qi}
- QFI -> QER mapping: {ctx.qfi_to_qer}
- QFIs where Reflective QoS (RQI=1) is allowed: {ctx.reflective_qos_enabled_qfis}
- Session expected outer DSCP marking: {ctx.dscp_marking}

3GPP TS 23.501 Table 5.7.4-1 reference (Resource Type, Example Services) for
the 5QIs in this session — use this, not a guess, to identify the application:
{qfi_5qi_reference}

STRICT RULES (apply to EVERY packet in the array):
1. extension_headers must contain exactly ONE entry with type 133 (PDU Session Container).
2. qfi MUST be an integer chosen from the session's active QFIs: {ctx.active_qfis}
3. pdu_type MUST be 0 (Downlink).
4. rqi may ONLY be 1 if the chosen qfi is in the Reflective QoS list {ctx.reflective_qos_enabled_qfis}. Otherwise rqi MUST be 0.
5. ppi MUST be 0 (non-paging baseline traffic).
6. outer_dscp MUST be {ctx.dscp_marking}.

Traffic Modeling:
Look up this QFI's 5QI in {ctx.qfi_to_5qi} and recall its TS 23.501 Table 5.7.4-1
application (e.g. voice, video, gaming, browsing). For EACH packet output
`target_bitrate_bps` (bits/sec) and `inter_arrival_ms` (ms) for that
application. Do NOT compute payload size yourself — it is derived
deterministically downstream from these two numbers.
{reference_block}

REALISM REQUIREMENT: real traffic has genuine variance, not mild jitter — do
NOT repeat the exact same target_bitrate_bps/inter_arrival_ms pair on every
packet, and do NOT make every packet a small tweak of the last. A handful of
real outliers (noticeably larger or with a longer gap) is what makes a
distribution look real instead of artificial; a distribution with no outliers
at all is itself unrealistic.

Generate EXACTLY {batch_size} such packets.

EXAMPLE VALID OUTPUT (structure only — replace values with ones reasoned for
5QI {sample_5qi} as above, and vary them packet to packet):
{{
  "packets": [
    {{
      "extension_headers": [
        {{"type": 133, "pdu_type": 0, "qfi": {sample_qfi}, "rqi": {sample_rqi}, "ppi": 0}}
      ],
      "outer_dscp": {ctx.dscp_marking},
      "traffic_class": "benign",
      "anomaly_type": "benign",
      "target_bitrate_bps": "<int, bits/sec>",
      "inter_arrival_ms": "<float, ms>"
    }}
  ]
}}

Field bounds:
- type: 133
- pdu_type: 0
- qfi: one integer from {ctx.active_qfis}
- rqi: 0 or 1
- ppi: 0
- outer_dscp: {ctx.dscp_marking}

Use these EXACT field names, spelled correctly: extension_headers, outer_dscp,
target_bitrate_bps, inter_arrival_ms.

RESPOND ONLY WITH VALID JSON: a single object with one key "packets" whose
value is an array of EXACTLY {batch_size} packet objects as shown above. No
markdown formatting, no placeholder strings — target_bitrate_bps and
inter_arrival_ms must be actual numbers.
"""
        # If the caller set an explicit ceiling, request exactly that so its
        # effect is directly observable (generate() would otherwise clamp a
        # smaller heuristic value down and the ceiling would never bind).
        # Only fall back to a batch_size-based guess when no ceiling was set.
        requested_max_tokens = self.max_output_tokens or max(2000, batch_size * 300)

        for attempt in range(1, max_retries + 1):
            response = self.generate(prompt, system, max_tokens=requested_max_tokens)
            parsed = self._parse_json_response(response)
            raw_packets = parsed.get("packets") if isinstance(parsed, dict) else None
            if isinstance(raw_packets, list) and raw_packets:
                sanitized: List[Dict] = []
                for i, raw_pkt in enumerate(raw_packets):
                    try:
                        sanitized.append(self._sanitize_benign(
                            raw_pkt, ctx,
                            reference_bitrate_bps=reference_bitrate_bps,
                            reference_inter_arrival_ms=reference_inter_arrival_ms,
                        ))
                    except Exception as e:
                        print(f"[WARN] Skipping malformed packet {i+1}/{len(raw_packets)} in batch call: {e}")
                if sanitized:
                    if len(sanitized) < batch_size:
                        print(f"[TELEMETRY] Batch call returned {len(sanitized)}/{batch_size} usable packets.")
                    return sanitized
            print(f"[WARN] Failed to generate/parse batch JSON from Mistral on attempt {attempt}/{max_retries}")

        print(f"[ERROR] Failed to generate a benign packet batch after {max_retries} attempts.")
        return []
