"""LLM client (any backend/model via LiteLLM) for GTP-U benign baseline & adversarial mutation generation."""

import json
import os
import re
from typing import Optional, Dict, List, Any

from gtpu_scapy import (
    SELF_HOSTED_MODELS_URL,
    MODEL_VARIANT,
    KNOWN_EXTENSION_TYPES,
    FIELD_BOUNDS,
)
from session_context import SessionContext
from packet_model import GTP_U_Mutation

try:
    # pyrefly: ignore [missing-import]
    from litellm import completion as litellm_completion
except Exception:
    litellm_completion = None

# 3GPP TS 23.501 Table 5.7.4-1 (Standardized 5QI to QoS characteristics
# mapping). Resource Type / Priority Level / Packet Delay Budget / Packet
# Error Rate are the spec's own numbers, not a third-party empirical paper —
# reproduced here from memory of the published table; cross-check against
# your own copy of TS 23.501 before citing these in written work.
_5QI_3GPP_REFERENCE = {
    2: {
        "resource_type": "GBR",
        "priority_level": 40,
        "pdb_ms": 150,
        "per": "10^-3",
        "example_services": "Conversational Video (Live Streaming)",
    },
    3: {
        "resource_type": "GBR",
        "priority_level": 30,
        "pdb_ms": 50,
        "per": "10^-3",
        "example_services": "Real-Time Gaming, V2X messages",
    },
    4: {
        "resource_type": "GBR",
        "priority_level": 50,
        "pdb_ms": 300,
        "per": "10^-6",
        "example_services": "Non-Conversational Video (Buffered Streaming)",
    },
    6: {
        "resource_type": "Non-GBR",
        "priority_level": 60,
        "pdb_ms": 300,
        "per": "10^-6",
        "example_services": "TCP-based apps (www, email, chat, ftp, p2p file sharing, progressive video) — i.e. web browsing, NOT voice/video",
    },
    8: {
        "resource_type": "Non-GBR",
        "priority_level": 80,
        "pdb_ms": 300,
        "per": "10^-6",
        "example_services": "Video (Buffered Streaming), TCP-based apps",
    },
}


def _qos_line(five_qi: int) -> str:
    qos = _5QI_3GPP_REFERENCE.get(five_qi)
    if not qos:
        return f"  5QI {five_qi}: unlisted — use your own TS 23.501 knowledge"
    return (
        f"  5QI {five_qi}: {qos['resource_type']}, Priority {qos['priority_level']}, "
        f"Packet Delay Budget {qos['pdb_ms']}ms, Packet Error Rate {qos['per']} — "
        f"{qos['example_services']}"
    )


class LLMClient:
    """Wrapper for LLM usage via LiteLLM, backed by either a local Ollama
    server (default, offline) or the OpenAI API (backend="openai")."""

    def __init__(self, base_url=SELF_HOSTED_MODELS_URL, model_name=MODEL_VARIANT,
                 backend: str = "ollama", api_key: Optional[str] = None,
                 max_output_tokens: Optional[int] = None,
                 seed: Optional[int] = None):
        self.backend = backend
        # Base seed for reproducibility. Each generate() call uses seed+call_count,
        # so the whole run is reproducible (same base -> same sequence) while each
        # call still samples differently (no identical packets). None = provider default.
        self.seed = seed
        # Ceiling applied to every generate() call's max_tokens, regardless of
        # backend; None (default) leaves each call site's own value untouched.
        self.max_output_tokens = max_output_tokens
        self.call_count = 0
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        # Set by generate() after each call so callers can distinguish "the
        # model wrote invalid JSON" from "the response was cut off at
        # max_tokens" — the latter needs a smaller request, not just a retry.
        self.last_finish_reason: Optional[str] = None

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
                if self.seed is not None:
                    # Per-call seed: reproducible run, but a different draw each call.
                    kwargs["seed"] = self.seed + self.call_count
                response = litellm_completion(**kwargs)

                self.call_count += 1
                usage = getattr(response, "usage", None)
                prompt_tokens = getattr(usage, "prompt_tokens", 0) or 0
                completion_tokens = getattr(usage, "completion_tokens", 0) or 0
                self.total_prompt_tokens += prompt_tokens
                self.total_completion_tokens += completion_tokens
                self.last_finish_reason = getattr(response.choices[0], "finish_reason", None)
                print(
                    f"[API CALL #{self.call_count}] model={self.model_name} "
                    f"prompt_tokens={prompt_tokens} completion_tokens={completion_tokens} "
                    f"finish_reason={self.last_finish_reason} "
                    f"(running total: {self.total_prompt_tokens} prompt / {self.total_completion_tokens} completion)"
                )
                if self.last_finish_reason == "length":
                    print(
                        f"[WARN] Response was cut off at max_tokens={max_tokens} "
                        f"(finish_reason=length) — output is likely truncated mid-JSON."
                    )

                return response.choices[0].message.content.strip()
            except Exception as e:
                self.last_finish_reason = None
                print(f"[WARN] litellm generation failed: {e}")
        return ""

    def _evaluate_semantic_precision(self, headers: List[Dict], dscp: int, ctx: SessionContext,
                                     direction: str = "DL") -> Dict[str, Any]:
        """Deterministically check if the generated packet violates session policy bounds.

        ``direction`` selects which enforcement point the anomaly targets and
        therefore which violation dimensions actually count:

        * ``"UL"`` (uplink, pdu_type=1) — the UPF performs QoS-flow-ID
          verification (TS 29.244 PDR/QER matching, TS 23.501 §5.7): a QFI not
          in the session's authorized set is the exact case the UPF is
          supposed to reject, so ``violates_active_qfis`` is the *UPF-enforced*
          anomaly. RQI/PPI do not exist on the uplink container, and outer DSCP
          is a transport marking the UPF does not semantically verify — those
          are recorded but do NOT drive ``is_semantically_anomalous`` here.
        * ``"DL"`` (downlink, pdu_type=0) — QFI/RQI/DSCP are set by the UPF and
          consumed by the gNB/UE, so all three inconsistency dimensions count
          (this models a compromised-UPF egress rather than a UPF the packet
          is verified against).
        """
        first_qfi = headers[0].get("qfi", 0) if headers else 0
        first_rqi = headers[0].get("rqi", 0) if headers else 0
        violates_qfis = first_qfi not in ctx.active_qfis
        violates_rqi = (first_rqi == 1) and (first_qfi not in ctx.reflective_qos_enabled_qfis)
        violates_dscp = dscp != ctx.dscp_marking

        if direction == "UL":
            # Only the UL QFI verification the UPF actually performs counts.
            is_anomalous = violates_qfis
            enforcement_point = "UPF (UL QoS-flow-ID verification)"
        else:
            is_anomalous = violates_qfis or violates_rqi or violates_dscp
            enforcement_point = "gNB/UE (DL marking consumer)"

        return {
            "direction": direction,
            "enforcement_point": enforcement_point,
            "violates_active_qfis": violates_qfis,
            "violates_rqi_allowlist": violates_rqi,
            "violates_dscp_marking": violates_dscp,
            "is_semantically_anomalous": is_anomalous,
            "semantic_precision_score": 1.0 if is_anomalous else 0.0,
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

    def _sanitize_mutation(self, raw: Any, ctx: SessionContext, direction: str = "DL") -> Optional[Dict[str, Any]]:
        """Attach read-only evaluation metrics to the LLM's raw output.

        Nothing here corrects, clamps, or rejects extension_headers/outer_dscp
        — those fields go to packet construction exactly as the model wrote
        them, so a malformed value fails visibly downstream instead of being
        silently repaired. This function only measures/labels what the model
        already produced (semantic precision, schema validity) for telemetry.
        """
        if not isinstance(raw, dict):
            return None

        ext_headers = raw.get("extension_headers", [])
        dscp = raw.get("outer_dscp", ctx.dscp_marking)

        mutation_dict = dict(raw)
        mutation_dict["teid"] = ctx.teid
        mutation_dict["direction"] = direction
        mutation_dict["semantic_precision"] = self._evaluate_semantic_precision(ext_headers, dscp, ctx, direction)
        mutation_dict["raw_schema_valid"] = GTP_U_Mutation.from_json(ctx, mutation_dict).is_valid_schema()

        return mutation_dict

    def generate_mutation(self, ctx: SessionContext,
                          previous_mutations: Optional[List[Dict]] = None,
                          request_campaign_plan: bool = False,
                          direction: str = "DL",
                          max_retries: int = 3) -> Optional[Dict]:
        if direction == "UL":
            return self._generate_ul_mutation(
                ctx, previous_mutations=previous_mutations,
                request_campaign_plan=request_campaign_plan, max_retries=max_retries,
            )

        system = (
        "You are a 5G core network security researcher conducting authorized "
        "adversarial testing. Your task is to craft GTP-U PDU Session Container "
        "mutations that deliberately violate a session's QoS policy (its "
        "QER/FAR state, as provisioned via TS 29.244 PFCP rules), for use in "
        "evaluating anomaly-detection systems. Reason precisely about "
        "3GPP-defined header semantics (TS 29.281 GTP-U tunneling, TS 38.415 "
        "PDU Session Container) when choosing which field to violate."
        )

        previous_context_block = ""
        if previous_mutations:
            previous_context_block = "\n".join(
                f"Previous packet #{i+1}: {json.dumps(mut, sort_keys=True)}"
                for i, mut in enumerate(previous_mutations[-2:])
            )
            previous_context_block = "\n\nPrevious packets in this campaign (use them as dependency context):\n" + previous_context_block

        # Literal few-shot mutations — taken verbatim (not invented) from an
        # actual gpt-5.6-luna attack campaign run, one per violation
        # dimension. The earlier campaign defaulted heavily to RQI violations
        # when left unguided; showing all three real dimensions side by side
        # is meant to counter that skew.
        few_shot_json = json.dumps(
            [
                {
                    "extension_headers": [{"type": 133, "pdu_type": 0, "qfi": 7, "rqi": 0, "ppi": 0}],
                    "outer_dscp": 0,
                    "reasoning": "QFI 7 is not provisioned for this session's active QFI set [6].",
                    "payload_size": 1200,
                    "inter_arrival_ms": 20.0,
                },
                {
                    "extension_headers": [{"type": 133, "pdu_type": 0, "qfi": 6, "rqi": 1, "ppi": 0}],
                    "outer_dscp": 0,
                    "reasoning": "RQI=1 on QFI 6 is outside the reflective-QoS allow-list for this session.",
                    "payload_size": 1200,
                    "inter_arrival_ms": 20.0,
                },
                {
                    "extension_headers": [{"type": 133, "pdu_type": 0, "qfi": 6, "rqi": 0, "ppi": 0}],
                    "outer_dscp": 10,
                    "reasoning": "Outer DSCP 10 conflicts with the session's expected DSCP 0x00.",
                    "payload_size": 1180,
                    "inter_arrival_ms": 20.0,
                },
            ],
            indent=2,
        )

        qfi_5qi_reference = "\n".join(
            _qos_line(five_qi) for five_qi in sorted(set(ctx.qfi_to_5qi.values()))
        )

        campaign_plan_block = ""
        campaign_plan_schema = ""
        if request_campaign_plan:
            campaign_plan_block = """
CAMPAIGN PLAN (this is the first packet — you also decide the campaign's
shape, don't wait to be told): reason like a real attacker would. How many
packets would a realistic qfi_qer_mismatch campaign consist of here — a
quick probe or a sustained attempt? At what point in an ongoing benign
traffic flow would a compromised session realistically start misbehaving —
immediately, or only after blending in for a while? There is no fixed
answer; pick values that fit your own reasoning about this specific session,
and vary them from what you might have picked in other runs. Include in
your JSON:
- "campaign_size": int, total packets for this whole campaign (this one included)
- "injection_fraction": float 0.0-1.0, how far into the background traffic
  timeline this campaign should begin (0.0 = start, 1.0 = end)
"""
            campaign_plan_schema = """
  "campaign_size": <int>,
  "injection_fraction": <float 0.0-1.0>,"""

        prompt = f"""Session state (evaluate mutation AGAINST this session state):
{ctx.to_prompt_block()}
{previous_context_block}

Known 3GPP extension header type codes:
{json.dumps(KNOWN_EXTENSION_TYPES, indent=2)}

3GPP TS 23.501 Table 5.7.4-1 QoS characteristics, to ground your payload_size/
inter_arrival_ms estimate:
{qfi_5qi_reference}

Task: Generate mutation whose QFI, RQI, or outer DSCP violates the session state rules above (a qfi_qer_mismatch).
{campaign_plan_block}

NOTE: RQI and PPI are only meaningful when pdu_type=0 (downlink). If you set rqi or ppi to a nonzero value, you MUST also set pdu_type=0, or those fields will be silently dropped from the wire packet.

CAMPAIGN DIVERSITY REQUIREMENT: there are three independent ways to violate
this policy — (1) qfi outside the active set, (2) rqi=1 outside the
reflective-QoS allow-list, (3) outer_dscp != the session's expected value.
If previous packets are shown above, do NOT repeat the same one of these
three dimensions again — rotate to a different one, and also vary header
order/flag state within it.

REAL FEW-SHOT EXAMPLE — 3 mutations taken verbatim from an actual attack
campaign run, one per violation dimension above (qfi/rqi/dscp values are
from a different session, don't copy them — only the dimension and
plausibility of payload_size/inter_arrival_ms is the point):
{few_shot_json}

Traffic Modeling: output realistic `payload_size` (int, bytes) and
`inter_arrival_ms` (float, milliseconds), derived from the QoS
characteristics above (tighter Packet Delay Budget implies shorter
inter-arrival; GBR implies more sustained bitrate than Non-GBR) — not
generic values.

RESPOND ONLY WITH VALID JSON (no markdown formatting):
{{
  "extension_headers": [
    {{"type": <int e.g. 133>, "pdu_type": <0 or 1>, "qfi": <int {FIELD_BOUNDS['qfi']['min']}-{FIELD_BOUNDS['qfi']['max']}>, "rqi": <int {FIELD_BOUNDS['rqi']['min']}-{FIELD_BOUNDS['rqi']['max']}>, "ppi": <int {FIELD_BOUNDS['ppi']['min']}-{FIELD_BOUNDS['ppi']['max']}>}}
  ],
  "outer_dscp": <int {FIELD_BOUNDS['outer_dscp']['min']}-{FIELD_BOUNDS['outer_dscp']['max']}>,{campaign_plan_schema}
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
                return self._sanitize_mutation(parsed, ctx)
            print(f"[WARN] Failed to generate/parse mutation JSON from {self.model_name} on attempt {attempt}/{max_retries}")

        print(f"[ERROR] Failed to generate valid mutation packet after {max_retries} attempts.")
        return None

    def _generate_ul_mutation(self, ctx: SessionContext,
                              previous_mutations: Optional[List[Dict]] = None,
                              request_campaign_plan: bool = False,
                              max_retries: int = 3) -> Optional[Dict]:
        """Uplink (pdu_type=1) qfi_qer_mismatch mutation.

        The UL PDU Session Container carries a QFI only — RQI and PPI are
        downlink-only fields and do not exist here. The semantic violation is
        therefore a QFI outside the session's authorized set: exactly the
        condition the UPF's uplink QoS-flow-ID verification (TS 29.244 PDR/QER
        matching, TS 23.501 §5.7) is required to detect and reject. This is the
        one violation dimension the UPF itself enforces, which is what makes it
        the load-bearing case for a UPF-targeted study.
        """
        system = (
            "You are a 5G core network security researcher conducting authorized "
            "adversarial testing against a UPF. You craft UPLINK GTP-U PDU Session "
            "Container mutations (TS 38.415 UL PDU SESSION INFORMATION, pdu_type=1) "
            "whose QFI is not authorized for the session, to test whether the UPF's "
            "uplink QoS-flow-ID verification (TS 29.244 PDR/QER matching) rejects "
            "them. On the uplink container there is no RQI and no PPI field — only a "
            "QFI. Reason precisely about which unauthorized QFI a compromised UE or "
            "gNB would mark to slip a flow past the UPF's enforcement."
        )

        previous_context_block = ""
        if previous_mutations:
            previous_context_block = "\n".join(
                f"Previous packet #{i+1}: {json.dumps(mut, sort_keys=True)}"
                for i, mut in enumerate(previous_mutations[-2:])
            )
            previous_context_block = "\n\nPrevious packets in this campaign (use them as dependency context):\n" + previous_context_block

        qfi_5qi_reference = "\n".join(
            _qos_line(five_qi) for five_qi in sorted(set(ctx.qfi_to_5qi.values()))
        )

        campaign_plan_block = ""
        campaign_plan_schema = ""
        if request_campaign_plan:
            campaign_plan_block = """
CAMPAIGN PLAN (this is the first packet — you also decide the campaign's
shape): reason like a real attacker probing UPF uplink enforcement. How many
packets would a realistic unauthorized-QFI uplink campaign consist of here —
a quick probe or a sustained attempt? At what point in an ongoing benign
flow would a compromised UE realistically start marking unauthorized QFIs?
Pick values that fit your own reasoning about this specific session, and vary
them across runs. Include in your JSON:
- "campaign_size": int, total packets for this whole campaign (this one included)
- "injection_fraction": float 0.0-1.0, how far into the background traffic
  timeline this campaign should begin (0.0 = start, 1.0 = end)
"""
            campaign_plan_schema = """
  "campaign_size": <int>,
  "injection_fraction": <float 0.0-1.0>,"""

        prompt = f"""Session state (evaluate mutation AGAINST this session state):
{ctx.to_prompt_block()}
{previous_context_block}

3GPP TS 23.501 Table 5.7.4-1 QoS characteristics, to ground your payload_size/
inter_arrival_ms estimate:
{qfi_5qi_reference}

Task: Generate an UPLINK mutation (pdu_type=1) whose QFI is NOT in this
session's active QFI set {ctx.active_qfis} — the case the UPF's uplink
QoS-flow-ID verification must reject. The uplink container has NO RQI and NO
PPI: set both to 0. Do not change outer_dscp away from the session value
({ctx.dscp_marking}); on the uplink the QFI is the UPF-verified field.
{campaign_plan_block}

CAMPAIGN DIVERSITY REQUIREMENT: if previous packets are shown above, pick a
DIFFERENT unauthorized QFI than they used (still outside {ctx.active_qfis}),
and vary payload_size/inter_arrival_ms — don't repeat one value.

Traffic Modeling: output realistic `payload_size` (int, bytes) and
`inter_arrival_ms` (float, milliseconds) grounded in the QoS characteristics
above — not generic values.

RESPOND ONLY WITH VALID JSON (no markdown formatting):
{{
  "extension_headers": [
    {{"type": 133, "pdu_type": 1, "qfi": <int {FIELD_BOUNDS['qfi']['min']}-{FIELD_BOUNDS['qfi']['max']} and NOT in {ctx.active_qfis}>, "rqi": 0, "ppi": 0}}
  ],
  "outer_dscp": {ctx.dscp_marking},{campaign_plan_schema}
  "reasoning": "<1 concise sentence: which unauthorized QFI and why the UPF should reject it>",
  "payload_size": <int>,
  "inter_arrival_ms": <float>
}}

CRITICAL: Use ONLY base-10 decimal integers. DO NOT use hex notation like 0x00 or 0x85.
"""
        for attempt in range(1, max_retries + 1):
            response = self.generate(prompt, system, max_tokens=2000)
            parsed = self._parse_json_response(response)
            if parsed:
                return self._sanitize_mutation(parsed, ctx, direction="UL")
            print(f"[WARN] Failed to generate/parse UL mutation JSON from {self.model_name} on attempt {attempt}/{max_retries}")

        print(f"[ERROR] Failed to generate valid UL mutation packet after {max_retries} attempts.")
        return None

    def generate_burst(self, ctx: SessionContext, burst_size: Optional[int] = None,
                       direction: str = "DL",
                       max_retries_per_pkt: int = 3, fallback_burst_size: int = 10) -> List[Dict]:
        """Generate a multi-packet qfi_qer_mismatch campaign.

        ``direction`` is "DL" (downlink, pdu_type=0, the compromised-UPF-egress
        model) or "UL" (uplink, pdu_type=1, the case the UPF's own QoS-flow-ID
        verification is meant to reject — see _evaluate_semantic_precision).

        If burst_size is None (default), the model itself decides the
        campaign's size and where in the background traffic it should be
        injected — the first packet's response carries "campaign_size" /
        "injection_fraction" (see generate_mutation's campaign-plan prompt),
        so every run can land at a different point with a different length
        instead of a fixed spot. Pass an explicit burst_size to override this
        and pin it to a fixed count (e.g. for a reproducible test run).
        """
        burst: List[Dict] = []
        previous_mutations: List[Dict] = []

        first = self.generate_mutation(
            ctx, previous_mutations=previous_mutations,
            request_campaign_plan=(burst_size is None), direction=direction,
            max_retries=max_retries_per_pkt,
        )
        if not first:
            print("[WARN] Burst campaign slot 1/? failed after retries.")
            return []
        previous_mutations.append(first)
        burst.append(first)

        if burst_size is None:
            planned = first.get("campaign_size")
            if isinstance(planned, int) and planned >= 1:
                burst_size = planned
            else:
                print(f"[WARN] Model didn't provide a usable campaign_size ({planned!r}); falling back to {fallback_burst_size}.")
                burst_size = fallback_burst_size

        for slot in range(2, burst_size + 1):
            mut = self.generate_mutation(ctx, previous_mutations=previous_mutations,
                                         direction=direction, max_retries=max_retries_per_pkt)
            if mut:
                previous_mutations.append(mut)
                burst.append(mut)
            else:
                print(f"[WARN] Burst campaign slot {slot}/{burst_size} failed after {max_retries_per_pkt} retries.")

        if len(burst) < burst_size:
            print(f"[TELEMETRY] Burst campaign completed with reduced size: {len(burst)}/{burst_size} packets generated.")
        return burst

    def _sanitize_benign(self, raw: Any, ctx: SessionContext) -> Optional[Dict[str, Any]]:
        """Attach read-only evaluation metrics to the LLM's raw benign output.

        Nothing here corrects, clamps, or rejects extension_headers/outer_dscp
        — those fields go to packet construction exactly as the model wrote
        them, so a malformed value fails visibly downstream instead of being
        silently repaired. This function only measures/labels what the model
        already produced (session-consistency, schema validity) for telemetry.
        """
        if not isinstance(raw, dict):
            return None

        ext_headers = raw.get("extension_headers", [])
        dscp = raw.get("outer_dscp", ctx.dscp_marking)

        first = ext_headers[0] if (isinstance(ext_headers, list) and ext_headers and isinstance(ext_headers[0], dict)) else {}
        qfi = first.get("qfi")
        rqi = first.get("rqi", 0)

        qfi_consistent = qfi in ctx.active_qfis
        rqi_consistent = (rqi == 0 or qfi in ctx.reflective_qos_enabled_qfis)
        dscp_consistent = (dscp == ctx.dscp_marking)
        no_exotic_headers = (
            isinstance(ext_headers, list)
            and all(isinstance(h, dict) and h.get("type") == 133 for h in ext_headers)
        )
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
        # MTU-sized wire segments), not one packet's size.
        payload_size = round(target_bitrate_bps * (inter_arrival_ms / 1000.0) / 8.0)

        mutation_dict = {
            "teid": ctx.teid,
            "extension_headers": ext_headers,
            "outer_dscp": dscp,
            "traffic_class": "benign",
            "anomaly_type": "benign",  # Explicit sentinel label to prevent mislabeling in GTP_U_Mutation.from_json
            "raw_llm_compliant": session_consistent,  # Surfaced as explicit evaluation metric
            "session_consistent": session_consistent,
            "consistency_detail": {
                "qfi_in_active_set": qfi_consistent,
                "rqi_matches_allowlist": rqi_consistent,
                "dscp_matches_session": dscp_consistent,
                "no_exotic_headers": no_exotic_headers,
            },
            "reasoning": reasoning,
            "payload_size": payload_size,
            "inter_arrival_ms": inter_arrival_ms,
            "target_bitrate_bps": target_bitrate_bps,
        }
        mutation_dict["raw_schema_valid"] = GTP_U_Mutation.from_json(ctx, mutation_dict).is_valid_schema()
        return mutation_dict

    def generate_benign_batch(self, ctx: SessionContext, batch_size: int = 50,
                               max_retries: int = 3) -> List[Dict]:
        """Generate benign baseline packets in a SINGLE LLM
        call. (roughly 150-250 tokens per packet in gpt-5.6-luna).

        Traffic timing/bitrate is grounded in each QFI's 3GPP TS 23.501
        Table 5.7.4-1 QoS characteristics (Resource Type, Priority Level,
        Packet Delay Budget, Packet Error Rate).
        """

        system = (
                "You are a senior 5G core network traffic engineer specializing in "
                "QoS-aware traffic modeling (3GPP TS 23.501). Your task is to produce "
                "normal, legitimate GTP-U PDU Session Container traffic that is FULLY "
                "CONSISTENT with the given session's QoS policy state, with realistic "
                "per-5QI timing and bitrate characteristics. Do NOT introduce any "
                "anomaly or policy violation."
        )

        qfi_5qi_reference = "\n".join(
            _qos_line(five_qi) for five_qi in sorted(set(ctx.qfi_to_5qi.values()))
        )

        few_shot_packets = [
            {"qfi": 6, "rqi": 0, "dscp": 0, "target_bitrate_bps": 770688, "inter_arrival_ms": 378.5},
            {"qfi": 6, "rqi": 0, "dscp": 0, "target_bitrate_bps": 3470943, "inter_arrival_ms": 125.8},
            {"qfi": 6, "rqi": 0, "dscp": 0, "target_bitrate_bps": 4242769, "inter_arrival_ms": 98.7},
            {"qfi": 6, "rqi": 0, "dscp": 0, "target_bitrate_bps": 81445596, "inter_arrival_ms": 7.4},
            {"qfi": 6, "rqi": 0, "dscp": 0, "target_bitrate_bps": 6554792, "inter_arrival_ms": 75.3},
            {"qfi": 6, "rqi": 0, "dscp": 0, "target_bitrate_bps": 5360527, "inter_arrival_ms": 94.2},
            {"qfi": 6, "rqi": 0, "dscp": 0, "target_bitrate_bps": 12664613, "inter_arrival_ms": 61.0},
            {"qfi": 6, "rqi": 0, "dscp": 0, "target_bitrate_bps": 44091814, "inter_arrival_ms": 14.6},
        ]
        few_shot_json = json.dumps(
            [
                {
                    "extension_headers": [
                        {"type": 133, "pdu_type": 0, "qfi": p["qfi"], "rqi": p["rqi"], "ppi": 0}
                    ],
                    "outer_dscp": p["dscp"],
                    "target_bitrate_bps": p["target_bitrate_bps"],
                    "inter_arrival_ms": p["inter_arrival_ms"],
                }
                for p in few_shot_packets
            ],
            indent=2,
        )

        def _build_prompt(n: int) -> str:
            return f"""Session state (every packet MUST be consistent with this):
- TEID: {ctx.teid}, Direction: DL (pdu_type=0)
- Active QFIs: {ctx.active_qfis}
- QFI -> 5QI: {ctx.qfi_to_5qi}
- Reflective QoS (RQI=1) allowed for QFIs: {ctx.reflective_qos_enabled_qfis}
- outer_dscp: {ctx.dscp_marking}

3GPP TS 23.501 Table 5.7.4-1 QoS characteristics, to identify each QFI's
application and derive realistic traffic behavior:
{qfi_5qi_reference}

RULES (every packet):
1. extension_headers: exactly one entry, type 133.
2. qfi: from {ctx.active_qfis}. pdu_type: 0. ppi: 0. outer_dscp: {ctx.dscp_marking}.
3. rqi: 1 only if qfi is in {ctx.reflective_qos_enabled_qfis}, else 0.
4. Output `target_bitrate_bps` (bits/sec) and `inter_arrival_ms` (ms) per the
   QFI's 5QI application — don't compute payload size, it's derived downstream.
   Derive these from the QoS characteristics above (not a fixed external
   benchmark): a tighter Packet Delay Budget implies shorter, more
   time-sensitive inter-arrival; GBR implies a more sustained/guaranteed
   bitrate than Non-GBR. Use your own domain knowledge of what that resource
   type and example service typically looks like on the wire.

REAL FEW-SHOT EXAMPLE — 8 packets taken verbatim from an actual captured
traffic burst (5QI 6, Non-GBR web browsing). This is not a target mean to
match — it illustrates the SHAPE of realistic variance: a burst that arrives
sooner than the previous one also tends to carry more bytes, so its
instantaneous bitrate can spike far above a typical value while
inter_arrival_ms drops to a fraction of it. Reproduce this same magnitude of
swing for your own QFI/5QI, scaled to what you derive above — the
qfi/rqi/dscp values below are from a different session, don't copy them:
{few_shot_json}

Generate EXACTLY {n} such packets.

RESPOND ONLY WITH VALID JSON: {{"packets": [...]}} with EXACTLY {n}
objects using these exact field names — extension_headers, outer_dscp,
target_bitrate_bps, inter_arrival_ms. No markdown, no placeholder strings;
target_bitrate_bps and inter_arrival_ms must be real numbers.
"""

        # If the caller set an explicit ceiling, respect it as a hard cap
        # (generate() would otherwise clamp a smaller heuristic value down
        # and the ceiling would never bind). Otherwise size it off however
        # many packets are actually being requested this attempt.
        current_batch_size = batch_size

        for attempt in range(1, max_retries + 1):
            requested_max_tokens = self.max_output_tokens or max(2000, current_batch_size * 300)
            prompt = _build_prompt(current_batch_size)
            response = self.generate(prompt, system, max_tokens=requested_max_tokens)
            truncated = (self.last_finish_reason == "length")
            parsed = self._parse_json_response(response)
            raw_packets = parsed.get("packets") if isinstance(parsed, dict) else None
            if isinstance(raw_packets, list) and raw_packets:
                sanitized: List[Dict] = []
                for i, raw_pkt in enumerate(raw_packets):
                    try:
                        sanitized.append(self._sanitize_benign(raw_pkt, ctx))
                    except Exception as e:
                        print(f"[WARN] Skipping malformed packet {i+1}/{len(raw_packets)} in batch call: {e}")
                if sanitized:
                    if len(sanitized) < current_batch_size:
                        print(f"[TELEMETRY] Batch call returned {len(sanitized)}/{current_batch_size} usable packets.")
                    return sanitized
            print(f"[WARN] Failed to generate/parse batch JSON from {self.model_name} on attempt {attempt}/{max_retries}")
            if truncated and current_batch_size > 1:
                # The response was cut off at max_tokens, not merely
                # malformed — retrying with the same request size would
                # likely truncate again. Shrink what we ask for so the next
                # attempt actually has a chance to complete.
                current_batch_size = max(1, current_batch_size // 2)
                print(f"[WARN] Response was truncated (finish_reason=length) — retrying with a smaller batch_size={current_batch_size}.")

        print(f"[ERROR] Failed to generate a benign packet batch after {max_retries} attempts.")
        return []

