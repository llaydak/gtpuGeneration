"""LLM client (any backend/model via LiteLLM) for GTP-U benign baseline & adversarial mutation generation."""

import json
import os
from typing import Optional, Dict, List, Any

import numpy as np
from dotenv import load_dotenv

from gtpu import FIELD_BOUNDS, GTP_U_Mutation
from session_context import SessionContext
import reference_models

load_dotenv()
SELF_HOSTED_MODELS_URL = os.environ["SELF_HOSTED_MODELS_URL"]
MODEL_VARIANT = os.environ["MODEL_VARIANT"]

try:
    import litellm
    from litellm import completion as litellm_completion
    litellm.suppress_debug_info = True
except Exception:
    litellm_completion = None

# 3GPP TS 23.501 Table 5.7.4-1 (Standardized 5QI to QoS characteristics mapping),
# pre-rendered in the spec's own Resource Type / Priority Level / Packet Delay
# Budget / Packet Error Rate order. Only 5QI 6 is listed: the benign session maps
# QFI 1 -> 5QI 6 and no other QoS class is generated.
_5QI_3GPP_REFERENCE = {
    6: "Non-GBR, Priority 60, Packet Delay Budget 300ms, Packet Error Rate 10^-6 — "
       "TCP-based apps (www, email, chat, ftp, p2p file sharing, progressive video) — "
       "i.e. web browsing, NOT voice/video",
}


def _qos_line(five_qi: int) -> str:
    spec = _5QI_3GPP_REFERENCE.get(five_qi, "unlisted — use your own TS 23.501 knowledge")
    return f"  5QI {five_qi}: {spec}"


def _qos_reference_block(ctx: SessionContext) -> str:
    """TS 23.501 QoS grounding lines for the session's 5QIs, for the prompt."""
    return "\n".join(_qos_line(q) for q in sorted(set(ctx.qfi_to_5qi.values())))


def _arrival_target_line() -> str:
    """5G-NIDD-grounded flow inter-arrival target (ms) for the prompt. A
    compromised UE's flows arrive like any UE's, so benign and attack share it —
    keeping the attack purely a QoS-marking anomaly, not a rate/volume spike."""
    a = reference_models.arrival_gap_percentiles()
    if not a:
        return ("inter_arrival_ms is MILLISECONDS; consecutive flows are seconds apart "
                "(~5000 ms median), so output values in the THOUSANDS (e.g. 5000), not single digits.")
    return (f"inter_arrival_ms is in MILLISECONDS (1 s = 1000 ms). Real 5G-NIDD distribution: "
            f"median ~{a['p50']:,} ms (~{a['p50']/1000:.0f} s), ~90% below ~{a['p90']:,} ms "
            f"(~{a['p90']/1000:.0f} s), heavy-tailed. Flows are SECONDS apart (a UE's think-time), "
            f"so inter_arrival_ms is in the THOUSANDS — e.g. 5000, 12000, 800. Do NOT output values "
            f"under ~500 for most flows.")


# Model-authored fields only — never echo our own evaluation back into the prompt.
_ECHO_FIELDS = ("extension_headers", "outer_dscp", "reasoning", "payload_size", "inter_arrival_ms")


_CAMPAIGN_PLAN_SCHEMA = """
  "campaign_size": <int>,
  "injection_fraction": <float 0.0-1.0>,"""


def _campaign_plan_block(actor: str) -> str:
    return f"""
CAMPAIGN PLAN (first packet — you set the campaign's shape too). Think as {actor}.
Decide: a quick probe or a sustained attempt, and whether to strike immediately or
blend in first. Vary both across runs. Add to your JSON:
- "campaign_size": int, total packets in this campaign (including this one)
- "injection_fraction": float 0.0-1.0, where in the background timeline it starts
"""


def _previous_context(previous_mutations: Optional[List[Dict]]) -> str:
    if not previous_mutations:
        return ""
    shown = "\n".join(
        f"Previous packet #{i+1}: {json.dumps({k: m[k] for k in _ECHO_FIELDS if k in m}, sort_keys=True)}"
        for i, m in enumerate(previous_mutations[-2:])
    )
    return "\n\nPrevious packets in this campaign (use them as dependency context):\n" + shown


class LLMClient:

    def __init__(self, base_url=SELF_HOSTED_MODELS_URL, model_name=MODEL_VARIANT,
                 backend: str = "ollama", api_key: Optional[str] = None,
                 max_output_tokens: Optional[int] = None):

        self.max_output_tokens = max_output_tokens
        self.call_count = 0
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.last_finish_reason: Optional[str] = None
        # Redrawn per batch (reference_models.sample_example_flows) so no few-shot
        # set becomes a ceiling; unseeded, like the provider's own sampling.
        self._few_shot_rng = np.random.default_rng()

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
        """Deterministically check if the generated packet violates session policy bounds."""
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
            "enforcement_point": enforcement_point,
            "violates_active_qfis": violates_qfis,
            "violates_rqi_allowlist": violates_rqi,
            "violates_dscp_marking": violates_dscp,
            "is_semantically_anomalous": is_anomalous,
        }

    def _parse_json_response(self, response: str) -> Optional[Dict[str, Any]]:
        """Extract and parse a JSON dictionary from an LLM text response."""
        try:
            return json.loads(response)
        except (json.JSONDecodeError, TypeError):
            return None

    def _sanitize_mutation(self, raw: Any, ctx: SessionContext, direction: str = "DL") -> Optional[Dict[str, Any]]:
        """Attach read-only evaluation metrics to the LLM's raw output."""
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
        "QER/FAR state, as provisioned via TS 29.244 PFCP rules). Reason precisely about "
        "3GPP-defined header semantics (TS 29.281 GTP-U tunneling, TS 38.415 "
        "PDU Session Container) when choosing which field to violate."
        )

        previous_context_block = _previous_context(previous_mutations)

        few_shot_json = json.dumps(
            [
                {
                    "extension_headers": [{"type": 133, "pdu_type": 0, "qfi": 7, "rqi": 0, "ppi": 0}],
                    "outer_dscp": 0,
                    "reasoning": "QFI 7 is not provisioned for this session's active QFI set [6].",
                    "payload_size": 1200,
                    "inter_arrival_ms": 4200.0,
                },
                {
                    "extension_headers": [{"type": 133, "pdu_type": 0, "qfi": 6, "rqi": 1, "ppi": 0}],
                    "outer_dscp": 0,
                    "reasoning": "RQI=1 on QFI 6 is outside the reflective-QoS allow-list for this session.",
                    "payload_size": 1200,
                    "inter_arrival_ms": 8100.0,
                },
                {
                    "extension_headers": [{"type": 133, "pdu_type": 0, "qfi": 6, "rqi": 0, "ppi": 0}],
                    "outer_dscp": 10,
                    "reasoning": "Outer DSCP 10 conflicts with the session's expected DSCP 0x00.",
                    "payload_size": 1180,
                    "inter_arrival_ms": 3500.0,
                },
            ],
            indent=2,
        )

        qfi_5qi_reference = _qos_reference_block(ctx)

        campaign_plan_block = _campaign_plan_block("a real attacker") if request_campaign_plan else ""
        campaign_plan_schema = _CAMPAIGN_PLAN_SCHEMA if request_campaign_plan else ""

        prompt = f"""Session state (evaluate mutation AGAINST this session state):
{ctx.to_prompt_block()}
{previous_context_block}

QoS grounding (TS 23.501) for payload_size (bytes):
{qfi_5qi_reference}

{_arrival_target_line()}
The compromised UE behaves like a normal UE in TIMING — only its QoS markings are
malicious. Do NOT burst; space flows seconds apart like benign traffic so the anomaly
is purely semantic, not a rate spike.

Task: Generate a mutation using extension header type 133 (PDU Session Container)
whose QFI, RQI, or outer DSCP violates the session state rules above (a qfi_qer_mismatch).
{campaign_plan_block}

NOTE: RQI and PPI are only meaningful when pdu_type=0 (downlink). If you set rqi or ppi to a nonzero value, you MUST also set pdu_type=0, or those fields will be silently dropped from the wire packet.

CAMPAIGN DIVERSITY REQUIREMENT: there are three independent ways to violate
this policy — (1) qfi outside the active set, (2) rqi=1 outside the
reflective-QoS allow-list, (3) outer_dscp != the session's expected value.
If previous packets are shown above, do NOT repeat the same one of these
three dimensions again — rotate to a different one, and also vary header
order/flag state within it.

Real examples, one per dimension (from another session — reuse the shape and the
plausible payload_size/inter_arrival_ms, not the exact qfi/rqi/dscp values):
{few_shot_json}

Respond with JSON only:
{{
  "extension_headers": [
    {{"type": 133, "pdu_type": <0 or 1>, "qfi": <int {FIELD_BOUNDS['qfi']['min']}-{FIELD_BOUNDS['qfi']['max']}>, "rqi": <int {FIELD_BOUNDS['rqi']['min']}-{FIELD_BOUNDS['rqi']['max']}>, "ppi": <int {FIELD_BOUNDS['ppi']['min']}-{FIELD_BOUNDS['ppi']['max']}>}}
  ],
  "outer_dscp": <int {FIELD_BOUNDS['outer_dscp']['min']}-{FIELD_BOUNDS['outer_dscp']['max']}>,{campaign_plan_schema}
  "reasoning": "<1 concise sentence explaining the policy violation>",
  "payload_size": <int>,
  "inter_arrival_ms": <float>
}}
"""
        return self._retry_mutation(system, prompt, ctx, direction="DL", max_retries=max_retries)

    def _retry_mutation(self, system: str, prompt: str, ctx: SessionContext,
                        direction: str, max_retries: int) -> Optional[Dict]:
        for attempt in range(1, max_retries + 1):
            parsed = self._parse_json_response(self.generate(prompt, system, max_tokens=2000))
            if parsed:
                return self._sanitize_mutation(parsed, ctx, direction=direction)
            print(f"[WARN] Failed to generate/parse {direction} mutation JSON from "
                  f"{self.model_name} on attempt {attempt}/{max_retries}")
        print(f"[ERROR] Failed to generate valid {direction} mutation after {max_retries} attempts.")
        return None

    def _generate_ul_mutation(self, ctx: SessionContext,
                              previous_mutations: Optional[List[Dict]] = None,
                              request_campaign_plan: bool = False,
                              max_retries: int = 3) -> Optional[Dict]:
        """Uplink (pdu_type=1) qfi_qer_mismatch mutation.

        The UL PDU Session Container carries a QFI only"""
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

        previous_context_block = _previous_context(previous_mutations)

        qfi_5qi_reference = _qos_reference_block(ctx)

        campaign_plan_block = (
            _campaign_plan_block("a compromised UE probing UPF uplink enforcement")
            if request_campaign_plan else ""
        )
        campaign_plan_schema = _CAMPAIGN_PLAN_SCHEMA if request_campaign_plan else ""

        prompt = f"""Session state (evaluate mutation AGAINST this session state):
{ctx.to_prompt_block()}
{previous_context_block}

QoS grounding (TS 23.501) for payload_size (bytes):
{qfi_5qi_reference}

{_arrival_target_line()}
The compromised UE behaves like a normal UE in TIMING — only its QFI is unauthorized.
Do NOT burst; space flows seconds apart like benign traffic so the anomaly is purely
semantic, not a rate spike.

Task: Generate an UPLINK mutation (pdu_type=1) whose QFI is NOT in this
session's active QFI set {ctx.active_qfis} — the case the UPF's uplink
QoS-flow-ID verification must reject. The uplink container has NO RQI and NO
PPI: set both to 0. Do not change outer_dscp away from the session value
({ctx.dscp_marking}); on the uplink the QFI is the UPF-verified field.
{campaign_plan_block}

CAMPAIGN DIVERSITY REQUIREMENT: if previous packets are shown above, pick a
DIFFERENT unauthorized QFI than they used (still outside {ctx.active_qfis}),
and vary payload_size/inter_arrival_ms — don't repeat one value.

Respond with JSON only:
{{
  "extension_headers": [
    {{"type": 133, "pdu_type": 1, "qfi": <int {FIELD_BOUNDS['qfi']['min']}-{FIELD_BOUNDS['qfi']['max']} and NOT in {ctx.active_qfis}>, "rqi": 0, "ppi": 0}}
  ],
  "outer_dscp": {ctx.dscp_marking},{campaign_plan_schema}
  "reasoning": "<1 concise sentence: which unauthorized QFI and why the UPF should reject it>",
  "payload_size": <int>,
  "inter_arrival_ms": <float>
}}
"""
        return self._retry_mutation(system, prompt, ctx, direction="UL", max_retries=max_retries)

    def generate_burst(self, ctx: SessionContext, burst_size: Optional[int] = None,
                       duration_sec: Optional[float] = None, direction: str = "DL",
                       max_retries_per_pkt: int = 3,
                       duration_max_packets: int = 500) -> List[Dict]:
        """Generate a multi-packet qfi_qer_mismatch campaign.

        Length precedence: duration_sec (keep generating until the campaign's own
        inter_arrival_ms fills that many seconds, capped at duration_max_packets
        so a small IAT can't run the API cost away), else burst_size packets,
        else the model's own campaign_size. Each packet is one API call.
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

        if duration_sec is not None:
            target_ms = duration_sec * 1000.0
            elapsed_ms = first.get("inter_arrival_ms") or 5000.0
            consecutive_fail = 0
            while elapsed_ms < target_ms and len(burst) < duration_max_packets:
                mut = self.generate_mutation(ctx, previous_mutations=previous_mutations,
                                             direction=direction, max_retries=max_retries_per_pkt)
                if mut:
                    consecutive_fail = 0
                    previous_mutations.append(mut)
                    burst.append(mut)
                    elapsed_ms += mut.get("inter_arrival_ms") or 5000.0
                else:
                    consecutive_fail += 1
                    print(f"[WARN] Attack slot {len(burst)+1} failed after {max_retries_per_pkt} retries.")
                    if consecutive_fail >= 3:
                        print("[ERROR] 3 consecutive failures — stopping the campaign early.")
                        break
            if len(burst) >= duration_max_packets and elapsed_ms < target_ms:
                print(f"[WARN] Duration campaign hit the {duration_max_packets}-packet safety cap at "
                      f"~{elapsed_ms/1000:.1f}s of {duration_sec:.0f}s — raise duration_max_packets to fill it.")
            print(f"[TELEMETRY] Duration campaign: {len(burst)} packets (= {len(burst)} API calls) "
                  f"covering ~{elapsed_ms/1000:.1f}s of a {duration_sec:.0f}s window.")
            return burst

        if burst_size is None:
            planned = first.get("campaign_size")
            if isinstance(planned, int) and planned >= 1:
                burst_size = planned
            else:
                print(f"[WARN] Model didn't provide a usable campaign_size ({planned!r}); falling back to 10.")
                burst_size = 10

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
        """
        if not isinstance(raw, dict):
            return None

        ext_headers = raw.get("extension_headers", [])
        dscp = raw.get("outer_dscp", ctx.dscp_marking)

        first = ext_headers[0] if (isinstance(ext_headers, list) and ext_headers and isinstance(ext_headers[0], dict)) else {}
        qfi = first.get("qfi")
        rqi = first.get("rqi", 0)

        policy_violations = [name for name, ok in (
            ("qfi_not_in_active_set", qfi in ctx.active_qfis),
            ("rqi_outside_allowlist", rqi == 0 or qfi in ctx.reflective_qos_enabled_qfis),
            ("dscp_mismatch", dscp == ctx.dscp_marking),
            ("exotic_extension_header", isinstance(ext_headers, list) and all(
                isinstance(h, dict) and h.get("type") == 133 for h in ext_headers)),
        ) if not ok]

        reasoning = str(raw.get("reasoning", "")) or "Normal traffic consistent with session QoS policy."

        try:
            payload_size = int(round(float(raw["payload_size"])))
        except (KeyError, TypeError, ValueError) as e:
            raise ValueError(f"LLM returned non-numeric or missing payload_size: {raw.get('payload_size')!r}") from e
        if payload_size <= 0:
            raise ValueError(f"LLM returned non-positive payload_size: {payload_size}")

        try:
            inter_arrival_ms = float(raw["inter_arrival_ms"])
        except (KeyError, TypeError, ValueError) as e:
            raise ValueError(f"LLM returned non-numeric or missing inter_arrival_ms: {raw.get('inter_arrival_ms')!r}") from e
        if inter_arrival_ms <= 0:
            raise ValueError(f"LLM returned non-positive inter_arrival_ms: {inter_arrival_ms}")

        try:
            request_bytes = int(raw["request_bytes"])
        except (KeyError, TypeError, ValueError) as e:
            raise ValueError(f"LLM returned non-numeric or missing request_bytes: {raw.get('request_bytes')!r}") from e
        if request_bytes <= 0:
            raise ValueError(f"LLM returned non-positive request_bytes: {request_bytes}")

        mutation_dict = {
            "teid": ctx.teid,
            "extension_headers": ext_headers,
            "outer_dscp": dscp,
            "traffic_class": "benign",
            "anomaly_type": "benign",  # Explicit sentinel label to prevent mislabeling in GTP_U_Mutation.from_json
            "policy_violations": policy_violations,
            "reasoning": reasoning,
            "payload_size": payload_size,
            "inter_arrival_ms": inter_arrival_ms,
            "request_bytes": request_bytes,
        }
        mutation_dict["raw_schema_valid"] = GTP_U_Mutation.from_json(ctx, mutation_dict).is_valid_schema()
        return mutation_dict

    def generate_benign_batch(self, ctx: SessionContext, batch_size: int = 50,
                               max_retries: int = 3) -> List[Dict]:

        system = (
                "You are a senior 5G core network traffic engineer specializing in "
                "QoS-aware traffic modeling (3GPP TS 23.501). Your task is to produce "
                "normal, legitimate GTP-U PDU Session Container traffic that is FULLY "
                "CONSISTENT with the given session's QoS policy state, with realistic "
                "per-5QI timing and bitrate characteristics. Do NOT introduce any "
                "anomaly or policy violation."
        )

        qfi_5qi_reference = _qos_reference_block(ctx)

        examples = reference_models.sample_example_flows(8, self._few_shot_rng)
        if examples:
            few_shot_block = "\n".join(
                f"- payload {e['total_bytes']:,} B, request {e['request_bytes']:,} B"
                for e in examples
            )
        else:
            few_shot_block = "(reference flows unavailable — rely on the shape above)"

     
        # Round figures give the shape without an exact value to latch onto.
        def _round_bytes(x: int) -> str:
            if x < 2_000:
                return f"~{round(x, -2):,} B"
            if x < 1_000_000:
                return f"~{x / 1000:.0f} KB"
            return f"~{x / 1_000_000:.0f} MB"

        pct = reference_models.flow_size_percentiles()
        shape_line = (
            f"Real payload_size distribution to reproduce: median {_round_bytes(pct['p50'])}, "
            f"~90% below {_round_bytes(pct['p90'])}, ~99% below {_round_bytes(pct['p99'])}, "
            f"with rare outliers up to a few MB."
            if pct else
            "payload_size is heavy-tailed: median a few hundred bytes, rare outliers up "
            "to several MB."
        )

        arrival_line = _arrival_target_line()

        def _build_prompt(n: int) -> str:
            return f"""Session (every flow MUST match this):
- Active QFIs: {ctx.active_qfis} (use only these; pdu_type 0, ppi 0)
- outer_dscp: {ctx.dscp_marking}
- RQI=1 allowed only for QFIs {ctx.reflective_qos_enabled_qfis} (else rqi 0)

QoS grounding (TS 23.501):
{qfi_5qi_reference}

Produce {n} benign downlink web-browsing FLOWS. Each flow is one TCP connection.
You set three numbers; the generator turns them into wire packets:
- payload_size (int bytes): total downlink bytes. THIS distribution is scored.
- inter_arrival_ms (float): gap since the previous flow STARTED, in MILLISECONDS
  (flows are seconds apart, so this is thousands of ms — see target below). Also scored.
- request_bytes (int): the uplink request that triggered the download.

{shape_line}
{arrival_line}
HALF of all flows are under ~900 B, and many are TINY — 50 to 500 bytes, single
small packets (keepalives, ACKs, small responses). The same small sizes recur
constantly: real traffic is highly repetitive at the small end, so reusing small
values is correct and expected. Only a minority reach tens or hundreds of KB, and
rarely one runs to MB scale. Do NOT round every flow up into the KB range — emit
many sub-500-byte flows. The examples are a representative sample (mostly small,
as the real traffic is), not a ceiling:
{few_shot_block}

Return ONLY JSON {{"flows": [ ... {n} objects ... ]}}, each object:
{{"extension_headers": [{{"type": 133, "pdu_type": 0, "qfi": <int>, "rqi": <int>, "ppi": 0}}],
  "outer_dscp": {ctx.dscp_marking}, "payload_size": <int>, "inter_arrival_ms": <float>,
  "request_bytes": <int>}}
No markdown; payload_size, inter_arrival_ms and request_bytes must be real numbers.
"""

        current_batch_size = batch_size

        for attempt in range(1, max_retries + 1):
            requested_max_tokens = self.max_output_tokens or max(2000, current_batch_size * 150)
            prompt = _build_prompt(current_batch_size)
            response = self.generate(prompt, system, max_tokens=requested_max_tokens)
            truncated = (self.last_finish_reason == "length")
            parsed = self._parse_json_response(response)
            raw_packets = None
            if isinstance(parsed, dict):
                raw_packets = parsed.get("flows") or parsed.get("packets")
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
                current_batch_size = max(1, current_batch_size // 2)
                print(f"[WARN] Response was truncated (finish_reason=length) — retrying with a smaller batch_size={current_batch_size}.")

        print(f"[ERROR] Failed to generate a benign packet batch after {max_retries} attempts.")
        return []

