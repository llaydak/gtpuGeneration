"""Estimate LLM token cost for a long benign/attack generation run BEFORE
committing to it, so a long-duration run doesn't burn tokens blindly.

Cost is dominated by COMPLETION tokens, which scale with the number of LLM
"arrivals" generated. The number of arrivals for a given simulated duration
depends on the average burst inter-arrival time the model itself produces —
which cannot be known a priori. So the accurate path is:

  1. Run ONE cheap calibration batch (a single LLM call), e.g.:
         ./upfvenv/bin/python generate_llm_pcap.py \
             --backend openai --model gpt-5.6-luna \
             --llm-batch-size 40 --max-packets 40
     This makes exactly one API call (~1.4k prompt + ~40x completion tokens)
     and writes a telemetry JSON with real token counts and the model's
     avg burst inter-arrival time.

  2. Extrapolate from it to your target duration:
         ./upfvenv/bin/python estimate_cost.py \
             --from-telemetry pcap_files/web_browsing_benign_*_telemetry.json \
             --target-minutes 15 --price-in 5 --price-out 15

Pricing (--price-in / --price-out, US$ per 1M tokens) is model-specific and
must be supplied for gpt-5.6-luna — this script does not assume a rate. Omit
them to get a token estimate only.
"""

from __future__ import annotations

import argparse
import glob
import json
import math
from typing import Optional

# Measured fixed prompt sizes (tiktoken cl100k_base; real tokenizer may differ
# ~10%). Used only in a-priori mode when no calibration telemetry is given.
PROMPT_TOKENS_BENIGN_CALL = 1400
PROMPT_TOKENS_ATTACK_PKT_DL = 1442
PROMPT_TOKENS_ATTACK_PKT_UL = 873
DEFAULT_COMPLETION_TOKENS_PER_ARRIVAL = 200   # code's own ~150-250 estimate
DEFAULT_ATTACK_COMPLETION_TOKENS_PER_PKT = 110


def _fmt_cost(tokens_in: int, tokens_out: int, price_in: Optional[float],
              price_out: Optional[float]) -> str:
    if price_in is None or price_out is None:
        return "  (supply --price-in / --price-out $/1M to see $ cost)"
    cost = tokens_in / 1e6 * price_in + tokens_out / 1e6 * price_out
    return f"  estimated cost: ${cost:,.2f}  (in ${tokens_in/1e6*price_in:,.2f} + out ${tokens_out/1e6*price_out:,.2f})"


def estimate_from_telemetry(path: str, target_minutes: float, batch_size: int,
                            price_in: Optional[float], price_out: Optional[float]) -> None:
    with open(path) as f:
        tel = json.load(f)

    sim_sec = tel.get("simulated_duration_seconds") or 0
    usage = tel.get("llm_usage", {})
    calib_prompt = usage.get("total_prompt_tokens", 0)
    calib_completion = usage.get("total_completion_tokens", 0)
    calib_calls = usage.get("api_call_count", 0)
    arrivals_used = usage.get("llm_arrivals_used") or tel.get("packet_count", 0)
    arrivals_generated = usage.get("llm_arrivals_count", arrivals_used)
    avg_iat_ms = tel.get("avg_burst_inter_arrival_ms") or 0

    if sim_sec <= 0 or arrivals_generated <= 0:
        raise SystemExit("Calibration telemetry has no usable duration/arrival counts.")

    completion_per_arrival = calib_completion / arrivals_generated
    arrivals_per_sec = arrivals_used / sim_sec if sim_sec else 0

    target_sec = target_minutes * 60.0
    proj_arrivals = arrivals_per_sec * target_sec
    proj_calls = math.ceil(proj_arrivals / batch_size) if batch_size else 0
    proj_completion = proj_arrivals * completion_per_arrival
    # Prompt tokens scale with number of calls, not arrivals; measure per-call
    # prompt from the calibration run itself.
    prompt_per_call = (calib_prompt / calib_calls) if calib_calls else PROMPT_TOKENS_BENIGN_CALL
    proj_prompt = proj_calls * prompt_per_call
    total = proj_prompt + proj_completion

    print("=" * 72)
    print(" COST ESTIMATE — extrapolated from a real calibration run")
    print("=" * 72)
    print(f" Calibration file        : {path}")
    print(f"   sim duration          : {sim_sec:.1f} s over {arrivals_used} arrivals "
          f"({calib_calls} call(s))")
    print(f"   avg burst inter-arrival: {avg_iat_ms:.1f} ms  -> {arrivals_per_sec:.2f} arrivals/s")
    print(f"   completion tokens/arr  : {completion_per_arrival:.1f}")
    print(f"   prompt tokens/call     : {prompt_per_call:.0f}")
    print("-" * 72)
    print(f" TARGET                   : {target_minutes:.1f} min  (batch_size={batch_size})")
    print(f"   projected arrivals     : {proj_arrivals:,.0f}")
    print(f"   projected API calls    : {proj_calls:,}")
    print(f"   prompt tokens          : {proj_prompt:,.0f}")
    print(f"   completion tokens      : {proj_completion:,.0f}")
    print(f"   TOTAL tokens           : {total:,.0f}")
    print(_fmt_cost(int(proj_prompt), int(proj_completion), price_in, price_out))
    print("=" * 72)
    print(" Note: linear extrapolation assumes the model keeps the same avg")
    print(" inter-arrival time and per-packet verbosity at longer durations.")


def estimate_apriori(target_minutes: float, avg_iat_ms: float, batch_size: int,
                     completion_per_arrival: float, price_in: Optional[float],
                     price_out: Optional[float]) -> None:
    target_sec = target_minutes * 60.0
    arrivals_per_sec = 1000.0 / avg_iat_ms
    proj_arrivals = arrivals_per_sec * target_sec
    proj_calls = math.ceil(proj_arrivals / batch_size)
    proj_completion = proj_arrivals * completion_per_arrival
    proj_prompt = proj_calls * PROMPT_TOKENS_BENIGN_CALL
    total = proj_prompt + proj_completion

    print("=" * 72)
    print(" COST ESTIMATE — a-priori (ASSUMPTIONS, not measured)")
    print("=" * 72)
    print(f" assumed avg inter-arrival : {avg_iat_ms:.1f} ms -> {arrivals_per_sec:.2f} arrivals/s")
    print(f" assumed completion/arrival: {completion_per_arrival:.0f} tokens")
    print(f" TARGET                    : {target_minutes:.1f} min (batch_size={batch_size})")
    print(f"   projected arrivals      : {proj_arrivals:,.0f}")
    print(f"   projected API calls     : {proj_calls:,}")
    print(f"   prompt tokens           : {proj_prompt:,.0f}")
    print(f"   completion tokens       : {proj_completion:,.0f}")
    print(f"   TOTAL tokens            : {total:,.0f}")
    print(_fmt_cost(int(proj_prompt), int(proj_completion), price_in, price_out))
    print("=" * 72)
    print(" WARNING: avg inter-arrival is the dominant unknown. Run a real")
    print(" calibration batch and use --from-telemetry for an accurate figure.")


def main() -> None:
    ap = argparse.ArgumentParser(description="Estimate LLM token cost for a benign/attack generation run.")
    ap.add_argument("--from-telemetry", default=None,
                    help="A calibration run's telemetry JSON (glob ok) to extrapolate from. Most accurate.")
    ap.add_argument("--target-minutes", type=float, required=True, help="Target simulated duration to price.")
    ap.add_argument("--batch-size", type=int, default=200, help="--llm-batch-size for the target run (default 200).")
    ap.add_argument("--avg-iat-ms", type=float, default=100.0,
                    help="A-priori only: assumed avg burst inter-arrival (ms). Ignored with --from-telemetry.")
    ap.add_argument("--completion-per-arrival", type=float, default=DEFAULT_COMPLETION_TOKENS_PER_ARRIVAL,
                    help="A-priori only: assumed completion tokens per arrival.")
    ap.add_argument("--price-in", type=float, default=None, help="US$ per 1M prompt tokens (model-specific).")
    ap.add_argument("--price-out", type=float, default=None, help="US$ per 1M completion tokens (model-specific).")
    args = ap.parse_args()

    if args.from_telemetry:
        matches = sorted(glob.glob(args.from_telemetry))
        if not matches:
            raise SystemExit(f"No telemetry file matched: {args.from_telemetry}")
        estimate_from_telemetry(matches[-1], args.target_minutes, args.batch_size,
                                args.price_in, args.price_out)
    else:
        estimate_apriori(args.target_minutes, args.avg_iat_ms, args.batch_size,
                         args.completion_per_arrival, args.price_in, args.price_out)


if __name__ == "__main__":
    main()
