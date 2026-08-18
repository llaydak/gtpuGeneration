"""Reference distributions for goodness-of-fit evaluation of the benign 5QI-6
baseline.

TS 23.501 grounds the generator's QoS semantics but defines no traffic
distribution, so realism is measured against real 5G data instead.

PAYLOAD (measured): per-flow downlink bytes from 5G-NIDD: real 5G RF network, real mobile devices, published as
Argus flow records. The generator opens one TCP connection per arrival, so flow
is the like-for-like unit: no reconstruction, no segmentation parameter.
Built by extract_5gnidd_reference.py. Fallback if absent: the 3GPP TR 36.814
HTTP page model (LTE-era, parametric) — heavy-tailed but older and not 5G.

This array is the SCORE, never the source: the LLM produces payload_size, and
KS D against this measures how close it got.

FEW-SHOT EXAMPLES (measured): sample_example_flows() hands the LLM a fresh draw
of real flows — downlink payload total and uplink request size — from the same
5G-NIDD flow records (extract_5gnidd_reference.py). These go into the PROMPT, not into
generation: they teach the flow-size distribution the model must reproduce. The
mechanical split of each flow into wire packets is the generator's own rule, not
the model's and not a copy of these examples. Redrawn per batch so no example
set becomes a ceiling.

ARRIVALS (assumed): exponential at ARRIVAL_MEAN_MS. The last non-measured
parameter here; replaceable with flow arrival gaps measured from the same
dataset. TR 36.814's 30 s reading time is human think-time between page loads —
a different regime — and is deliberately not used.
"""

from __future__ import annotations

import os
import numpy as np

ARRIVAL_MEAN_MS = 100.0

_HERE = os.path.dirname(os.path.abspath(__file__))
EMPIRICAL_5GNIDD_NPZ = os.path.join(_HERE, "reference_data",
                                    "5gnidd_benign_tcp_flows.npz")

HTTP_3GPP_TR36814 = {
    "main_object": {"mu": 8.35, "sigma": 1.37, "min": 100, "max": 2_000_000},
    "embedded_object": {"mu": 6.17, "sigma": 2.36, "min": 50, "max": 2_000_000},
    "embedded_count": {"alpha": 1.1, "k": 2, "m": 55},
}

_cache: dict = {}


def load_5gnidd() -> dict | None:
    """Real 5G-NIDD benign TCP flow measurements, or None if not extracted yet.

    Keys: bytes, pkts, dur (aligned per flow, sorted by bytes), ttl, req_bytes.
    """
    if "npz" not in _cache:
        _cache["npz"] = (dict(np.load(EMPIRICAL_5GNIDD_NPZ))
                         if os.path.exists(EMPIRICAL_5GNIDD_NPZ) else None)
    return _cache["npz"]


def load_5gnidd_flow_bytes() -> np.ndarray | None:
    """Per-flow downlink payloads (bytes) — the GoF reference."""
    d = load_5gnidd()
    return d["bytes"].astype(float) if d is not None else None


def sample_example_flows(n: int, rng) -> list[dict] | None:
    """`n` real (total_bytes, request_bytes) pairs, shown to the LLM as few-shot
    examples. None if the flow reference has not been extracted.

    Drawn REPRESENTATIVELY (a uniform draw over flows, so the mix is mostly-small
    like the real distribution) rather than stratified across the size range: a
    stratified draw over-showed large flows and pushed the model's median ~16x
    too high. The heavy tail is communicated separately by flow_size_percentiles()
    in the prompt, so a mostly-small example set does not hide it. Drawn from the
    same reference the fit is scored against, so the exact-match rate is the
    guard that says whether the model learned the shape or copied the numbers.
    REDRAWN ON EVERY CALL so no fixed set can be memorised or act as a ceiling.
    """
    d = load_5gnidd()
    if d is None:
        return None
    b, req = d["bytes"], d["req_bytes"]
    return [{"total_bytes": int(b[rng.integers(0, b.size)]),
             "request_bytes": int(req[rng.integers(0, req.size)])}
            for _ in range(n)]


def flow_size_percentiles() -> dict | None:
    """Percentiles of the real per-flow downlink payload, for the prompt's target
    spec (the shape the model must reproduce). None if the reference is absent."""
    b = load_5gnidd_flow_bytes()
    if b is None:
        return None
    return {"p50": int(np.median(b)), "p90": int(np.quantile(b, 0.9)),
            "p99": int(np.quantile(b, 0.99)), "max": int(b.max())}


def _trunc_lognormal(n, mu, sigma, lo, hi, rng):
    out = np.empty(n, dtype=float)
    filled = 0
    while filled < n:
        x = np.exp(rng.normal(mu, sigma, size=(n - filled) * 2 + 8))
        x = x[(x >= lo) & (x <= hi)]
        take = min(len(x), n - filled)
        out[filled:filled + take] = x[:take]
        filled += take
    return out


def _trunc_pareto(n, alpha, k, m, rng):
    u = rng.random(n)
    return np.minimum(k / (1.0 - u * (1.0 - (k / m) ** alpha)) ** (1.0 / alpha), m)


def sample_web_page_bytes(n, rng):
    """TR 36.814 page size: main object + Pareto-count embedded objects."""
    p = HTTP_3GPP_TR36814
    mo, eo, ec = p["main_object"], p["embedded_object"], p["embedded_count"]
    main = _trunc_lognormal(n, mo["mu"], mo["sigma"], mo["min"], mo["max"], rng)
    counts = np.clip(np.rint(_trunc_pareto(n, ec["alpha"], ec["k"], ec["m"], rng)).astype(int), 0, None)
    emb = _trunc_lognormal(int(counts.sum()), eo["mu"], eo["sigma"], eo["min"], eo["max"], rng)
    emb_sum = np.bincount(np.repeat(np.arange(n), counts), weights=emb, minlength=n)
    return main + emb_sum


def reference_flow_payload_bytes(n, rng, source="5gnidd", target_mean_bytes=None):
    """Reference per-flow downlink payload (bytes).

    source="5gnidd"  -> bootstrap real 5G-NIDD benign TCP flows (falls back to
                        tr36814 if the array is missing).
    source="tr36814" -> parametric 3GPP HTTP page model.

    target_mean_bytes rescales by a single factor (shape/CV/tail preserved,
    location shifted) for a pure shape comparison. Native scale if None.
    """
    pool = load_5gnidd_flow_bytes() if source == "5gnidd" else None
    x = rng.choice(pool, size=n, replace=True) if pool is not None else sample_web_page_bytes(n, rng)
    if target_mean_bytes is not None and x.mean() > 0:
        x = x * (target_mean_bytes / x.mean())
    return x


def reference_flow_interarrival_ms(n, rng, mean_ms=ARRIVAL_MEAN_MS):
    """Reference flow inter-arrival: exponential (Poisson). See module docstring."""
    return rng.exponential(mean_ms, size=n)


def describe(x) -> dict:
    x = np.asarray(x, dtype=float)
    mean, std = float(x.mean()), float(x.std())
    return {"n": int(x.size), "mean": mean, "std": std,
            "cv": (std / mean) if mean else float("nan"),
            "min": float(x.min()), "p50": float(np.median(x)),
            "p90": float(np.quantile(x, 0.90)), "p99": float(np.quantile(x, 0.99)),
            "max": float(x.max()),
            "skew": float(((x - mean) ** 3).mean() / std ** 3) if std else float("nan")}


def _show(title, x):
    print(f"\n{title}")
    for k, v in describe(x).items():
        print(f"  {k:5}: {v:,.2f}" if isinstance(v, float) else f"  {k:5}: {v}")


if __name__ == "__main__":
    rng = np.random.default_rng(0)
    pool = load_5gnidd_flow_bytes()
    if pool is None:
        print("[missing] run extract_5gnidd_reference.py first.")
    else:
        _show("PAYLOAD — 5G-NIDD benign TCP downlink flows (real 5G, measured):", pool)
        print("\nFEW-SHOT EXAMPLES — one draw of real flows shown to the LLM:")
        ex = sample_example_flows(6, rng)
        if ex is None:
            print("  [missing] run extract_5gnidd_shapes.py for few-shot examples.")
        else:
            for e in ex:
                print(f"  payload {e['total_bytes']:>9,} B   request {e['request_bytes']:>7,} B")
    _show("PAYLOAD fallback — 3GPP TR 36.814 HTTP page model (LTE-era):",
          sample_web_page_bytes(50_000, rng))
    _show(f"ARRIVAL — Exp({ARRIVAL_MEAN_MS:g} ms, assumed):",
          reference_flow_interarrival_ms(50_000, rng))
