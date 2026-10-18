"""Reference distributions for goodness-of-fit evaluation of the benign 5QI-6
baseline.

Two-layer division of labor: the LLM chooses the flow scalars (payload_size,
request_bytes, inter_arrival_ms, QoS markings); the PACKETIZER (generate_llm_pcap.py)
mechanically renders each flow into wire packets. 

TS 23.501 grounds the LLM's QoS semantics but defines no traffic distribution, so
realism is measured against real 5G data instead.

PAYLOAD (measured): per-flow downlink bytes from 5G-NIDD: real 5G RF network, real mobile devices, published as
Argus flow records. The packetizer opens one TCP connection per arrival, so flow
is the like-for-like unit: no reconstruction, no segmentation parameter.

This array is the SCORE, never the source: the LLM produces payload_size, and
KS D against this measures how close it got.

FEW-SHOT EXAMPLES (measured): sample_example_flows() hands the LLM a fresh draw
of real flows — downlink payload total and uplink request size — from the same
5G-NIDD flow records. These go into the PROMPT, not into
generation: they teach the flow-size distribution the LLM must reproduce. The
mechanical split of each flow into wire packets is the packetizer's own rule, not
the LLM's and not a copy of these examples. Redrawn per batch so no example
set becomes a ceiling.

ARRIVALS (measured): per-device (one SrcAddr = one UE) flow inter-arrival gaps
from 5G-NIDD StartTime, bootstrapped. One PDU session models one UE, so the
single-device arrival process is the like-for-like unit, not the whole-BS
aggregate. Real median ~5 s (mean ~77 s, heavy-tailed) = ~2-3 flows/min, in the
real-BS range; the old Exp(100 ms) assumption implied ~600 flows/min (~70x too
fast), which is why the reference is the measured array, not a parametric model.
"""

from __future__ import annotations

import os
import numpy as np

_HERE = os.path.dirname(os.path.abspath(__file__))
EMPIRICAL_5GNIDD_NPZ = os.path.join(_HERE, "reference_data",
                                    "5gnidd_benign_tcp_flows.npz")

_cache: dict = {}

def load_5gnidd() -> dict | None:
    if "npz" not in _cache:
        _cache["npz"] = (dict(np.load(EMPIRICAL_5GNIDD_NPZ))
                         if os.path.exists(EMPIRICAL_5GNIDD_NPZ) else None)
    return _cache["npz"]


def load_5gnidd_flow_bytes() -> np.ndarray | None:
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


def reference_flow_payload_bytes(n, rng): 
    """Bootstrap n real 5G-NIDD benign TCP per-flow downlink payloads (bytes).

    The whole project scores against real 5G, so there is no parametric fallback:
    a missing reference is an error, not a silent substitution. Returns native
    scale; a shape-only comparison normalizes both sides at the call site
    (plot_gof), which is symmetric rather than rescaling this reference.
    """
    pool = load_5gnidd_flow_bytes()
    if pool is None:
        raise FileNotFoundError(
            f"5G-NIDD reference not found ({EMPIRICAL_5GNIDD_NPZ}); "
            "run extract_5gnidd_reference.py first.")
    return rng.choice(pool, size=n, replace=True)


def load_5gnidd_arrival_gaps_ms() -> np.ndarray | None:
    d = load_5gnidd()
    if d is None or "arrival_gaps_ms" not in d:
        return None
    g = d["arrival_gaps_ms"].astype(float)
    return g if g.size else None


def sample_benign_flow_scalars(n, rng) -> dict | None:
    d = load_5gnidd()
    g = load_5gnidd_arrival_gaps_ms()
    if d is None or g is None:
        return None
    b, req = d["bytes"], d["req_bytes"]
    return {"payload": b[rng.integers(0, b.size, size=n)].astype(int),
            "request": req[rng.integers(0, req.size, size=n)].astype(int),
            "iat_ms": g[rng.integers(0, g.size, size=n)].astype(float)}


def arrival_gap_percentiles() -> dict | None:
    """Percentiles of the real per-device flow inter-arrival (ms), for the
    prompt's arrival target. None if the reference is absent."""
    g = load_5gnidd_arrival_gaps_ms()
    if g is None:
        return None
    return {"p50": int(np.median(g)), "p90": int(np.quantile(g, 0.9)),
            "p99": int(np.quantile(g, 0.99)), "mean": int(g.mean())}


def reference_flow_interarrival_ms(n, rng):
    g = load_5gnidd_arrival_gaps_ms()
    if g is None:
        raise FileNotFoundError(
            f"5G-NIDD arrival gaps not found ({EMPIRICAL_5GNIDD_NPZ}); "
            "run extract_5gnidd_reference.py first.")
    return rng.choice(g, size=n, replace=True)


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
            print("  [missing] run extract_5gnidd_reference.py for few-shot examples.")
        else:
            for e in ex:
                print(f"  payload {e['total_bytes']:>9,} B   request {e['request_bytes']:>7,} B")
    _show("ARRIVAL — real 5G-NIDD per-device flow inter-arrivals (ms):",
          reference_flow_interarrival_ms(50_000, rng))
