#!/usr/bin/env python3
"""Goodness-of-fit visualization for the generated benign 5QI-6 baseline.

Compares per-flow payload and flow inter-arrival of the generated stream against
the references in `reference_models.py`, as density + ECDF overlays plus a
two-sample Kolmogorov-Smirnov D so improvement is a number, not an eyeball.

The generator opens one TCP connection per arrival, so flow is the like-for-like
unit against 5G-NIDD's Argus flow records.

By default the payload reference is rescaled (shape-preserving) to the observed
mean, making KS D a pure *shape* comparison; the native scale is printed too, so
the absolute operating-point difference stays visible. --native-scale and
--reference-mean override this.

Usage:
    ./upfvenv/bin/python plot_reference_fit.py [TELEMETRY.json] [options]

With no path it picks the most recent pcap_files/web_browsing_benign_*_telemetry.json.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys

import matplotlib
matplotlib.use("Agg")  # headless; save PNGs
import matplotlib.pyplot as plt
import numpy as np

import reference_models as ref


# --- observed reconstruction -------------------------------------------------
def load_observed(path: str):
    """Per-flow DOWNLINK payloads (bytes) and flow inter-arrivals (ms) from a
    telemetry JSON's packet_records.

    One flow spans the records between consecutive `is_flow_start` markers (each
    flow is its own TCP connection). The reference is the downlink payload
    distribution, so only `direction == "DL"` records are summed — the uplink
    request packets that open each flow are excluded from the payload total but
    still mark the flow's arrival (their gap is the inter-arrival). Records
    without a direction (older telemetry) are treated as downlink.
    """
    with open(path) as f:
        d = json.load(f)
    recs = d.get("packet_records")
    if not recs:
        sys.exit(f"[ERROR] {path} has no 'packet_records'.")

    payloads, iats = [], []
    cur = 0.0
    for r in recs:
        if r.get("is_flow_start"):
            if cur > 0:
                payloads.append(cur)
            cur = 0.0
            if r.get("inter_arrival_ms") is not None:
                iats.append(float(r["inter_arrival_ms"]))
        if r.get("direction", "DL") != "UL":
            cur += float(r.get("payload_size_bytes", 0) or 0)
    if cur > 0:
        payloads.append(cur)
    return np.array(payloads, dtype=float), np.array(iats, dtype=float), d


# --- two-sample Kolmogorov-Smirnov (numpy; no scipy needed) ------------------
def ks_2samp(a: np.ndarray, b: np.ndarray):
    """Two-sample KS statistic D and asymptotic p-value (Numerical Recipes Q_KS)."""
    a = np.sort(a)
    b = np.sort(b)
    allx = np.concatenate([a, b])
    cdf_a = np.searchsorted(a, allx, side="right") / a.size
    cdf_b = np.searchsorted(b, allx, side="right") / b.size
    d = float(np.max(np.abs(cdf_a - cdf_b)))
    en = a.size * b.size / (a.size + b.size)
    lam = (np.sqrt(en) + 0.12 + 0.11 / np.sqrt(en)) * d
    j = np.arange(1, 101)
    p = 2.0 * np.sum(((-1.0) ** (j - 1)) * np.exp(-2.0 * lam ** 2 * j ** 2))
    return d, float(min(1.0, max(0.0, p)))


def ecdf(x: np.ndarray):
    xs = np.sort(x)
    ys = np.arange(1, xs.size + 1) / xs.size
    return xs, ys


# --- one metric = one figure (density + ECDF), like the mentor's plots -------
def plot_metric(observed, reference, title, xlabel, unit, outpath, xview=None,
                ref_label="reference model"):
    d, p = ks_2samp(observed, reference)
    o, r = ref.describe(observed), ref.describe(reference)

    if xview is None:
        xview = max(float(observed.max()), float(np.quantile(reference, 0.95)))
    bins = np.linspace(0, xview, 60)

    fig, (axd, axc) = plt.subplots(1, 2, figsize=(12, 4.2))

    axd.hist(observed, bins=bins, density=True, alpha=0.6, label="observed (generated)")
    axd.hist(reference, bins=bins, density=True, alpha=0.5, label=ref_label)
    axd.set_title(f"{title} - density")
    axd.set_xlabel(xlabel)
    axd.set_ylabel("density")
    axd.set_xlim(0, xview)
    axd.legend()

    xo, yo = ecdf(observed)
    xr, yr = ecdf(reference)
    axc.plot(xo, yo, label="observed")
    axc.plot(xr, yr, label=ref_label)
    axc.set_title(f"{title} - ECDF")
    axc.set_xlabel(xlabel)
    axc.set_ylabel("cumulative probability")
    axc.set_xlim(0, xview)
    axc.set_ylim(0, 1.02)
    axc.legend(loc="lower right")
    axc.text(0.03, 0.97,
             f"KS D = {d:.3f}\np = {p:.3g}",
             transform=axc.transAxes, ha="left", va="top",
             bbox=dict(boxstyle="round", fc="white", ec="0.7", alpha=0.9))

    fig.tight_layout()
    fig.savefig(outpath, dpi=120)
    plt.close(fig)
    return {"ks_d": d, "ks_p": p, "observed": o, "reference": r, "unit": unit,
            "title": title, "outpath": outpath}


def fmt_row(name, o, r, unit):
    return (f"  {name:26} obs mean={o['mean']:>12,.1f} CV={o['cv']:.2f} | "
            f"ref mean={r['mean']:>12,.1f} CV={r['cv']:.2f}  ({unit})")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("telemetry", nargs="?",
                    help="benign telemetry JSON (default: latest web_browsing_benign_*)")
    ap.add_argument("--reference", choices=["5gnidd", "tr36814"], default="5gnidd",
                    help="payload reference (default: 5gnidd = real 5G benign TCP "
                         "flows; tr36814 = LTE-era parametric model)")
    ap.add_argument("--reference-mean", type=float, default=None,
                    help="rescale payload reference to this mean (bytes). "
                         "Overrides the default match-observed-mean behavior.")
    ap.add_argument("--native-scale", action="store_true",
                    help="plot the payload reference at its true (unrescaled) scale, "
                         "exposing the absolute operating-point difference.")
    ap.add_argument("--iat-mean", type=float, default=ref.ARRIVAL_MEAN_MS,
                    help=f"exponential mean for the arrival reference (ms, default {ref.ARRIVAL_MEAN_MS:g})")
    ap.add_argument("--n-ref", type=int, default=20000,
                    help="reference sample size for a smooth model curve (default 20000)")
    ap.add_argument("--seed", type=int, default=0, help="RNG seed (default 0)")
    ap.add_argument("--outdir", default="gof_plots", help="output directory (default gof_plots)")
    args = ap.parse_args()

    path = args.telemetry
    if not path:
        cands = sorted(glob.glob("pcap_files/web_browsing_benign_*_telemetry.json"))
        cands = [c for c in cands if "single_call" not in c]
        if not cands:
            sys.exit("[ERROR] No benign telemetry found; pass a path explicitly.")
        path = cands[-1]

    payload_obs, iat_obs, meta = load_observed(path)
    if payload_obs.size < 5:
        sys.exit(f"[ERROR] Only {payload_obs.size} flows found in {path}; nothing to fit.")

    rng = np.random.default_rng(args.seed)
    if args.native_scale:
        tgt = None
    elif args.reference_mean is not None:
        tgt = args.reference_mean
    else:
        tgt = float(payload_obs.mean())
    payload_ref = ref.reference_flow_payload_bytes(
        args.n_ref, rng, source=args.reference, target_mean_bytes=tgt)
    iat_ref = ref.reference_flow_interarrival_ms(args.n_ref, rng, mean_ms=args.iat_mean)
    native = ref.describe(ref.reference_flow_payload_bytes(
        args.n_ref, rng, source=args.reference))

    os.makedirs(args.outdir, exist_ok=True)
    stamp = os.path.splitext(os.path.basename(path))[0]

    pay_ref_label = {"5gnidd": "reference (real 5G per-flow)",
                     "tr36814": "reference (TR 36.814, LTE)"}[args.reference]
    r_iat = plot_metric(
        iat_obs, iat_ref, "Flow inter-arrival", "inter-arrival (ms)", "ms",
        os.path.join(args.outdir, f"{stamp}_interarrival.png"),
        xview=float(np.quantile(np.concatenate([iat_obs, iat_ref]), 0.99)),
        ref_label="reference (Exp, assumed)")
    r_pay = plot_metric(
        payload_obs, payload_ref, "Per-flow payload", "bytes", "bytes",
        os.path.join(args.outdir, f"{stamp}_payload.png"),
        xview=float(max(payload_obs.max(), np.quantile(payload_ref, 0.95))),
        ref_label=pay_ref_label)

    src_label = {"5gnidd": "real 5G-NIDD benign TCP downlink flows",
                 "tr36814": "3GPP TR 36.814 HTTP model (LTE-era)"}[args.reference]
    if args.native_scale:
        scale_note = "native scale"
    elif args.reference_mean is not None:
        scale_note = f"rescaled to {args.reference_mean:,.0f} B"
    else:
        scale_note = f"rescaled to observed mean {payload_obs.mean():,.0f} B (shape comparison)"

    print(f"\nTelemetry : {path}")
    print(f"Model     : {meta.get('model_name','?')}  |  flows: {payload_obs.size}")
    print(f"Reference : payload = {src_label}, {scale_note} ; arrival = Exp(mean={args.iat_mean:g} ms)")
    print(f"Native reference scale (unrescaled): mean={native['mean']:,.0f} B CV={native['cv']:.2f}")
    print("\n--- Goodness of fit (KS D: lower = closer to reference) ---")
    for res in (r_iat, r_pay):
        print(f"\n[{res['title']}]  KS D = {res['ks_d']:.3f}  (p = {res['ks_p']:.3g})")
        print(fmt_row("observed vs reference", res["observed"], res["reference"], res["unit"]))
        print(f"  saved: {res['outpath']}")

    print("\nInterpretation: arrival should already fit well (small D). Per-flow "
          "payload D is the number to watch: the reference CV is ~4.5 (real 5G) "
          "vs the generator's ~0.18, so D stays high until the generator "
          "reproduces the heavy tail. Re-run after a generator change to track it.\n")


if __name__ == "__main__":
    main()
