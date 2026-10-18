#!/usr/bin/env python3
"""Goodness-of-fit figures: generated benign/attack streams vs real 5G-NIDD.

benign.png : per-flow payload shape + flow inter-arrival ECDFs (log x) against the
             real reference, one line per run, KS D in the legend.
attack.png : schema-valid attack rate per run + the measured detection gap.

Labels come from each telemetry's own generation_mode/model_name. With no
arguments it plots the latest benign run.

Usage:
    ./upfvenv/bin/python plot_gof.py [TELEMETRY.json ...] [--attack TEL.json ...]
"""
from __future__ import annotations
import argparse, glob, json, os, sys

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import reference_models as ref

REF_C = "#24272C"
RUN_C = ["#F07C00", "#C0392B", "#1E874B", "#2E5FA3", "#7B4BA3"]
GRAY, RED, GREEN = "#9C9E9F", "#C0392B", "#1E874B"
plt.rcParams.update({"axes.grid": True, "grid.color": "#E6E4DF", "axes.axisbelow": True})


def load_observed(path):
    """Per-flow downlink payload (bytes) and flow inter-arrival (ms) from telemetry.

    A flow spans consecutive `is_flow_start` records; only DL records add payload
    (the uplink request opens the flow but is not part of the DL reference)."""
    d = json.load(open(path))
    recs = d.get("packet_records")
    if not recs:
        sys.exit(f"[ERROR] {path} has no 'packet_records'.")
    payloads, iats, cur = [], [], 0.0
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
    return np.array(payloads, float), np.array(iats, float), d


def ks_2samp(a, b):
    a, b = np.sort(a), np.sort(b)
    allx = np.concatenate([a, b])
    return float(np.max(np.abs(np.searchsorted(a, allx, "right") / a.size
                               - np.searchsorted(b, allx, "right") / b.size)))


def ks_crit(n, m, alpha=0.05):
    """Critical KS D at alpha: differences below this are sampling noise."""
    return np.sqrt(-np.log(alpha / 2) / 2) * np.sqrt((n + m) / (n * m))


def ecdf(x):
    xs = np.sort(x)
    return xs, np.arange(1, xs.size + 1) / xs.size


def label_of(meta, path, seen):
    """Run name from its own telemetry; same-model runs get their timestamp back."""
    name = ("sampled (floor)" if meta.get("generation_mode") == "sampled"
            else meta.get("model_name") or os.path.basename(path)[:18])
    if name in seen:
        name = f"{name}\n{''.join(c for c in os.path.basename(path) if c.isdigit())[-6:]}"
    seen.add(name)
    return name


def benign_fig(paths, outdir, n_ref=30000, seed=0):
    rng = np.random.default_rng(seed)
    pay_ref = ref.reference_flow_payload_bytes(n_ref, rng)
    iat_ref = ref.reference_flow_interarrival_ms(n_ref, rng)
    pay_ref_n = pay_ref / pay_ref.mean()

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13.5, 5.2))
    for ax, x, lab in ((ax1, pay_ref_n, "real 5G-NIDD"), (ax2, iat_ref, "real 5G-NIDD")):
        xr, yr = ecdf(x)
        ax.plot(xr, yr, color=REF_C, lw=2.4, ls=(0, (5, 2)), label=lab, zorder=5)

    rows, seen = [], set()
    for i, path in enumerate(paths):
        pay, iat, meta = load_observed(path)
        if pay.size < 5:
            print(f"[skip] {path}: {pay.size} flows")
            continue
        col = RUN_C[i % len(RUN_C)]
        pay_n = pay / pay.mean()
        dp, di = ks_2samp(pay_n, pay_ref_n), ks_2samp(iat, iat_ref)
        name = label_of(meta, path, seen)
        for ax, x, d in ((ax1, pay_n, dp), (ax2, iat, di)):
            xo, yo = ecdf(x)
            ax.plot(xo, yo, color=col, lw=2.2, label=f"{name}   D={d:.3f}")
        rows.append({"name": name, "n": pay.size, "d_pay": dp, "d_iat": di,
                     "cv": float(pay.std() / pay.mean()), "mean": float(pay.mean()),
                     "p99": float(np.quantile(pay, 0.99)),
                     "crit": ks_crit(pay.size, n_ref)})

    r_cv = float(pay_ref.std() / pay_ref.mean())
    ax1.set_xlabel("per-flow payload / its own mean  (shape only, log scale)")
    ax1.set_title(f"Per-flow payload SHAPE vs real 5G-NIDD (reference CV={r_cv:.1f})",
                  fontsize=12, fontweight="bold")
    ax2.set_xlabel("flow inter-arrival (ms, log scale, absolute)")
    ax2.set_title("Flow inter-arrival vs real 5G-NIDD", fontsize=12, fontweight="bold")
    for ax in (ax1, ax2):
        ax.set_xscale("log")
        ax.set_ylabel("cumulative fraction of flows")
        ax.set_ylim(0, 1.02)
        ax.legend(loc="upper left", fontsize=9).set_title("KS D: lower = closer",
                                                          prop={"size": 8})
    fig.suptitle("Benign realism vs real 5G traffic (lower KS D is better)",
                 fontsize=14, fontweight="bold")
    fig.tight_layout(rect=[0, 0, 1, 0.96])
    out = os.path.join(outdir, "benign.png")
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return out, rows, r_cv


def attack_fig(paths, outdir):
    rows, seen = [], set()
    for path in paths:
        d = json.load(open(path))
        m = d.get("attack_mutations", [])
        if not m:
            print(f"[skip] {path}: no attack_mutations")
            continue
        gap_path = path.replace("_telemetry.json", "_detection_gap.json")
        gap = json.load(open(gap_path)) if os.path.exists(gap_path) else None
        rows.append({
            "name": label_of(d, path, seen),
            "total": len(m),
            "valid": sum(1 for x in m if x.get("raw_schema_valid")),
            "struct": gap and gap["structural_ids"]["attack_detection_rate"],
            "sem": gap and gap["semantic_ids"]["attack_detection_rate"],
            "gap_src": os.path.basename(gap_path) if gap else None,
        })
    if not rows:
        return None, rows

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13.5, 5.2))
    rates = [100 * r["valid"] / r["total"] for r in rows]
    bars = ax1.bar([r["name"] for r in rows], rates,
                   color=[RUN_C[i % len(RUN_C)] for i in range(len(rows))], width=.6, zorder=3)
    for b, rt, r in zip(bars, rates, rows):
        ax1.text(b.get_x() + b.get_width() / 2, rt + 2, f"{rt:.0f}%\n{r['valid']}/{r['total']}",
                 ha="center", va="bottom", fontweight="bold")
    ax1.set_ylim(0, 115)
    ax1.set_ylabel("schema-valid attack packets (%)")
    ax1.set_title("Can it produce valid attack packets?", fontsize=12, fontweight="bold")
    ax1.xaxis.grid(False)

    measured = [r for r in rows if r["struct"] is not None]
    if measured:
        r = measured[0]
        vals = [100 * r["struct"], 100 * r["sem"]]
        b2 = ax2.bar(["structural\ndetector", "semantic\ndetector"], vals,
                     color=[RED, GREEN], width=.55, zorder=3)
        for b, v in zip(b2, vals):
            ax2.text(b.get_x() + b.get_width() / 2, v + 2, f"{v:.0f}%", ha="center",
                     va="bottom", fontsize=13, fontweight="bold")
        ax2.set_title(f"Detection gap — measured on {r['name']}", fontsize=12, fontweight="bold")
    else:
        ax2.text(.5, .5, "no *_detection_gap.json\nrun detection_gap_report.py", ha="center",
                 va="center", color=GRAY, transform=ax2.transAxes)
        ax2.set_title("Detection gap (not measured)", fontsize=12, fontweight="bold")
    ax2.set_ylim(0, 115)
    ax2.set_ylabel("attack packets caught (%)")
    ax2.xaxis.grid(False)

    fig.suptitle("Attack generation quality and the detection gap",
                 fontsize=14, fontweight="bold")
    fig.tight_layout(rect=[0, 0, 1, 0.96])
    out = os.path.join(outdir, "attack.png")
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return out, rows


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("telemetry", nargs="*", help="benign telemetry JSONs (default: latest)")
    ap.add_argument("--attack", nargs="*", default=[], help="attack telemetry JSONs")
    ap.add_argument("--outdir", default="gof_plots")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    paths = args.telemetry
    if not paths:
        cands = sorted(glob.glob("pcap_files/web_browsing_benign_*_telemetry.json"))
        if not cands:
            sys.exit("[ERROR] No benign telemetry found; pass a path explicitly.")
        paths = [cands[-1]]
    os.makedirs(args.outdir, exist_ok=True)

    out, rows, r_cv = benign_fig(paths, args.outdir, seed=args.seed)
    print(f"\n=== BENIGN (reference: real 5G-NIDD, CV={r_cv:.2f}) ===")
    print(f"  {'run':22} {'flows':>6} {'D_pay':>7} {'D_iat':>7} {'D_crit':>7} "
          f"{'CV':>6} {'mean B':>10} {'p99 B':>10}")
    for r in rows:
        print(f"  {r['name'].replace(chr(10), ' '):22} {r['n']:>6} {r['d_pay']:>7.3f} {r['d_iat']:>7.3f} "
              f"{r['crit']:>7.3f} {r['cv']:>6.2f} {r['mean']:>10,.0f} {r['p99']:>10,.0f}")
    print(f"  saved: {out}")
    print("  D_crit = KS critical value at alpha=0.05; D below it is sampling noise.")
    print("  D_pay is SHAPE only (each run normalised by its own mean) — CV/p99 columns")
    print("  carry the heavy tail, which KS underweights; read them together, not D alone.")

    if args.attack:
        out, rows = attack_fig(args.attack, args.outdir)
        print("\n=== ATTACK ===")
        for r in rows:
            gap = (f"struct {100*r['struct']:.0f}% / sem {100*r['sem']:.0f}%"
                   if r["struct"] is not None else "no detection_gap.json")
            print(f"  {r['name'].replace(chr(10), ' '):22} schema-valid {r['valid']}/{r['total']}   {gap}")
        if out:
            print(f"  saved: {out}")


if __name__ == "__main__":
    main()
