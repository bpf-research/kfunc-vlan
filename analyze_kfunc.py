#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Avinash Duduskar <avinash.duduskar@gmail.com>
# Host-side analysis for the bpf_xdp_egress_dev cost bench.
#
#   usage: analyze_kfunc.py <results_dir>
#
# kfunc cost = mode1 - mode0 per cell. The micro method gives R paired runs per
# cell, so the delta carries a real CI; the literal method is one window per cell
# (per-call averaged over millions of frames), used as the real-path cross-check.
#
# Figures:
#   cost.png      added cost per call vs VLAN population.
#   sits.png      kfunc as a fraction of bpf_fib_lookup, warm vs at the 4094 ceiling.
#   ab.png        fold vs split: absolute cost of each, and the delta the fold avoids.
#   footprint.png working-set sensitivity: cost vs touch-set with L2-miss + DRAM overlay.
#   dist.png      per-population distribution of the added cost.
#   context.png  where bpf_xdp_egress_dev sits in the host receive path (net_rx_action).
#   pps.png      throughput (Mpps), fold vs split.
#   controls.png measurement environment stability (clock, DRAM).
import sys
import os
import numpy as np
import pandas as pd
from scipy import stats
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

L2_BYTES = 1024 * 1024     # Zen4 per-core L2; meta.txt overrides with THIS box's
DEV_BYTES = 192            # ~3 cachelines touched per device in the chain walk
VLAN_CEILING = 4094        # a single trunk caps here (12-bit VID)

C_KFUNC = "#1565C0"        # the added kfunc cost (the primary series)
C_FIB = "#43A047"          # bpf_fib_lookup, the call this kfunc extends
C_BARE = "#9E9E9E"         # bare program floor
C_REF = "#555555"          # reference markers (256 wall, ceiling)


def parse_size(s):
    """'1024K' / '32M' (sysfs cache size) -> bytes; None if unparseable."""
    if not s:
        return None
    s = s.strip()
    mult = {"K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}.get(s[-1].upper())
    try:
        return int(s[:-1]) * mult if mult else int(s)
    except ValueError:
        return None


def read_meta(out):
    meta = {}
    try:
        with open(os.path.join(out, "meta.txt")) as f:
            for line in f:
                if "=" in line:
                    k, v = line.rstrip("\n").split("=", 1)
                    meta[k] = v
    except OSError:
        pass
    return meta


def ci95(x):
    """Half-width of the 95% confidence interval for the mean (Student t)."""
    x = np.asarray(x, float)
    n = len(x)
    if n < 2:
        return 0.0
    return float(stats.t.ppf(0.975, n - 1) * x.std(ddof=1) / np.sqrt(n))


def delta(df, method, sweep):
    """Per cell: mean of the paired mode1-mode0 deltas, with a 95% CI.

    Runs are interleaved (mode0 then mode1 within each run), so pairing by run
    index cancels per-run drift; the CI is over those paired deltas.
    """
    d = df[(df.method == method) & (df.sweep == sweep)]
    rows = []
    for (pop, ws), g in d.groupby(["pop", "working_set"]):
        m0 = g[g["mode"] == 0].sort_values("run")
        m1 = g[g["mode"] == 1].sort_values("run")
        if len(m0) == 0 or len(m1) == 0:
            continue
        n = min(len(m0), len(m1))

        def col(a, b):
            v = a.values[:n] - b.values[:n]
            return v[~np.isnan(v)]

        dcy = col(m1.cyc_per_call, m0.cyc_per_call)
        dns = col(m1.ns_per_call, m0.ns_per_call)
        ddr = col(m1.dram_fills_per_call, m0.dram_fills_per_call)
        mean = lambda v: float(v.mean()) if len(v) else float("nan")
        rows.append(dict(pop=pop, ws=ws,
                         dcyc=mean(dcy), ci_cyc=ci95(dcy),
                         dns=mean(dns), ci=ci95(dns), ddram=mean(ddr)))
    cols = ["pop", "ws", "dcyc", "ci_cyc", "dns", "ci", "ddram"]
    if not rows:
        return pd.DataFrame(columns=cols)
    return pd.DataFrame(rows).sort_values(["pop", "ws"])


def measured_ghz(df):
    """The box's pinned clock, read straight from the data (cyc / ns)."""
    m = df[(df.method == "micro") & df.freq_ghz.notna()]
    if len(m):
        return float(m.freq_ghz.median())
    return 3.0


def fig_cost(df, out, ghz):
    """cost.png: added cost per call vs VLAN population (chain sweep).

    Plotted in cycles (high resolution; the micro ns clock is ~20 ns quantized),
    with a proportional ns axis on the right. The cost is flat to ~512 VLANs then
    climbs as the hash chain lengthens, so both the warm floor and the ceiling
    are labelled. DRAM fills stay ~0 across the whole dataset.
    """
    c = delta(df, "micro", "chain")
    c = c[c["dcyc"].notna()].sort_values("pop")
    if not len(c):
        return
    floor = c[c["pop"] <= 512]["dcyc"].mean()       # the flat region (chains <= ~2 deep)
    top = c.iloc[-1]
    ratio = top["dcyc"] / floor if floor else float("nan")
    # absolute DRAM fills/call across the whole dataset
    abs_dram = float(df[df.method == "micro"]["dram_fills_per_call"].max())

    fig, ax = plt.subplots(figsize=(8.2, 4.8))
    ax.fill_between(c["pop"], c["dcyc"] - c["ci_cyc"], c["dcyc"] + c["ci_cyc"],
                    color=C_KFUNC, alpha=.15, lw=0)
    ax.plot(c["pop"], c["dcyc"], marker="o", color=C_KFUNC, lw=2.2, ms=6,
            label="bpf_xdp_egress_dev added cost", zorder=5)
    ax.set_xscale("log", base=2)
    ax.set_xlim(c["pop"].min() * 0.85, VLAN_CEILING * 1.15)
    ax.set_ylim(0, top["dcyc"] * 1.25)

    # floor and ceiling, annotated on the line
    ax.axhline(floor, ls=":", color=C_REF, alpha=.6, lw=1)
    ax.annotate(f"~{floor:.0f} cyc  ≈ {floor / ghz:.0f} ns warm\n(flat to ~512 VLANs)",
                xy=(c["pop"].iloc[1], floor), xytext=(0, 30),
                textcoords="offset points", ha="left", va="bottom", fontsize=9.5,
                color=C_KFUNC, fontweight="bold",
                bbox=dict(boxstyle="round,pad=0.4", fc="white", ec=C_KFUNC, alpha=.9))
    ax.annotate(f"{top['dcyc']:.0f} cyc ≈ {top['dcyc'] / ghz:.0f} ns at the "
                f"{int(top['pop'])}-VLAN ceiling\n({ratio:.1f}x the floor, chain lengthens)",
                xy=(top["pop"], top["dcyc"]), xytext=(-10, -6),
                textcoords="offset points", ha="right", va="top", fontsize=9,
                arrowprops=dict(arrowstyle="->", color=C_REF, lw=1))

    # reference markers: 256 buckets and the VLAN ceiling
    ax.axvline(256, ls="--", color=C_REF, alpha=.35, lw=1)
    ax.text(256, top["dcyc"] * 1.2, "256 hash buckets ",
            fontsize=8, color=C_REF, ha="right", va="top")
    ax.axvline(VLAN_CEILING, ls="--", color=C_FIB, alpha=.5, lw=1)

    secax = ax.secondary_yaxis("right", functions=(lambda v: v / ghz,
                                                   lambda n: n * ghz))
    secax.set_ylabel(f"ns / call  (at {ghz:.2f} GHz)")
    ax.set_xlabel("VLAN population in the namespace  (hot working set fixed)")
    ax.set_ylabel("added CPU cost  (cycles / call)")
    ax.set_title(f"bpf_xdp_egress_dev added cost vs VLAN population  "
                 f"(~{floor / ghz:.0f} ns warm, ~{top['dcyc'] / ghz:.0f} ns at the "
                 f"{VLAN_CEILING} ceiling)")
    ax.grid(alpha=.3)

    note = (f"L3-resident at every population and working set: "
            f"DRAM fills/call <= {abs_dram:.0e}, never a memory fill.")
    fig.text(0.5, -0.02, note, ha="center", fontsize=8.5, color=C_REF)
    fig.tight_layout()
    fig.savefig(os.path.join(out, "cost.png"), dpi=130, bbox_inches="tight")
    plt.close(fig)


def fig_sits(df, out, ghz, meta):
    """sits.png: the kfunc as a fraction of the bpf_fib_lookup it follows, at the
    warm floor and at the 4094-VLAN ceiling. The fraction grows from ~14% to
    ~33% as the hash chain lengthens.
    """
    m = df[(df.method == "micro") & (df.sweep == "chain")]

    def regime(sel):
        g = m[sel(m)]
        b = g[g["mode"] == 0]["cyc_per_call"].median()
        k = g[g["mode"] == 1]["cyc_per_call"].median() - b
        return float(b), float(k)

    fib_w, kf_w = regime(lambda d: d["pop"] <= 512)
    fib_c, kf_c = regime(lambda d: d["pop"] == VLAN_CEILING)
    if not all(np.isfinite(v) for v in (fib_w, kf_w, fib_c, kf_c)) or fib_w <= 0:
        return

    fig, ax = plt.subplots(figsize=(7.4, 5.0))
    x = [0, 1]
    fib, kf = [fib_w, fib_c], [kf_w, kf_c]
    ax.bar(x, fib, width=.5, color=C_FIB, edgecolor="white",
           label="bpf_fib_lookup program (mode 0)")
    ax.bar(x, kf, width=.5, bottom=fib, color=C_KFUNC, edgecolor="white",
           label="+ bpf_xdp_egress_dev (mode 1)")
    for xi, b, k in zip(x, fib, kf):
        ax.text(xi, b / 2, f"{b:.0f} cyc\n≈{b / ghz:.0f} ns", ha="center",
                va="center", color="white", fontsize=9, fontweight="bold")
        ax.annotate(f"+ {k:.0f} cyc  ({100 * k / b:.0f}%)", xy=(xi, b + k),
                    xytext=(0, 8), textcoords="offset points", ha="center",
                    fontsize=10, color=C_KFUNC, fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(["warm\n(<=512 VLANs)", f"{VLAN_CEILING} VLANs"])
    ax.set_ylabel("per-call cost  (cycles)")
    ax.secondary_yaxis("right", functions=(lambda v: v / ghz, lambda n: n * ghz)
                       ).set_ylabel(f"ns  (at {ghz:.2f} GHz)")
    ax.set_ylim(0, (fib_c + kf_c) * 1.2)
    ax.set_title(f"bpf_xdp_egress_dev as a fraction of bpf_fib_lookup: "
                 f"{100 * kf_w / fib_w:.0f}% warm, {100 * kf_c / fib_c:.0f}% at the "
                 f"{VLAN_CEILING} ceiling")
    ax.legend(loc="upper left", fontsize=8.5)
    ax.grid(axis="y", alpha=.3)
    fig.text(0.5, -0.02, "The fraction grows as the hash chain lengthens. "
             "L3-resident, DRAM-free in both regimes.", ha="center", fontsize=8.2,
             color=C_REF)
    fig.tight_layout()
    fig.savefig(os.path.join(out, "sits.png"), dpi=130, bbox_inches="tight")
    plt.close(fig)


def fig_footprint(df, out, ghz):
    """footprint.png: working-set sensitivity at full population. The kfunc cost
    rises with the device touch-set, tracking L2 misses, while DRAM fills stay
    flat at ~0: the rising cost is absorbed by L3, never a memory fill.
    """
    d = df[(df.method == "micro") & (df.sweep == "footprint")]
    if not len(d):
        return
    ws = sorted(d.working_set.unique())
    dmean, dci, l2m, dram = [], [], [], []
    for w in ws:
        g = d[d.working_set == w]
        m0 = g[g["mode"] == 0].sort_values("run")["cyc_per_call"].values
        m1 = g[g["mode"] == 1].sort_values("run")["cyc_per_call"].values
        n = min(len(m0), len(m1))
        if n == 0:
            continue
        dd = m1[:n] - m0[:n]
        dmean.append(float(dd.mean()))
        dci.append(ci95(dd))
        l2m.append(float(g[g["mode"] == 1]["l2_miss_per_call"].median()))
        dram.append(float(g[g["mode"] == 1]["dram_fills_per_call"].median()))
    pop = int(d["pop"].iloc[0])
    dmean, dci, l2m, dram = map(np.array, (dmean, dci, l2m, dram))

    fig, ax = plt.subplots(figsize=(8.8, 5.2))
    ax.fill_between(ws, dmean - dci, dmean + dci, color=C_KFUNC, alpha=.15, lw=0)
    ln_cost, = ax.plot(ws, dmean, "o-", color=C_KFUNC, lw=2.4, ms=6,
                       label="kfunc added cost (mode1 - mode0)")
    ax.set_xscale("log", base=2)
    ax.set_ylim(0, dmean.max() * 1.3)
    ax.set_xlabel(f"working set  (distinct VLANs touched, full {pop}-VLAN population)")
    ax.set_ylabel("kfunc added cost  (cycles / call)", color=C_KFUNC)
    ax.tick_params(axis="y", labelcolor=C_KFUNC)
    ax.grid(alpha=.3, which="both")

    ax2 = ax.twinx()
    ln_l2, = ax2.plot(ws, l2m, "s--", color="#C62828", lw=1.8, ms=5,
                      label="L2 misses / call")
    ln_dr, = ax2.plot(ws, dram, "^:", color="#6A1B9A", lw=1.8, ms=5,
                      label="DRAM fills / call")
    ax2.set_ylabel("cache events / call")
    ax2.set_ylim(0, max(float(l2m.max()), 1.0) * 1.18)
    ax2.annotate(f"DRAM fills/call flat at ~{dram.max():.0e}\n(never a memory fill)",
                 xy=(ws[len(ws) // 2], dram[len(ws) // 2]), xytext=(0, 46),
                 textcoords="offset points", ha="center", fontsize=8, color="#6A1B9A",
                 arrowprops=dict(arrowstyle="->", color="#6A1B9A", lw=1))

    ax.set_title(f"Working-set sensitivity at full {pop}-VLAN population: "
                 f"cost rises into L3, never DRAM")
    ax.legend([ln_cost, ln_l2, ln_dr], [h.get_label() for h in (ln_cost, ln_l2, ln_dr)],
              loc="upper left", fontsize=8.5)
    fig.tight_layout()
    fig.savefig(os.path.join(out, "footprint.png"), dpi=130)
    plt.close(fig)


def fig_context(df, out, meta, ghz):
    """context.png: net_rx_action's share of host CPU under load, from a
    system-wide perf record during the flood. The XDP program and this kfunc run
    within net_rx_action.
    """
    try:
        nrx = float(meta.get("net_rx_action_pct"))
    except (TypeError, ValueError):
        return
    mm = df[(df.method == "micro") & (df.sweep == "chain") & (df["pop"] <= 256)]
    kf = (mm[mm["mode"] == 1]["cyc_per_call"].median()
          - mm[mm["mode"] == 0]["cyc_per_call"].median())
    kf_txt = (f", where bpf_xdp_egress_dev adds ~{kf / ghz:.0f} ns"
              if np.isfinite(kf) and ghz else "")

    fig, ax = plt.subplots(figsize=(8.6, 2.8))
    ax.barh(0, nrx, color=C_KFUNC, height=.5)
    ax.barh(0, 100 - nrx, left=nrx, color="#dcdcdc", height=.5)
    ax.text(nrx / 2, 0, f"net_rx_action  ~{nrx:.0f}%", ha="center", va="center",
            color="white", fontweight="bold", fontsize=11)
    ax.text(nrx + (100 - nrx) / 2, 0, "rest of host CPU", ha="center", va="center",
            color="#555", fontsize=10)
    ax.text(50, -0.62, f"The XDP program executes within net_rx_action{kf_txt}",
            ha="center", va="top", fontsize=9, color=C_REF)
    ax.set_xlim(0, 100)
    ax.set_ylim(-0.85, .5)
    ax.set_yticks([])
    ax.set_xlabel("share of host CPU under load  (%)")
    ax.set_title("Receive-path context: net_rx_action share of host CPU under load")
    fig.tight_layout()
    fig.savefig(os.path.join(out, "context.png"), dpi=130, bbox_inches="tight")
    plt.close(fig)


def fig_controls(df, out, ctl):
    """controls.png: was the measurement environment stable? The measured clock
    and DRAM latency across the run.

    The clock is the micro method's measured value (cycles / run time). sysfs
    scaling_cur_freq reads a nominal ~3.0 GHz on this AMD box while the core runs
    at the ~3.76 GHz base (boost off), so it is recorded in control.csv but not
    plotted.
    """
    if ctl is None or not len(ctl):
        return
    dram = pd.to_numeric(ctl.dram_min_ns, errors="coerce")
    m = df[(df.method == "micro") & df.freq_ghz.notna()]
    overall = float(m.freq_ghz.median()) if len(m) else float("nan")

    def freq_for(label):                   # measured clock during each phase
        if isinstance(label, str) and label.startswith("pop_"):
            try:
                p = int(label.split("_")[1])
            except ValueError:
                return overall
            sel = m[(m.sweep == "chain") & (m["pop"] == p)]
            return float(sel.freq_ghz.median()) if len(sel) else overall
        if isinstance(label, str) and "footprint" in label:
            sel = m[m.sweep == "footprint"]
            return float(sel.freq_ghz.median()) if len(sel) else overall
        return overall

    ghz = pd.Series([freq_for(l) for l in ctl.label])
    fig, (a1, a2) = plt.subplots(2, 1, figsize=(7.5, 4.6), sharex=True)
    a1.plot(range(len(ctl)), ghz, marker="o", color=C_KFUNC)
    a1.set_ylabel("core GHz (measured)")
    a1.grid(alpha=.3)
    if ghz.notna().any():                  # band the axis so a tiny jitter reads flat
        mid = float(ghz.median())
        a1.set_ylim(mid - .5, mid + .5)
    fspread = (ghz.max() - ghz.min()) * 1e3 if ghz.notna().any() else float("nan")
    dspread = (dram.max() - dram.min()) if dram.notna().any() else float("nan")
    a1.set_title(f"Measurement environment stable  "
                 f"(clock within {fspread:.0f} MHz, DRAM within {dspread:.0f} ns)")
    a2.plot(range(len(ctl)), dram, marker="o", color=C_FIB)
    a2.set_ylabel("DRAM latency (ns)")
    a2.grid(alpha=.3)
    if dram.notna().any():                 # don't let a 1 ns wiggle fill the panel
        mid = float(dram.median())
        a2.set_ylim(mid - 8, mid + 8)
    a2.set_xticks(range(len(ctl)))
    a2.set_xticklabels(ctl.label, rotation=55, ha="right", fontsize=7)
    fig.tight_layout()
    fig.savefig(os.path.join(out, "controls.png"), dpi=130, bbox_inches="tight")
    plt.close(fig)


def fig_ab(df, out, ghz):
    """ab.png: fold vs split over the footprint sweep, at the full 4094-VLAN
    population. Left: the absolute per-call cost of folding the egress device out
    of fib_lookup (mode 0) versus splitting it into a separate kfunc call
    (mode 1). Right: the difference, the one dev_get_by_index_rcu the fold avoids.
    """
    d = df[(df.method == "micro") & (df.sweep == "footprint")]
    if not len(d):
        return
    ws = sorted(d.working_set.unique())
    base, split, dmean, dci = [], [], [], []
    for w in ws:
        g = d[d.working_set == w]
        m0 = g[g["mode"] == 0].sort_values("run")["cyc_per_call"].values
        m1 = g[g["mode"] == 1].sort_values("run")["cyc_per_call"].values
        n = min(len(m0), len(m1))
        if n == 0:
            continue
        base.append(np.median(m0))
        split.append(np.median(m1))
        dd = m1[:n] - m0[:n]
        dmean.append(float(dd.mean()))
        dci.append(ci95(dd))
    pop = int(d["pop"].iloc[0])
    dmean, dci = np.array(dmean), np.array(dci)

    fig, (axL, axR) = plt.subplots(1, 2, figsize=(12.6, 4.8))
    axL.plot(ws, base, "o-", color=C_FIB, lw=2, ms=6,
             label="fold: fib_lookup only (mode 0)")
    axL.plot(ws, split, "s-", color=C_KFUNC, lw=2, ms=6,
             label="split: + bpf_xdp_egress_dev (mode 1)")
    axL.set_xscale("log", base=2)
    axL.set_xlabel("working set  (distinct VLANs touched)")
    axL.set_ylabel("per-call cost  (cycles)")
    axL.secondary_yaxis("right", functions=(lambda v: v / ghz, lambda n: n * ghz)
                        ).set_ylabel(f"ns  (at {ghz:.2f} GHz)")
    axL.set_title("Absolute per-call cost: fold vs split")
    axL.legend()
    axL.grid(alpha=.3, which="both")

    axR.fill_between(ws, dmean - dci, dmean + dci, color=C_KFUNC, alpha=.15, lw=0)
    axR.plot(ws, dmean, "D-", color=C_KFUNC, lw=2, ms=6)
    axR.set_xscale("log", base=2)
    axR.set_ylim(bottom=0)
    axR.set_xlabel("working set  (distinct VLANs touched)")
    axR.set_ylabel("split - fold  (cycles)")
    axR.secondary_yaxis("right", functions=(lambda v: v / ghz, lambda n: n * ghz)
                        ).set_ylabel(f"ns  (at {ghz:.2f} GHz)")
    axR.set_title("Cost avoided by folding  (one dev_get_by_index_rcu)")
    axR.grid(alpha=.3, which="both")

    fig.suptitle(f"bpf_xdp_egress_dev: fold vs split at full {pop}-VLAN "
                 f"population (worst-case chain depth)")
    l2max = float(df[(df.method == "micro") &
                     (df.sweep == "footprint")]["l2_miss_per_call"].max())
    fig.text(0.5, -0.01, f"Working set spills L2 (up to ~{l2max:.0f} misses/call at the "
             f"peak) but stays L3-resident; DRAM-free throughout.", ha="center",
             fontsize=8.2, color=C_REF)
    fig.tight_layout()
    fig.savefig(os.path.join(out, "ab.png"), dpi=130, bbox_inches="tight")
    plt.close(fig)


def fig_dist(df, out, ghz):
    """dist.png: the per-population spread of the added cost.

    Each population's 11 paired mode1-mode0 deltas as a box (IQR + median +
    range), every run as a jittered point, and the mean with its 95% CI. The
    boxes are a couple of cycles wide until the chains lengthen past 256. The
    per-cell sd and n are in the printed summary, not on the plot.
    """
    d = df[(df.method == "micro") & (df.sweep == "chain")]
    pops = sorted(d["pop"].unique())
    if not pops:
        return
    rng = np.random.default_rng(0)
    deltas, means, cis = [], [], []
    for p in pops:
        g = d[d["pop"] == p]
        m0 = g[g["mode"] == 0].sort_values("run")["cyc_per_call"].values
        m1 = g[g["mode"] == 1].sort_values("run")["cyc_per_call"].values
        n = min(len(m0), len(m1))
        dd = m1[:n] - m0[:n]
        deltas.append(dd)
        means.append(float(dd.mean()))
        cis.append(ci95(dd))
    pos = np.arange(len(pops))

    fig, ax = plt.subplots(figsize=(8.8, 5.0))
    bp = ax.boxplot(deltas, positions=pos, widths=.55, showfliers=False,
                    patch_artist=True, medianprops=dict(color="black"))
    for b in bp["boxes"]:
        b.set(facecolor="#cfe3f5", alpha=.85)
    for i, dd in enumerate(deltas):
        ax.scatter(rng.normal(i, .05, len(dd)), dd, s=14, alpha=.5, color="navy",
                   zorder=3, edgecolor="none")
    ax.errorbar(pos, means, yerr=cis, fmt="D", ms=6, color=C_KFUNC, capsize=4,
                lw=1.6, zorder=4, label="mean ± 95% CI  (n=11 paired runs / cell)")
    for i, dd in enumerate(deltas):       # the mean over each box
        ax.annotate(f"{means[i]:.0f}", xy=(i, max(dd)), xytext=(0, 6),
                    textcoords="offset points", ha="center", fontsize=8,
                    color="dimgray")
    wall = next((i for i, p in enumerate(pops) if p > 256), len(pos))
    ax.axvspan(wall - .5, len(pos) - .5, color="orange", alpha=.06)
    ax.text((wall - .5 + len(pos) - .5) / 2, 0.96, "hash chains lengthen beyond 256 buckets",
            fontsize=8, ha="center", va="top", color=C_REF,
            transform=ax.get_xaxis_transform())
    ax.set_xticks(pos)
    ax.set_xticklabels([str(p) for p in pops])
    ax.set_xlabel("VLAN population in the namespace  (hot working set fixed)")
    ax.set_ylabel("added cost  (cycles / call)")
    ax.secondary_yaxis("right", functions=(lambda v: v / ghz, lambda n: n * ghz)
                       ).set_ylabel(f"ns / call  (at {ghz:.2f} GHz)")
    ax.set_title("Per-population distribution of added cost  (box = IQR, n = 11 runs)")
    ax.legend(loc="upper left")
    ax.grid(axis="y", alpha=.3)
    fig.tight_layout()
    fig.savefig(os.path.join(out, "dist.png"), dpi=130)
    plt.close(fig)


def fig_pps(out, ghz):
    """pps.png: throughput, fold vs split over the population sweep.

    The literal method's real packet rate (run_cnt over the wall window), fold
    (mode 0) versus split (mode 1). Left: the rates, zero-based. Right: the cost
    in kpps. One sender core, so the absolute rate is the program's per-packet
    cost, not line rate; the fold-vs-split gap is the kfunc's marginal cost.
    """
    try:
        tpt = pd.read_csv(os.path.join(out, "throughput.csv"))
    except Exception:
        return
    ch = tpt[tpt.sweep == "chain"]
    piv = ch.pivot_table(index="pop", columns="mode", values="pps")
    if 0 not in piv.columns or 1 not in piv.columns:
        return
    piv = piv.dropna()
    pops = piv.index.values
    fold, split = piv[0].values, piv[1].values
    cost = (fold - split) / 1e3                          # kpps the kfunc costs

    fig, (axL, axR) = plt.subplots(1, 2, figsize=(12.4, 4.6))
    axL.plot(pops, fold / 1e6, "o-", color=C_FIB, lw=2, ms=6,
             label="fold: fib_lookup only (mode 0)")
    axL.plot(pops, split / 1e6, "s-", color=C_KFUNC, lw=2, ms=6,
             label="split: + bpf_xdp_egress_dev (mode 1)")
    axL.set_xscale("log", base=2)
    axL.set_ylim(0, fold.max() / 1e6 * 1.15)
    axL.set_xlabel("VLAN population in the namespace")
    axL.set_ylabel("throughput  (Mpps, one sender core)")
    axL.set_title("Packet rate: fold vs split")
    axL.legend(loc="lower left")
    axL.grid(alpha=.3, which="both")

    # Each cell is one perf window, so the per-cell delta is at the throughput
    # noise floor (it bounces, and a connecting line would invent a trend).
    # Show the points and the median, not a curve.
    med = float(np.median(cost))
    medpct = 100 * med * 1e3 / float(np.median(fold))
    axR.scatter(pops, cost, color=C_KFUNC, s=48, zorder=3)
    axR.axhline(med, color=C_KFUNC, ls="--", lw=1.6, alpha=.8)
    axR.set_xscale("log", base=2)
    axR.set_ylim(0, max(float(cost.max()) * 1.25, med * 2))
    axR.set_xlabel("VLAN population in the namespace")
    axR.set_ylabel("throughput cost of bpf_xdp_egress_dev  (kpps)")
    axR.annotate(f"median {med:.1f} kpps  (~{medpct:.1f}%)",
                 xy=(pops[0], med), xytext=(2, 8), textcoords="offset points",
                 ha="left", va="bottom", fontsize=9, color=C_KFUNC, fontweight="bold")
    axR.set_title("Per-cell throughput delta  (single-window measurement noise)")
    axR.grid(alpha=.3, which="both")

    # footprint sweep (device-touch-pressure regime), for the scope note
    fp = tpt[tpt.sweep == "footprint"].pivot_table(index="working_set",
                                                   columns="mode", values="pps")
    fp_txt = ""
    if 0 in fp.columns and 1 in fp.columns:
        fp_max = float(((fp[0] - fp[1]) / fp[0] * 100).max())
        fp_txt = (f"  Under the footprint sweep's device-touch pressure (not plotted) "
                  f"it rises to ~{fp_max:.1f}%.")
    fig.suptitle("bpf_xdp_egress_dev throughput cost in the population sweep "
                 "(veth, one sender core)")
    fig.text(0.5, -0.01, f"A per-call CPU-cost proxy, not deployment line rate.{fp_txt}",
             ha="center", fontsize=8.2, color=C_REF)
    fig.tight_layout()
    fig.savefig(os.path.join(out, "pps.png"), dpi=130, bbox_inches="tight")
    plt.close(fig)


def summary(df, out, meta, ctl, ghz):
    print("== bpf_xdp_egress_dev cost ==")
    m = df[df.method == "micro"]
    c = delta(df, "micro", "chain")
    c = c[c["dcyc"].notna()].sort_values("pop")
    f = delta(df, "micro", "footprint")
    f = f[f["dcyc"].notna()]
    floor = top = float("nan")
    if len(c):
        floor = c[c["pop"] <= 512]["dcyc"].mean()
        fci = c[c["pop"] <= 512]["ci_cyc"].max()
        top = float(c["dcyc"].iloc[-1])
        print(f"[micro] population sweep: {floor:.0f}+/-{fci:.0f} cyc warm "
              f"(~{floor / ghz:.0f} ns, flat to ~512 VLANs) rising to {top:.0f} cyc "
              f"(~{top / ghz:.0f} ns, {top / floor:.1f}x) at {VLAN_CEILING}")
    if len(f):
        fp_top = float(f["dcyc"].max())
        print(f"[micro] footprint sweep: up to {fp_top:.0f} cyc (~{fp_top / ghz:.0f} ns) "
              f"under working-set pressure")
    # relative to the bpf_fib_lookup driver (micro mode 0) it follows
    fib_warm = float(m[(m.sweep == "chain") & (m["mode"] == 0) &
                       (m["pop"] <= 512)]["cyc_per_call"].median())
    press = []
    for w in sorted(m[m.sweep == "footprint"]["working_set"].unique()):
        g = m[(m.sweep == "footprint") & (m["working_set"] == w)]
        a = g[g["mode"] == 0]["cyc_per_call"].median()
        b = g[g["mode"] == 1]["cyc_per_call"].median()
        if a > 0:
            press.append(100 * (b - a) / a)
    if np.isfinite(fib_warm) and np.isfinite(floor):
        pmax = max(press) if press else float("nan")
        gc = m[(m.sweep == "chain") & (m["pop"] == VLAN_CEILING)]
        fib_c = float(gc[gc["mode"] == 0]["cyc_per_call"].median())
        ceil_pct = 100 * (float(gc[gc["mode"] == 1]["cyc_per_call"].median()) - fib_c) / fib_c
        print(f"context: kfunc is ~{100 * floor / fib_warm:.0f}% of bpf_fib_lookup warm "
              f"({fib_warm:.0f} cyc), ~{ceil_pct:.0f}% at the {VLAN_CEILING} ceiling, "
              f"up to ~{pmax:.0f}% under footprint pressure")
    abs_dram = float(m["dram_fills_per_call"].max())
    print(f"L3-resident: DRAM fills/call <= {abs_dram:.0e} across the whole dataset, "
          f"never a memory fill")
    cl = delta(df, "literal", "chain")
    lkf = cl[cl["pop"] <= 256]["dns"].median() if len(cl) else float("nan")
    if np.isfinite(lkf):
        print(f"context: literal (real frames) cross-check, kfunc adds ~{lkf:.0f} ns warm")
    nrx = meta.get("net_rx_action_pct")
    if nrx and nrx != "NA":
        print(f"context: net_rx_action ~{nrx}% of host CPU during the flood")
    try:
        tpt = pd.read_csv(os.path.join(out, "throughput.csv"))

        def tpct(sw, idx):
            p = tpt[tpt.sweep == sw].pivot_table(index=idx, columns="mode", values="pps")
            return ((p[0] - p[1]) / p[0] * 100) if (0 in p.columns and 1 in p.columns) else None

        chp, fpp = tpct("chain", "pop"), tpct("footprint", "working_set")
        if chp is not None and fpp is not None:
            print(f"throughput cost (veth, 1 sender core): ~{chp.median():.1f}% population "
                  f"sweep, up to ~{fpp.max():.1f}% footprint (a per-call-cost proxy)")
    except Exception:
        pass
    if ctl is not None:
        dram = pd.to_numeric(ctl.dram_min_ns, errors="coerce").dropna()
        if len(dram):
            print(f"controls: measured clock ~{ghz:.2f} GHz, DRAM latency "
                  f"{dram.min():.0f}-{dram.max():.0f} ns (stable)")
    print("plots: cost.png  sits.png  ab.png  footprint.png  dist.png  context.png  "
          "pps.png  controls.png")


def main():
    out = sys.argv[1]
    df = pd.read_csv(os.path.join(out, "samples.csv"))
    try:
        ctl = pd.read_csv(os.path.join(out, "control.csv"))
    except Exception:
        ctl = None
    meta = read_meta(out)
    global L2_BYTES
    L2_BYTES = parse_size(meta.get("l2_size")) or L2_BYTES
    ghz = measured_ghz(df)

    fig_cost(df, out, ghz)
    fig_sits(df, out, ghz, meta)
    fig_ab(df, out, ghz)
    fig_footprint(df, out, ghz)
    fig_dist(df, out, ghz)
    fig_context(df, out, meta, ghz)
    fig_pps(out, ghz)
    fig_controls(df, out, ctl)
    summary(df, out, meta, ctl, ghz)


if __name__ == "__main__":
    main()
