#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Avinash Duduskar <avinash.duduskar@gmail.com>
# Cost bench for bpf_xdp_egress_dev. Run as root on a box whose kernel exports
# the kfunc in BTF. README.md is the summary; this documents what the script does.
#
# Measures the kfunc's added cost (mode1 - mode0), two methods and two sweeps:
#   methods  micro    PROG_TEST_RUN self-PMU (kfunc_drive), 11 paired runs/cell.
#            literal  real frames through an attached XDP prog calling the kfunc
#                     (kfunc_xdp + pkt_send), via perf -b + run_time_ns/run_cnt.
#   sweeps   population  hot set fixed, vary VLAN count (NETDEV_HASHENTRIES = 256
#                        chain-walk wall).
#            footprint   full population, vary the working set.
# Both run in one netns so they resolve against the same netdevice hash.
#
# mode1 - mode0 is the kfunc's full cost; no fold variant is measured, so it is
# an upper bound on the split-over-fold delta. The per-cell value is the median
# of the paired deltas. The clock is cycles / run time; scaling_cur_freq is not
# used. Isolation is verified below before any cell is measured.
#
# Context controls: a bare XDP_DROP floor and net_rx_action's share of host CPU
# during the flood.
#
# Override with env vars: CORE, SENDCORE, HOTK, PREFETCH_CMD (a python script).
set -u
NS=kbench
CORE="${CORE:-6}"
SENDCORE="${SENDCORE:-5}"
HOTK="${HOTK:-8}"
# cache events: DRAM fills = L3 miss->DRAM, and L2
# miss. Zen4 named events; override per-arch via env (and BENCH_DRAM_CFG /
# BENCH_L2_CFG for the C micro loader's raw configs).
DRAM_EVENT="${DRAM_EVENT:-ls_any_fills_from_sys.dram_io_near}"
L2_EVENT="${L2_EVENT:-l2_cache_req_stat.ic_dc_miss_in_l2}"
export BENCH_CORE="$CORE"
BENCH="$(cd "$(dirname "$0")" && pwd)"
# Treat the arg as a PARENT dir (e.g. a USB mount) and always create a fresh
# timestamped subdir under it. Never write into an existing dir, so prior logs
# on the target are never clobbered.
BASE="${1:-/tmp}"
OUT="$BASE/kfunc-bench-$(date +%Y%m%d-%H%M%S)"
if [ -e "$OUT" ]; then echo "refusing: $OUT already exists"; exit 1; fi
mkdir -p "$OUT" || { echo "cannot create $OUT (is $BASE mounted and writable?)"; exit 1; }
CSV="$OUT/samples.csv"
CTL="$OUT/control.csv"
echo "method,sweep,pop,working_set,run,mode,cyc_per_call,ns_per_call,dram_fills_per_call,l2_miss_per_call,freq_ghz" > "$CSV"
echo "ts,label,dram_min_ns,cpu_khz" > "$CTL"
TPT="$OUT/throughput.csv"      # literal-method packet rate (real XDP datapath)
echo "sweep,pop,working_set,mode,pps,mpps" > "$TPT"

say() { echo "[$(date +%H:%M:%S)] $*"; }

# ---- environment ----
say "environment: governor=performance, boost off, nmi_watchdog=0, paranoid=-1, bpf_stats=1"
for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance > "$g" 2>/dev/null; done
echo 0  > /sys/devices/system/cpu/cpufreq/boost   2>/dev/null   # pin the clock so ns is comparable across cells
echo 0  > /proc/sys/kernel/nmi_watchdog          2>/dev/null
echo -1 > /proc/sys/kernel/perf_event_paranoid   2>/dev/null
echo 1  > /proc/sys/kernel/bpf_stats_enabled     2>/dev/null
modprobe msr 2>/dev/null

# machine metadata, so the data is self-describing and analyze reads the real
# cache sizes off THIS box rather than a hardcoded model
meta() { echo "$1=$2" >> "$OUT/meta.txt"; }
: > "$OUT/meta.txt"
meta kernel   "$(uname -r)"
meta cpu      "$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//')"
meta core     "$CORE"
meta sendcore "$SENDCORE"
for idx in /sys/devices/system/cpu/cpu"$CORE"/cache/index*; do
	[ -d "$idx" ] || continue
	lvl=$(cat "$idx/level" 2>/dev/null); typ=$(cat "$idx/type" 2>/dev/null); sz=$(cat "$idx/size" 2>/dev/null)
	case "$typ" in
	Data)        meta "l${lvl}d_size" "$sz" ;;
	Instruction) meta "l${lvl}i_size" "$sz" ;;
	Unified)     meta "l${lvl}_size"  "$sz" ;;
	esac
done

PREFETCH_PY="${PREFETCH_CMD:-$BENCH/prefetch_off.py}"
if python3 "$PREFETCH_PY" > "$OUT/prefetch.txt" 2>&1; then
	pf_ok=1; meta prefetch_off yes; say "prefetch: $(tail -1 "$OUT/prefetch.txt")"
else
	pf_ok=0; meta prefetch_off no; say "prefetch: NOT verified off (see prefetch.txt)"
fi

# ---- read the isolation knobs back and confirm they took before measuring ----
iso=1
gov=$(cat /sys/devices/system/cpu/cpu"$CORE"/cpufreq/scaling_governor 2>/dev/null); meta governor "$gov"
if [ "$gov" = performance ]; then say "verify governor=performance OK"; else say "verify governor='$gov' NOT performance"; iso=0; fi
if [ -f /sys/devices/system/cpu/cpufreq/boost ]; then
	bst=$(cat /sys/devices/system/cpu/cpufreq/boost 2>/dev/null)
	if [ "$bst" = 0 ]; then meta boost_off yes; say "verify boost off OK"; else meta boost_off no; say "verify boost ON ($bst)"; iso=0; fi
fi
par=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null); meta perf_event_paranoid "$par"
if [ "${par:-9}" -le 0 ] 2>/dev/null; then say "verify paranoid=$par OK"; else say "verify paranoid=$par need<=0"; iso=0; fi
bs=$(cat /proc/sys/kernel/bpf_stats_enabled 2>/dev/null); meta bpf_stats "$bs"
if [ "$bs" = 1 ]; then say "verify bpf_stats=1 OK"; else say "verify bpf_stats off"; iso=0; fi
[ "${pf_ok:-0}" = 1 ] || iso=0
meta isolation_verified "$([ "$iso" = 1 ] && echo yes || echo no)"
if [ "$iso" = 1 ]; then say "ISOLATION VERIFIED, starting"; else say "WARNING: isolation INCOMPLETE (see meta.txt), results may be noisy"; fi

# ---- topology in a netns ----
ip netns del "$NS" 2>/dev/null
ip netns add "$NS"
ip -n "$NS" link set lo up
ip -n "$NS" link add veth0 type veth peer name veth1
ip -n "$NS" link set veth0 up
ip -n "$NS" link set veth1 up
HAVE=0
add_vlans() {            # $1 target population on veth0
	while [ "$HAVE" -lt "$1" ]; do
		HAVE=$((HAVE + 1))
		ip -n "$NS" link add link veth0 name "v$HAVE" type vlan id "$HAVE" 2>/dev/null
	done
}

control_sample() {       # $1 label: DRAM latency + current core freq, timestamped
	local ns f
	ns=$(taskset -c "$CORE" "$BENCH/controls/chase" --cpu "$CORE" --pages thp --samples 2 2>/dev/null \
	     | grep -o '"min_ns": [0-9.]*' | grep -o '[0-9.]*')
	f=$(cat /sys/devices/system/cpu/cpu"$CORE"/cpufreq/scaling_cur_freq 2>/dev/null)
	echo "$(date +%s.%N),$1,${ns:-NA},${f:-NA}" >> "$CTL"
}

micro() {                # $@ sweep-args for kfunc_drive; emits method=micro rows
	ip netns exec "$NS" taskset -c "$CORE" "$BENCH/kfunc_drive" "$@" 2>>"$OUT/micro.err" \
		| grep '^CSV ' | sed 's/^CSV /micro,/' >> "$CSV"
}

# literal cell: attach prog, drive with the running sender, read perf -b + bpf_stats
literal() {              # $1 sweep $2 mode $3 ws $4 popcount $5 pop_for_csv
	local sweep=$1 mode=$2 ws=$3 popn=$4 popcsv=$5 pid s0 s1 c0 c1 t0 t1 cyc dramf l2m dc dt w0 w1
	ip netns exec "$NS" taskset -c "$CORE" "$BENCH/kfunc_xdp" veth0 "$mode" "$ws" "$popn" \
		> "$OUT/.progid" 2>&1 &
	local lp=$!
	sleep 0.5
	pid=$(grep -o 'PROGID [0-9]*' "$OUT/.progid" | awk '{print $2}')
	if [ -z "$pid" ]; then say "literal attach failed ($sweep m$mode ws$ws): $(cat "$OUT/.progid")"; kill "$lp" 2>/dev/null; return; fi
	# Snapshot run_cnt/run_time adjacent to the perf call so dc/dt cover the same
	# window perf counts; parse the snapshots afterwards (parsing is outside the
	# window). This removes the bpftool-latency skew on cyc/dram/l2/pps.
	w0=$(date +%s.%N); s0=$(bpftool prog show id "$pid" 2>/dev/null)
	perf stat -e "cycles,$DRAM_EVENT,$L2_EVENT" -b "$pid" -- sleep 2 2> "$OUT/.perf"
	s1=$(bpftool prog show id "$pid" 2>/dev/null); w1=$(date +%s.%N)
	kill "$lp" 2>/dev/null; wait "$lp" 2>/dev/null
	c0=$(echo "$s0" | grep -o 'run_cnt [0-9]*'     | awk '{print $2}')
	t0=$(echo "$s0" | grep -o 'run_time_ns [0-9]*' | awk '{print $2}')
	c1=$(echo "$s1" | grep -o 'run_cnt [0-9]*'     | awk '{print $2}')
	t1=$(echo "$s1" | grep -o 'run_time_ns [0-9]*' | awk '{print $2}')
	# perf -b count = the first field of the matching line, only when it is
	# numeric. perf prints '<not counted>'/'<not supported>' when a counter did
	# not run; taking the first field (not the first digit-run on the line) avoids
	# grabbing a digit from inside an event name like l2_..._in_l2, and an empty
	# result records NA rather than a fabricated 0.
	cyc=$(awk 'index($0,"cycles"){v=$1;gsub(/,/,"",v);if(v~/^[0-9]+$/)print v;exit}' "$OUT/.perf")
	dramf=$(awk -v e="$DRAM_EVENT" 'index($0,e){v=$1;gsub(/,/,"",v);if(v~/^[0-9]+$/)print v;exit}' "$OUT/.perf")
	l2m=$(awk -v e="$L2_EVENT" 'index($0,e){v=$1;gsub(/,/,"",v);if(v~/^[0-9]+$/)print v;exit}' "$OUT/.perf")
	dc=$(( ${c1:-0} - ${c0:-0} )); dt=$(( ${t1:-0} - ${t0:-0} ))
	if [ "$dc" -le 0 ]; then say "literal: no invocations ($sweep m$mode ws$ws pop$popcsv)"; return; fi
	# real XDP packet rate over the window: run_cnt delta / wall seconds (Mpps)
	awk -v dc="$dc" -v w0="$w0" -v w1="$w1" -v s="$sweep" -v p="$popcsv" -v ws="$ws" -v m="$mode" \
	    'BEGIN{e=w1-w0; if(e>0){pps=dc/e; printf "%s,%d,%d,%d,%.0f,%.4f\n",s,p,ws,m,pps,pps/1e6}}' >> "$TPT"
	python3 - "$sweep" "$popcsv" "$ws" "$mode" "${cyc:-}" "${dramf:-}" "${l2m:-}" "$dc" "$dt" >> "$CSV" <<'PY'
import sys
sw, pop, ws, mode = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
dc, dt = int(sys.argv[8]), int(sys.argv[9])

def per(x):                      # per-call, or "" (NA) when the counter did not run
    try:
        return "%.6f" % (float(x) / dc)
    except ValueError:
        return ""

cyc, dram, l2 = per(sys.argv[5]), per(sys.argv[6]), per(sys.argv[7])
try:
    freq = "%.4f" % (float(sys.argv[5]) / dt) if dt else ""
except ValueError:
    freq = ""
print("literal,%s,%d,%d,0,%d,%s,%.4f,%s,%s,%s" %
      (sw, pop, ws, mode, cyc, dt / dc, dram, l2, freq))
PY
}

# net_rx_action's share of host CPU during the flood. One system-wide record
# window; best-effort, since kernel unwind can be flaky.
datapath_context() {
	command -v perf >/dev/null 2>&1 || { meta net_rx_action_pct NA; return; }
	perf record -a -g -F 999 -e cycles -o "$OUT/.rx.data" -- sleep 3 >/dev/null 2>&1 || { meta net_rx_action_pct NA; return; }
	local pct
	pct=$(perf report --stdio -g -i "$OUT/.rx.data" 2>/dev/null \
	      | grep -m1 'net_rx_action' | grep -oE '[0-9]+\.[0-9]+%' | head -1 | tr -d '%')
	meta net_rx_action_pct "${pct:-NA}"
	say "datapath context: net_rx_action ~${pct:-NA}% of CPU during the flood"
}

# start the flooder once (veth1 -> arrives veth0 where the literal prog attaches)
say "starting flooder on veth1 (core $SENDCORE)"
ip netns exec "$NS" taskset -c "$SENDCORE" "$BENCH/pkt_send" veth1 "$SENDCORE" > /dev/null 2>&1 &
SENDER=$!
trap 'kill "$SENDER" 2>/dev/null; ip netns del "$NS" 2>/dev/null' EXIT

# ---- context controls (net_rx_action share, and the bare XDP floor) ----
# no VLANs needed here (bare prog uses nr_devs=0); leaving the netns empty lets
# the population sweep below start clean at 64 instead of being pinned at 256
datapath_context
literal bare 0 0 0 0                 # bare XDP_DROP: per-packet prog floor, no fib, no kfunc

# ---- Phase 1: population sweep (the 256 wall) ----
say "phase 1: population sweep (hot set K=$HOTK), micro + literal"
for P in 64 128 256 512 1024 2048 4094; do
	add_vlans "$P"
	control_sample "pop_$P"
	micro chain "$HOTK"            # micro emits sweep=chain,pop=current,ws=K
	literal chain 0 "$HOTK" "$HOTK" "$P"
	literal chain 1 "$HOTK" "$HOTK" "$P"
	say "  pop=$P done"
done

# ---- Phase 2: footprint sweep (cache residence) at full population ----
say "phase 2: footprint sweep at pop=$HAVE, micro + literal"
control_sample "footprint_full"
micro footprint                     # micro emits sweep=footprint, ws over Ns[]
for W in 1 2 4 8 16 32 64 128 256 512 1024 2048 4094; do
	[ "$W" -gt "$HAVE" ] && break
	literal footprint 0 "$W" "$HAVE" "$HAVE"
	literal footprint 1 "$W" "$HAVE" "$HAVE"
done
control_sample "end"

say "done. results in $OUT"
ls -la "$OUT"
