#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Avinash Duduskar <avinash.duduskar@gmail.com>
# One command on the dedicated UKI: locate the results USB, run the bench, print
# a banner when done. USB detection scans sysfs for a removable usb-path device
# with a filesystem-label fallback for enclosures that do not report removable,
# so it needs no blkid or by-label support (which the minimal UKI lacks).
#
# Results go to a fresh timestamped subdir under the mount, so existing files on
# the USB are never touched.
set -u
# resolve through the /usr/local/bin/bench symlink to the real script dir, so
# run_kfunc.sh and the binaries are found regardless of how bench is invoked
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
: "${USB_LABEL:=ESD-USB}"                              # Pass-2 label fallback
_USB_AUTOMOUNT="${BENCH_OUTPUT_ROOT:-/mnt/bench-results}"

# Resolve the results USB strictly by filesystem label (default ESD-USB), so it
# can never pick another removable stick (e.g. a Ventoy boot USB). Tries several
# label-resolution methods, then falls back to a sysfs scan of removable USB
# partitions filtered by the same label. Returns its mountpoint.
find_usb_mount() {
	local label="${USB_LABEL:-ESD-USB}" dev mnt blk bdev devpath p

	# already mounted under that label?
	mnt=$(findmnt -n -o TARGET -L "$label" 2>/dev/null || true)
	[[ -n "$mnt" ]] && { echo "$mnt"; return; }

	# resolve the device by label
	dev=$(blkid -L "$label" 2>/dev/null \
	      || readlink -f "/dev/disk/by-label/$label" 2>/dev/null || true)

	# fallback: scan removable USB partitions, match the label ourselves
	if [[ -z "$dev" || ! -b "$dev" ]]; then
		for blk in /sys/block/sd*; do
			[[ "$(cat "$blk/removable" 2>/dev/null)" == "1" ]] || continue
			devpath=$(readlink -f "$blk" 2>/dev/null || true)
			[[ "$devpath" == *usb* ]] || continue
			bdev=$(basename "$blk")
			for p in "/dev/${bdev}"[0-9]* "/dev/${bdev}"; do
				[[ -b "$p" ]] || continue
				[[ "$(blkid -o value -s LABEL "$p" 2>/dev/null)" == "$label" ]] \
					&& { dev="$p"; break 2; }
			done
		done
	fi
	[[ -n "$dev" && -b "$dev" ]] || return

	# use the existing mount if any, otherwise auto-mount
	mnt=$(findmnt -n -o TARGET -S "$dev" 2>/dev/null || true)
	[[ -n "$mnt" ]] && { echo "$mnt"; return; }
	mkdir -p "$_USB_AUTOMOUNT"
	mount "$dev" "$_USB_AUTOMOUNT" 2>/dev/null && echo "$_USB_AUTOMOUNT"
}

USB_MOUNT=$(find_usb_mount || true)
if [[ -z "$USB_MOUNT" ]]; then
	echo "no results USB found. block devices seen:"
	lsblk -o NAME,LABEL,FSTYPE,RM,MOUNTPOINT 2>/dev/null
	exit 1
fi
echo ">>> results USB at: $USB_MOUNT"

bash "$HERE/run_kfunc.sh" "$USB_MOUNT"
rc=$?
sync
out=$(for d in "$USB_MOUNT"/kfunc-bench-*/; do [ -d "$d" ] && echo "${d%/}"; done | sort | tail -1)

echo
echo "############################################################"
if [ "$rc" -eq 0 ]; then
	echo "#  BENCH COMPLETE"
	echo "#  results: $out  (synced to the USB)"
	echo "#  SAFE TO REBOOT -> pick arch-linux-lts, then on the host:"
	echo "#    python3 analyze_kfunc.py <usb>/${out##*/}"
else
	echo "#  BENCH FAILED (rc=$rc) -- see the output above"
fi
echo "############################################################"
