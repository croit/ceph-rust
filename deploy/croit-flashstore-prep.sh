#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: 2026 croit GmbH
# SPDX-FileContributor: Martin Verges, croit GmbH
# SPDX-FileContributor: Igor Fedotov, croit GmbH
# SPDX-FileContributor: Mahamudur Rahaman Sajib, croit GmbH
# croit-flashstore-prep.sh ID: idempotent host preparation for one OSD (adr 0034). Touches ONLY the NVMe named in
# [osd.ID] (flashstore_dev) of /etc/ceph/$CLUSTER.conf. NICs stay on kernel drivers (adr 0682).
#   conf keys: flashstore_driver (vfio-pci default | uio_pci_generic = lab fallback without vIOMMU),
#              flashstore_hugepages_mb | flashstore_mem (2048; resolved by croit-flashstore-tool hugepage-budget), flashstore_hugepage_kb (2048 | 1048576), flashstore_huge_dir (/dev/hugepages),
#   env:  CLUSTER (ceph), FLASHSTORE_PREP_DRY=1 (print actions only)
# Exit: 0 ok, 3 refused (device in use / missing), 2 usage (ID is not a non-negative integer), 1 failure.
set -euo pipefail
id=${1:-}
# the id builds paths (data dir, conf section) and feeds `chown -R`: a separator or `..` must never reach them
case $id in ''|*[!0-9]*) echo "croit-flashstore-prep: usage: croit-flashstore-prep.sh OSD_ID (non-negative integer), got '$id'" >&2; exit 2 ;; esac
cluster=${CLUSTER:-ceph}
conf=${FLASHSTORE_CONF:-/etc/ceph/$cluster.conf}
dry=${FLASHSTORE_PREP_DRY:-0}
# sysfs root (a fixture tree in tests); everything below only reads/writes paths under it
sysfs=${FLASHSTORE_SYSFS:-/sys}
log() { echo "croit-flashstore-prep[$id]: $*" >&2; }
die() { log "refused: $*"; exit 3; }
run() { if [ "$dry" = 1 ]; then log "dry: $*"; else "$@"; fi; }
wr() { if [ "$dry" = 1 ]; then log "dry: echo $1 > $2"; else printf '%s' "$1" > "$2"; fi; }
[ -r "$conf" ] || die "$conf not readable"

# value of a key, precedence [global] < [osd] < [osd.ID]; keys normalised (space/dash -> underscore); inline comments cut
opt() {
  local key=$1 s v out=${2:-}
  for s in global osd "osd.$id"; do
    v=$(awk -v sec="$s" -v key="$key" '
      /^[ \t]*\[/ { cur=$0; gsub(/^[ \t]*\[|\][ \t]*$/, "", cur); next }
      cur==sec && /=/ {
        k=$0; sub(/=.*/, "", k); gsub(/^[ \t]+|[ \t]+$/, "", k); gsub(/[ -]/, "_", k)
        if (k==key) { v=$0; sub(/^[^=]*=[ \t]*/, "", v); sub(/[ \t]+[#;].*$/, "", v); gsub(/[ \t]+$/, "", v); val=v }
      }
      END { if (val!="") print val }' "$conf")
    [ -n "$v" ] && out=$v
  done
  printf '%s' "$out"
}

# The device list is root-owned configuration only: the OSD data dir (and its `croit-flashstore-osd` marker) belongs to the daemon
# user, and a root unit must never unbind a host device named there.
dev=$(opt flashstore_dev)
[ -n "$dev" ] || log "no flashstore_dev in [osd.$id] of $conf: no SPDK PCI device bound"
nvme_pci=$(printf '%s' "$dev" | sed -n 's/^spdk:\([^,]*\).*/\1/p')
backend=$(opt flashstore_store_backend)
kernel_storage=0
case "$backend" in
  kernel|kernel-cmd) kernel_storage=1 ;;
  ''|spdk) case "$dev" in kernel:*) kernel_storage=1;; esac ;;
  *) die "flashstore_store_backend must be spdk, kernel or kernel-cmd" ;;
esac
# The spdk:BDF identity remains valid for a kernel backend; resolving it requires
# the namespace to stay bound to nvme.
[ "$kernel_storage" = 0 ] || nvme_pci=
if [ -n "$(opt flashstore_vf_pci)" ]; then
  vf=$(opt flashstore_vf_pci)
  log "WARNING flashstore_vf_pci = $vf is obsolete and ignored: NICs stay on their kernel drivers (kernel TCP/RDMA). Remove the line: sed -i '/^[[:space:]]*flashstore_vf_pci[[:space:]]*[=]/d' $conf. A NIC an older release moved to vfio-pci returns to its kernel driver with: echo > /sys/bus/pci/devices/$vf/driver_override; echo $vf > /sys/bus/pci/drivers_probe"
fi
# PCI address shape (`[dddd:]bb:dd.f`): the value is interpolated into sysfs paths, so refuse anything else
valid_bdf() {
  case "$1" in
    "" | *[!0-9A-Fa-f:.]*) die "bad PCI address '$1' ($2)" ;;
  esac
  printf '%s' "$1" | grep -Eq '^([0-9a-fA-F]{4}:)?[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$' \
    || die "bad PCI address '$1' ($2)"
}
driver=$(opt flashstore_driver vfio-pci)
# The hugepage budget has ONE resolver, the daemon's (K/M/G/T suffixes, the flashstore_mem alias, conflicting
# spellings refused): croit-flashstore-tool reads it from the same conf. The tool also proves an NVMe unused before
# an unbind (bind_nvme), so prep needs it on every host.
command -v croit-flashstore-tool >/dev/null \
  || die "croit-flashstore-tool not found: it resolves the hugepage budget and proves an NVMe unused before the unbind (install the croit-flashstore-osd package; container hosts: docker create --name flashstore-tool-copy IMAGE && docker cp flashstore-tool-copy:/usr/bin/croit-flashstore-tool /usr/local/bin/ && docker rm flashstore-tool-copy; podman likewise)"
rc=0
need_mb=$(croit-flashstore-tool hugepage-budget --id "$id" --cluster "$cluster" --conf "$conf") || rc=$?
[ "$rc" = 0 ] || die "hugepage budget of osd.$id (croit-flashstore-tool hugepage-budget exit $rc, reason above)"
case $need_mb in ''|*[!0-9]*) log "croit-flashstore-tool hugepage-budget printed '$need_mb', not MB"; exit 1 ;; esac
page_kb=$(opt flashstore_hugepage_kb 2048)
huge_dir=$(opt flashstore_huge_dir /dev/hugepages)
# non-root operation (adr 0056): the daemon runs as this user; "root" = leave ownership alone (uio / NOIOMMU lab hosts)
run_user=$(opt flashstore_user)
case "$driver" in vfio-pci|uio_pci_generic) ;; *) die "flashstore_driver must be vfio-pci or uio_pci_generic";; esac
# default: ceph with vfio, root with the uio lab fallback (pair it with the unit drop-in root.conf.example)
[ -n "$run_user" ] || { [ "$driver" = vfio-pci ] && run_user=ceph || run_user=root; }
nonroot=0
if [ "$run_user" != root ]; then
  [ "$driver" = vfio-pci ] || die "flashstore_user = $run_user needs flashstore_driver = vfio-pci (uio needs root: set flashstore_user = root)"
  uid=$(id -u "$run_user" 2>/dev/null) || die "flashstore_user: no such user '$run_user'"
  gid=$(id -g "$run_user")
  nonroot=1
fi

# ---- hugepages: enough FREE pages of the configured size, hugetlbfs mounted at huge_dir
# free = free_hugepages - resv_hugepages: reserved pages count as free until faulted but belong to another mapping
hp=$sysfs/kernel/mm/hugepages/hugepages-${page_kb}kB
[ -d "$hp" ] || die "no hugepage size ${page_kb} kB on this kernel"
need=$(( (need_mb * 1024 + page_kb - 1) / page_kb ))
hp_free() { local f r; f=$(cat "$hp/free_hugepages"); r=$(cat "$hp/resv_hugepages" 2>/dev/null || echo 0); echo $(( f > r ? f - r : 0 )); }
free=$(hp_free)
if [ "$free" -lt "$need" ]; then
  total=$(cat "$hp/nr_hugepages")
  want=$(( total + need - free ))
  log "hugepages ${page_kb}kB: free $free < need $need, nr_hugepages $total -> $want"
  wr "$want" "$hp/nr_hugepages"
  [ "$dry" = 1 ] || [ "$(hp_free)" -ge "$need" ] || { log "could not reserve $need hugepages (fragmented memory? reserve at boot: hugepagesz=/hugepages= kernel cmdline)"; exit 1; }
fi
if ! mountpoint -q "$huge_dir"; then
  log "mounting hugetlbfs on $huge_dir (pagesize ${page_kb}kB)"
  run mkdir -p "$huge_dir"
  run mount -t hugetlbfs -o "pagesize=${page_kb}K" nodev "$huge_dir"
fi
if [ "$nonroot" = 1 ]; then
  # DPDK creates its hugepage files here as the daemon user: group access + sticky (files stay private to their owner)
  run chgrp "$gid" "$huge_dir"
  run chmod 1770 "$huge_dir"
fi

# ---- driver bind of the ONE NVMe function. Admission (NVMe class, no holders/mounts/swap, exclusive O_EXCL + lock
# claims held through the unbind) and the sysfs rebind are croit-flashstore-tool nvme-rebind: bash cannot hold an
# exclusive block-device claim. Cross-process claim dir first: nvme-rebind takes the SPDK PCI claim from vfio/uio.
run install -d -o root -g ceph -m 1770 /run/croit-flashstore-osd
bind_nvme() {
  local pci=$1 d="$sysfs/bus/pci/devices/$1" cur rc
  valid_bdf "$pci" nvme
  [ -d "$d" ] || die "nvme $pci: no such PCI device"
  cur=$(basename "$(readlink "$d/driver" 2>/dev/null)" 2>/dev/null || true)
  if [ "$cur" = "$driver" ]; then log "nvme $pci already on $driver"; return 0; fi
  run modprobe "$driver"
  if [ "$driver" = vfio-pci ] && [ -z "$(ls -A "$sysfs/kernel/iommu_groups" 2>/dev/null)" ]; then
    [ "$(cat "$sysfs/module/vfio/parameters/enable_unsafe_noiommu_mode" 2>/dev/null || echo N)" = Y ] \
      || die "vfio-pci needs the IOMMU (intel_iommu=on / amd_iommu=on) or noiommu mode; lab without vIOMMU: flashstore_driver = uio_pci_generic"
  fi
  log "nvme $pci: ${cur:-unbound} -> $driver"
  rc=0
  croit-flashstore-tool nvme-rebind --pci "$pci" --driver "$driver" $([ "$dry" = 1 ] && echo --dry-run) >&2 || rc=$?
  case $rc in
    0) ;;
    3) die "nvme $pci: in use or not eligible (reason above); nothing changed" ;;
    *) log "nvme $pci: rebind to $driver failed (exit $rc)"; exit 1 ;;
  esac
}
[ -z "$nvme_pci" ] || bind_nvme "$nvme_pci"

# ---- non-root: hand the vfio group nodes of the bound devices and the daemon's directories to the daemon user.
# Group node = /dev/vfio/<iommu group> (created when the device binds; udev would give root:root 0600). A group is
# owned by ONE process: devices sharing a group (same IOMMU group) all belong to this OSD or none may be used.
# Cross-process claim locks (adr 0649 am. 1): root-owned 1770 root:ceph, shared by the daemon (group ceph), root tools
# and containers; PrivateTmp keeps /var/tmp private to the unit, so the locks must not live there. Claim files are
# created 0666 by whoever opens first: nothing is chowned in the group-writable dir (a swapped symlink would redirect it).
# (The claim dir itself is created before the bind, above.)
if [ "$nonroot" = 1 ]; then
  for pci in $nvme_pci; do
    [ "$dry" = 1 ] && { log "dry: chown/chmod /dev/vfio/<group of $pci> to :$gid 0660"; continue; }
    g=$(basename "$(readlink "$sysfs/bus/pci/devices/$pci/iommu_group" 2>/dev/null)" 2>/dev/null || true)
    [ -n "$g" ] || die "$pci: no IOMMU group (IOMMU off? vfio needs intel_iommu=on / amd_iommu=on; no-IOMMU hosts: flashstore_user = root)"
    node=/dev/vfio/$g
    for _ in 1 2 3 4 5 6 7 8 9 10; do [ -e "$node" ] && break; sleep 0.5; done
    [ -e "$node" ] || die "$pci: $node did not appear"
    chown "root:$gid" "$node"
    chmod 0660 "$node"
    log "$pci: $node -> root:$gid 0660"
  done
  for d in /var/run/ceph /var/log/ceph; do
    [ -d "$d" ] || run install -d -o "$uid" -g "$gid" -m 0755 "$d"
    [ "$(stat -c %u "$d" 2>/dev/null)" = "$uid" ] || run chown "$uid:$gid" "$d"
  done
  # crash dumps carry host details, the stack and a log tail: directory 0750 (the agent runs as the daemon user)
  d=/var/lib/ceph/crash
  [ -d "$d" ] || run install -d -o "$uid" -g "$gid" -m 0750 "$d"
  [ "$(stat -c %u "$d" 2>/dev/null)" = "$uid" ] || run chown "$uid:$gid" "$d"
  run chmod 0750 "$d"
  if [ -n "${FLASHSTORE_DATA_DIR:-}" ]; then
    dd=$FLASHSTORE_DATA_DIR
  else
    # Match osddir::expand: known variables only, one pass, unknown names intact.
    # Do not evaluate configuration as shell code or re-expand substituted values.
    dd=$(opt osd_data "/var/lib/ceph/osd/$cluster-$id" | PREP_CLUSTER="$cluster" PREP_ID="$id" awk '
      BEGIN {v["cluster"]=ENVIRON["PREP_CLUSTER"]; v["id"]=ENVIRON["PREP_ID"]; v["type"]="osd"; v["name"]="osd." v["id"]}
      {
        s=$0; out=""
        while (match(s, /\$(\{[A-Za-z0-9_]*\}|[A-Za-z0-9_]*)/)) {
          out=out substr(s,1,RSTART-1); raw=substr(s,RSTART,RLENGTH); k=substr(raw,2)
          if (substr(k,1,1)=="{") k=substr(k,2,length(k)-2)
          out=out ((k in v) ? v[k] : raw); s=substr(s,RSTART+RLENGTH)
        }
        printf "%s%s",out,s
      }')
  fi
  # small dir (keyring, markers); recursive only when the top is not ours yet (first run after switching to non-root).
  # osd_data is configurable: a recursive chown as root only on a directory that is an OSD dir (whoami present), never
  # on a mistyped parent such as / or /var/lib.
  if [ -d "$dd" ] && [ "$(stat -c %u "$dd" 2>/dev/null)" != "$uid" ]; then
    [ -f "$dd/whoami" ] && [ ! -L "$dd/whoami" ] \
      || die "osd_data $dd is not owned by $run_user and is not an OSD dir (no whoami): check osd_data; fix: chown -R $run_user: <the OSD dir>"
    run chown -R "$uid:$gid" "$dd"
  fi
fi
log "ready"
