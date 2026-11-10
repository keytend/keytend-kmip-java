#!/usr/bin/env bash
# Copyright 2026 Jeremiah Jordan
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Two keytend-kmip-server containers, replicas A and B of one KMS: one SQLite store (STATE/kmip.sqlite),
# one master key, one policy, on two fixed loopback ports (the health listener of each on its port
# + 1000). The server locks its store, so only one replica runs at a time: `start` starts A, and B
# is the standby that takes the store over once A is down (start-b). Killing one is an outage of
# that replica; starting it again is a recovery of the same store on the same address. Every
# container is started, stopped and killed by the shared helper, tools/kmip-server/run-server.sh
# (the pinned image, podman).
#
#   qual/server-kms.sh start PKI STATE PORT_A PORT_B MAX_LEASE_SECONDS [SERVE-OPTION...]
#   qual/server-kms.sh start-a|start-b STATE   start that replica, as configured by `start`, once the
#                                              other is down
#   qual/server-kms.sh kill-a|kill-b STATE     SIGKILL that replica: its connections drop
#   qual/server-kms.sh stop STATE              stop both (SIGTERM, SIGKILL after 2 s)
#
# PKI: a directory from qual/server-pki.sh (server.pem, server.key, ca.pem, policy.json,
# master.key). MAX_LEASE_SECONDS is --max-lease-seconds: every object the server creates states it
# as its Lease Time. KMIP 3.0 is the server's --experimental-v3. SERVE-OPTIONs (for example
# `--lease-states active`) are passed to every start of both replicas. `start` records the image's
# ID, so a replica started again runs the same image whatever the caller's environment. The
# containers are named <prefix>-a and <prefix>-b, the prefix derived from STATE (in
# STATE/pair.env), so pairs of different state directories never meet; `stop` removes both.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
helper=$here/../../../tools/kmip-server/run-server.sh
cmd=${1:-}
case "$cmd" in
  start)
    [ $# -ge 6 ] || { echo "usage: $0 start PKI STATE PORT_A PORT_B MAX_LEASE_SECONDS [SERVE-OPTION...]" >&2; exit 2; }
    pki=$(readlink -f "$2")
    state=$(realpath -m "$3")
    mkdir -p "$state"
    [ ! -f "$state/pair.env" ] || { echo "$state/pair.env exists: one pair per state directory" >&2; exit 2; }
    # the image the pair runs, verified against the pin (exit 10: unpinned, allowed by KEYTEND_SERVER_UNPINNED=1)
    rc=0; image=$("$helper" image) || rc=$?
    [ $rc -eq 0 ] || [ $rc -eq 10 ] || exit 1
    prefix=kt-trunk-tde-$(printf '%s' "$state" | sha256sum | cut -c1-12)
    { echo "pki=$pki"; echo "port_a=$4"; echo "port_b=$5"; echo "lease=$6"; echo "image=$image"
      echo "unpinned=$([ $rc -eq 10 ] && echo 1 || echo 0)"; echo "prefix=$prefix"
      for o in "${@:7}"; do echo "option=$o"; done; } > "$state/pair.env" ;;
  start-a|start-b|kill-a|kill-b|stop)
    [ $# -eq 2 ] || { echo "usage: $0 $cmd STATE" >&2; exit 2; }
    state=$(realpath -m "$2") ;;
  *) echo "usage: $0 start ... | start-a|start-b|kill-a|kill-b|stop STATE" >&2; exit 2 ;;
esac
[ -f "$state/pair.env" ] || { echo "no $state/pair.env: run start first" >&2; exit 2; }
setting() { sed -n "s/^$1=//p" "$state/pair.env"; }
pki=$(setting pki)
lease=$(setting lease)
prefix=$(setting prefix)
mapfile -t options < <(setting option)
export KEYTEND_SERVER_IMAGE
KEYTEND_SERVER_IMAGE=$(setting image)
[ "$(setting unpinned)" != 1 ] || export KEYTEND_SERVER_UNPINNED=1
event() { echo "$(date -u +%FT%T.%3NZ) $*" >> "$state/kms-events.log"; }

start_one() {
  local replica=$1 port
  port=$(setting "port_$replica")
  event "start $replica port=$port max-lease=$lease options=${options[*]:-} container=$prefix-$replica"
  "$helper" start "$prefix-$replica" --data "$state" --pki "$pki" --port "$port" --health-port "$((port + 1000))" \
    --log "$state/server-$replica.log" -- --experimental-v3 --max-lease-seconds "$lease" ${options[@]+"${options[@]}"} \
    || { echo "replica $replica did not start; see $state/server-$replica.log" >&2; return 1; }
}

signal_one() {
  local replica=$1 how=$2
  "$helper" running "$prefix-$replica" || return 0
  event "$how $replica container=$prefix-$replica"
  "$helper" "$how" "$prefix-$replica"
}

case "$cmd" in
  start) start_one a ;; # B is the standby: a second server on the store exits (the store is locked)
  start-a) start_one a ;;
  start-b) start_one b ;;
  kill-a) signal_one a kill ;;
  kill-b) signal_one b kill ;;
  stop) signal_one a stop; signal_one b stop; "$helper" cleanup "$prefix-" ;;
esac
