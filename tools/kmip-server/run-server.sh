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

# The one place the live tools run keytend-kmip-server: the pinned container image
# (pinned-image.properties here), with podman (see README.md here).
#
#   run-server.sh image [DOCKER-TAR|IMAGE]   verify the image (a Docker archive: its SHA-256, then
#                                            load it and check the loaded ID); print its ID
#   run-server.sh version                    the image's --version
#   run-server.sh master-key FILE            a new master key, by the image's generate-master-key
#   run-server.sh start NAME --data DIR (--pki DIR | --cert F --key F --ca F --policy F --master-key F)
#       [--users F] [--validation-ca F] [--provisioning-ca F --provisioning-ca-key F]
#       [--port P] [--health-port P] [--log FILE] [-- SERVE-OPTION...]
#                                            start container NAME; wait until /readyz answers 200;
#                                            print "port=P health=P" (the host ports)
#   run-server.sh stop NAME...               SIGTERM, SIGKILL after 2 s; wait until it is removed
#   run-server.sh kill NAME...               SIGKILL at once (an outage); wait until it is removed
#   run-server.sh running NAME               exit 0 if container NAME is running, 1 if not
#   run-server.sh cleanup PREFIX             remove every container this helper started whose name
#                                            starts with PREFIX (for traps; never fails)
#
# The image: KEYTEND_SERVER_IMAGE (an image ID or reference), else the pin's `image`. Its ID must
# be the pin's `image_id`, and a Docker archive's SHA-256 the pin's `archive_sha256`, unless
# KEYTEND_SERVER_UNPINNED=1: then another image runs, with a warning, and `image` exits 10 instead
# of 0 (release-check.sh records that as UNPIN). Any other non-zero exit is a refusal or a failure.
#
# `start` runs `serve` with the TLS files, policy and master key each mounted read-only (with
# --pki DIR: DIR/server.pem, server.key, ca.pem, policy.json and master.key; the options name
# other files), the store at /data/kmip.sqlite in DIR (--data, which must exist and be owned by
# the caller: the container runs as UID 10001, which --userns keep-id maps to the caller), a
# read-only root and a /tmp tmpfs. KMIP and health ports go to 127.0.0.1 on the given host ports,
# or on free ones podman picks. The SERVE-OPTIONs (such as --experimental-v3 or
# --max-lease-seconds 30; none is added by default) follow the fixed ones; every KMIP_* variable
# of the caller's environment is passed to the container too. The server locks its store: a second
# container given the same --data exits at startup, so integration/cassandra-trunk-tde/qual starts
# its standby replica only once the other is down. The container's output is appended to --log
# (default DIR/server-NAME.log). Containers are started with --rm, so a stopped, killed or crashed
# server leaves nothing behind; `cleanup` removes the running ones.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
pin=$here/pinned-image.properties
podman=${PODMAN:-podman}
label=dev.keytend.kmip.server-helper
userns=keep-id:uid=10001,gid=10001

die() { echo "run-server.sh: $*" >&2; exit "${code:-1}"; }
pinned() { sed -n "s/^$1=//p" "$pin"; }
unpinned() { [ "${KEYTEND_SERVER_UNPINNED:-}" = 1 ]; }
image_id_of() { "$podman" image inspect --format '{{.Id}}' "$1" 2>/dev/null | head -1; }

# The ID of the image to run: KEYTEND_SERVER_IMAGE or the pin's, refused unless pinned or allowed.
resolve_image() {
  local ref=${KEYTEND_SERVER_IMAGE:-$(pinned image)} id want
  want=$(pinned image_id)
  id=$(image_id_of "$ref") || true
  [ -n "$id" ] || die "image $ref is not loaded: run $0 image <the release's docker tar>"
  if [ "$id" != "$want" ]; then
    unpinned || code=3 die "image $ref has ID $id, not the pinned $(pinned image) ($want); set KEYTEND_SERVER_UNPINNED=1 to run it anyway"
    echo "run-server.sh: WARNING: image $ref ($id) is NOT the pinned $(pinned name) $(pinned version)" >&2
  fi
  echo "$id"
}

cmd_image() {
  local arg=${1:-} sha id ref out want_sha want_id status=0
  want_sha=$(pinned archive_sha256) want_id=$(pinned image_id)
  if [ -n "$arg" ] && [ -f "$arg" ]; then
    sha=$(sha256sum "$arg" | cut -d' ' -f1)
    if [ "$sha" != "$want_sha" ]; then
      unpinned || code=3 die "$arg has SHA-256 $sha, not the pinned archive's $want_sha"
      echo "run-server.sh: WARNING: $arg ($sha) is NOT the pinned archive" >&2
      status=10
    fi
    out=$("$podman" load -i "$arg" 2>&1) || die "podman load -i $arg failed: $out"
    ref=$(printf '%s\n' "$out" | sed -n 's/^Loaded image[^:]*: *//p' | tail -1)
    [ -n "$ref" ] || die "cannot tell which image $arg loaded: $out"
    id=$(image_id_of "$ref")
    if [ "$status" = 0 ] && [ "$id" != "$want_id" ]; then
      code=3 die "$arg is the pinned archive but loaded $ref with ID $id, not $want_id"
    fi
  else
    ref=${arg:-${KEYTEND_SERVER_IMAGE:-$(pinned image)}}
    id=$(image_id_of "$ref") || true
    [ -n "$id" ] || die "image $ref is not loaded (give the Docker archive instead)"
    if [ "$id" != "$want_id" ]; then
      unpinned || code=3 die "image $ref has ID $id, not the pinned $want_id"
      echo "run-server.sh: WARNING: image $ref ($id) is NOT the pinned image" >&2
      status=10
    fi
  fi
  echo "$id"
  return $status
}

cmd_version() {
  local id
  id=$(resolve_image)
  "$podman" run --rm --network none "$id" --version
}

cmd_master_key() {
  local file=${1:?master-key FILE} dir base id
  [ ! -e "$file" ] || die "$file exists"
  dir=$(cd "$(dirname "$file")" && pwd) base=$(basename "$file")
  id=$(resolve_image)
  "$podman" run --rm --network none --read-only --userns "$userns" --label "$label=1" \
    -v "$dir:/out" "$id" generate-master-key --output "/out/$base" >/dev/null
  chmod 600 "$file"
}

exists() { "$podman" container exists "$1" 2>/dev/null; }
is_running() { [ "$("$podman" container inspect --format '{{.State.Running}}' "$1" 2>/dev/null)" = true ]; }
host_port() { "$podman" port "$1" "$2/tcp" 2>/dev/null | head -1 | sed 's/.*://'; }

# Waits until container $1 is gone (--rm removes it once it has exited).
gone() {
  local _
  for _ in $(seq 1 100); do exists "$1" || return 0; sleep 0.1; done
  "$podman" rm -f -t 0 "$1" >/dev/null 2>&1 || true
  ! exists "$1" || die "container $1 was not removed"
}

ready() { # PORT: /readyz answers 200
  python3 -I -c '
import sys, urllib.request
try:
    sys.exit(0 if urllib.request.urlopen("http://127.0.0.1:%s/readyz" % sys.argv[1], timeout=1).status == 200 else 1)
except Exception:
    sys.exit(1)' "$1"
}

# The start option that sets variable $1 of cmd_start.
option_of() {
  case $1 in
    master) echo --master-key ;;
    validation) echo --validation-ca ;;
    provisioning) echo --provisioning-ca ;;
    provisioning_key) echo --provisioning-ca-key ;;
    *) echo "--$1" ;;
  esac
}

cmd_start() {
  local name=${1:?start NAME ...}; shift
  local data= pki= cert= key= ca= policy= master= users= validation= port= health= log=
  local provisioning= provisioning_key=
  while [ $# -gt 0 ]; do
    case $1 in
      --data) data=$2; shift 2 ;;
      --pki) pki=$2; shift 2 ;;
      --cert) cert=$2; shift 2 ;;
      --key) key=$2; shift 2 ;;
      --ca) ca=$2; shift 2 ;;
      --policy) policy=$2; shift 2 ;;
      --master-key) master=$2; shift 2 ;;
      --users) users=$2; shift 2 ;;
      --validation-ca) validation=$2; shift 2 ;;
      --provisioning-ca) provisioning=$2; shift 2 ;;
      --provisioning-ca-key) provisioning_key=$2; shift 2 ;;
      --port) port=$2; shift 2 ;;
      --health-port) health=$2; shift 2 ;;
      --log) log=$2; shift 2 ;;
      --) shift; break ;;
      *) die "start: unknown option $1" ;;
    esac
  done
  [ -n "$data" ] && [ -d "$data" ] || die "start: --data DIR (an existing directory)"
  data=$(cd "$data" && pwd)
  if [ -n "$pki" ]; then
    cert=${cert:-$pki/server.pem} key=${key:-$pki/server.key} ca=${ca:-$pki/ca.pem}
    policy=${policy:-$pki/policy.json} master=${master:-$pki/master.key}
  fi
  local mounts=() f
  if { [ -n "$provisioning" ] && [ -z "$provisioning_key" ]; } \
    || { [ -z "$provisioning" ] && [ -n "$provisioning_key" ]; }; then
    die "start: --provisioning-ca and --provisioning-ca-key go together"
  fi
  for f in cert key ca policy master users validation provisioning provisioning_key; do
    [ -n "${!f}" ] || continue
    [ -f "${!f}" ] || die "start: $(option_of "$f") ${!f} is not a file"
    mounts+=(-v "$(readlink -f "${!f}"):/run/kmip/$f:ro")
  done
  [ -n "$cert" ] && [ -n "$key" ] && [ -n "$ca" ] && [ -n "$policy" ] && [ -n "$master" ] \
    || die "start: the server certificate, key, CA, policy and master key (--pki DIR, or each option)"
  local extra=()
  [ -z "$users" ] || extra+=(--users /run/kmip/users)
  [ -z "$validation" ] || extra+=(--validation-ca /run/kmip/validation)
  [ -z "$provisioning" ] \
    || extra+=(--provisioning-ca /run/kmip/provisioning --provisioning-ca-key /run/kmip/provisioning_key)
  local env=() v
  for v in $(compgen -e); do case $v in KMIP_*) env+=(--env "$v") ;; esac; done
  log=${log:-$data/server-$name.log}
  local id
  id=$(resolve_image)
  if exists "$name"; then
    is_running "$name" && die "container $name is already running"
    gone "$name"
  fi
  local run=("$podman" run --rm --name "$name" --label "$label=1" --userns "$userns"
    --read-only --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777
    --cap-drop=ALL --security-opt=no-new-privileges
    -p "127.0.0.1:${port}:5696" -p "127.0.0.1:${health}:8080"
    "${mounts[@]}" -v "$data:/data" ${env[@]+"${env[@]}"} "$id"
    serve --listen 0.0.0.0:5696 --health-listen 0.0.0.0:8080
    --cert /run/kmip/cert --key /run/kmip/key --ca /run/kmip/ca --policy /run/kmip/policy
    --master-key /run/kmip/master --database /data/kmip.sqlite ${extra[@]+"${extra[@]}"} "$@")
  echo "$(date -u +%FT%T.%3NZ) run-server.sh start: ${run[*]}" >>"$log"
  setsid "${run[@]}" >>"$log" 2>&1 </dev/null &
  local client=$! _ p= h=
  for _ in $(seq 1 300); do
    if is_running "$name"; then
      [ -n "$p" ] || p=$(host_port "$name" 5696)
      [ -n "$h" ] || h=$(host_port "$name" 8080)
      if [ -n "$h" ] && ready "$h"; then echo "port=$p health=$h"; return 0; fi
    elif ! kill -0 "$client" 2>/dev/null; then
      tail -20 "$log" >&2
      die "container $name exited during startup; see $log"
    fi
    sleep 0.1
  done
  "$podman" rm -f -t 0 "$name" >/dev/null 2>&1 || true
  die "container $name did not become ready in 30 s; see $log"
}

cmd_stop() {
  local name how=$1; shift
  for name in "$@"; do
    exists "$name" || continue
    if [ "$how" = kill ]; then "$podman" kill "$name" >/dev/null 2>&1 || true
    else "$podman" stop -t 2 "$name" >/dev/null 2>&1 || true; fi
    gone "$name"
  done
}

cmd_cleanup() {
  local prefix=${1:?cleanup PREFIX} name
  for name in $("$podman" ps -a --filter "label=$label" --format '{{.Names}}' 2>/dev/null); do
    case $name in "$prefix"*) "$podman" rm -f -t 0 "$name" >/dev/null 2>&1 || true ;; esac
  done
  return 0
}

[ -f "$pin" ] || die "no $pin"
command -v "$podman" >/dev/null || die "podman is not installed (PODMAN names another)"
sub=${1:-}; [ $# -eq 0 ] || shift
case $sub in
  image) cmd_image "$@" ;;
  version) cmd_version ;;
  master-key) cmd_master_key "$@" ;;
  start) cmd_start "$@" ;;
  stop) cmd_stop stop "$@" ;;
  kill) cmd_stop kill "$@" ;;
  running) is_running "${1:?running NAME}" ;;
  cleanup) cmd_cleanup "$@" ;;
  -h|--help|'') sed -n '16,49p' "$0" ;;
  *) die "unknown command $sub (image, version, master-key, start, stop, kill, running, cleanup)" ;;
esac
