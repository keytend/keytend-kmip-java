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

# Records again, on the pinned keytend-kmip-server build, the one live check a release ships as a
# recorded result (docs/releasing.md, "Recorded results"): the Cassandra trunk dtest. Run it when
# the pin moves; the packaging and the publish script refuse a recorded result of another build.
#
#   tools/record-live.sh cassandra-dtest --server DOCKER-TAR|IMAGE --cassandra DIR [--work DIR]
#
# It builds the SDK in a detached git worktree of HEAD under the work directory (default a new
# one under ${TMPDIR:-/tmp}), runs the check there on JDK 17 against the server image, which must be
# the pinned one (tools/kmip-server/run-server.sh image checks it), and replaces that check's
# entries in validation/recorded/live-server.json (tools/release_reports.py), PASS or FAIL. Commit
# the file after reading it.
#
# cassandra-dtest: integration/cassandra-trunk-tde/run-trial.sh twice, the server leasing
# Deactivated keys (its default, active-deactivated) and then Active keys only (active). DIR is
# the Cassandra checkout its README's "Build and run" prepares; when DIR does not exist, this
# script prepares it there: a clone of Apache Cassandra, trunk at CASSANDRA_TRUNK below, the
# integration's patches applied, and `ant jar build-test` (ant on the PATH).
#
# JDK 17 is JDK17_HOME, or the newest patch release of 17 SDKMAN has. Exit status: 0 when the
# check passed and was recorded, 1 when it failed (and was recorded as FAIL), 2 when nothing ran.
set -uo pipefail

CASSANDRA_TRUNK=275a3a5
CASSANDRA_REPOSITORY=https://github.com/apache/cassandra.git

root=$(cd "$(dirname "$0")/.." && pwd)
recorded=$root/validation/recorded/live-server.json
usage() {
  sed -n '20p' "$0" | sed 's/^# *//' >&2
  exit 2
}
[ $# -ge 1 ] || usage
check=$1
shift
case $check in
  cassandra-dtest) ;;
  -h|--help) sed -n '16,34p' "$0"; exit 0 ;;
  *) usage ;;
esac
server= cassandra= work=
while [ $# -gt 0 ]; do
  case $1 in
    --server) server=$2; shift 2 ;;
    --cassandra) cassandra=$2; shift 2 ;;
    --work) work=$2; shift 2 ;;
    *) echo "unknown argument $1" >&2; usage ;;
  esac
done
[ -n "$server" ] || { echo "--server: the pinned Docker archive or image" >&2; exit 2; }
if [ -z "$cassandra" ]; then
  echo "--cassandra: the Cassandra checkout (made there if it does not exist)" >&2; exit 2
fi
[ -e "$server" ] && server=$(cd "$(dirname "$server")" && pwd)/$(basename "$server")
[ -n "$work" ] || work=$(mktemp -d "${TMPDIR:-/tmp}/keytend-kmip-record.XXXXXX")
mkdir -p "$work"
work=$(cd "$work" && pwd)
[ -z "$(ls -A "$work")" ] || { echo "$work is not empty" >&2; exit 2; }

jdk=${JDK17_HOME:-}
if [ -z "$jdk" ]; then
  while IFS= read -r candidate; do
    [ -x "$candidate/bin/java" ] && jdk=$candidate
  done < <(printf '%s\n' "$HOME"/.sdkman/candidates/java/17.* | sort -V)
fi
[ -x "$jdk/bin/java" ] || { echo "Set JDK17_HOME to a JDK 17 installation" >&2; exit 2; }
export JAVA_HOME=$jdk PATH=$jdk/bin:$PATH

# The pinned image only: a recorded result of another build is refused when the release packages.
helper=$root/tools/kmip-server/run-server.sh
image=$(KEYTEND_SERVER_UNPINNED=0 "$helper" image "$server") || {
  echo "$server is not the pinned image (tools/kmip-server/pinned-image.properties)" >&2; exit 2; }
server_version=$(KEYTEND_SERVER_IMAGE=$image "$helper" version | head -1)
identity=(--server "$server_version" --image "$image" --pinned yes --jdk 17 --date "$(date -u +%F)"
  --source recorded)

# The SDK of HEAD, built in a worktree of its own (removed on exit).
commit=$(git -C "$root" rev-parse HEAD)
tree=$work/tree
git -C "$root" worktree add --detach "$tree" "$commit" >"$work/worktree.log" 2>&1 || {
  echo "cannot create the worktree $tree (see $work/worktree.log)" >&2; exit 2; }
trap 'git -C "$root" worktree remove --force "$tree" >/dev/null 2>&1 || true' EXIT
version=$(python3 -I - "$root/pom.xml" <<'PY'
import sys, xml.etree.ElementTree as E
print(E.parse(sys.argv[1]).getroot().findtext('{http://maven.apache.org/POM/4.0.0}version'))
PY
)
echo "recording $check of $commit on $server_version (image $image); work $work"
"$tree/mvnw" -B -ntp -f "$tree/pom.xml" -pl sdk,testing -am package -DskipTests \
  >"$work/build.log" 2>&1 || {
  echo "the SDK build failed (see $work/build.log)" >&2; exit 2; }
jar=$tree/sdk/target/keytend-kmip-$version.jar

status=0
# written STATUS: release_reports.py wrote the entries (0) or wrote them with a FAIL (3); else
# nothing was written.
written() {
  case $1 in 0) ;; 3) status=1 ;; *) echo "no entry was written" >&2; exit 2 ;; esac
}
case $check in
  cassandra-dtest)
    if [ ! -e "$cassandra" ]; then
      echo "preparing $cassandra: Apache Cassandra trunk $CASSANDRA_TRUNK with the patches, built"
      ( set -e
        git clone "$CASSANDRA_REPOSITORY" "$cassandra"
        git -C "$cassandra" checkout "$CASSANDRA_TRUNK"
        git -C "$cassandra" submodule update --init
        for p in "$root"/integration/cassandra-trunk-tde/patches/000*.patch; do
          git -C "$cassandra" apply "$p"
        done
        cd "$cassandra"
        ant jar build-test ) >"$work/cassandra-build.log" 2>&1 || {
        echo "preparing $cassandra failed (see $work/cassandra-build.log)" >&2; exit 2; }
    fi
    cassandra=$(cd "$cassandra" && pwd)
    trials=()
    for leases in active-deactivated active; do
      echo "the dtest under --lease-states $leases"
      "$tree/integration/cassandra-trunk-tde/run-trial.sh" "$cassandra" "$jar" "$work/tde-$leases" \
        "$image" 1.4,2.1,3.0 "$leases" >"$work/tde-$leases.log" 2>&1 || status=1
      trials+=("$work/tde-$leases")
    done
    python3 "$root/tools/release_reports.py" cassandra "$recorded" "${trials[@]}" "${identity[@]}"
    written $?
    ;;
esac
echo "validation/recorded/live-server.json updated; logs in $work. Commit the file."
exit $status
