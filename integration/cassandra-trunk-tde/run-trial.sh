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

# The bounded Cassandra test run: build.sh --install, then, one ant invocation each, the hints
# test and the upstream tests of the code the patches change; given the keytend-kmip-server image,
# also the live dtest KmipTdeRotationTest against that server, a replica and its standby on one
# store (containers, through tools/kmip-server/run-server.sh). Not the full Cassandra suite.
#
#   integration/cassandra-trunk-tde/run-trial.sh [--server-unpinned] CASSANDRA_DIR SDK_JAR OUT \
#     [SERVER_IMAGE [VERSIONS [LEASE_STATES]]]
#
# CASSANDRA_DIR: trunk with the patches applied and `ant jar build-test` run (JDK 17). OUT must be
# empty or new: it gets PROVENANCE.txt, one log per suite and SUMMARY.txt. SERVER_IMAGE: the
# release's Docker archive (keytend-kmip-server-<version>.docker.tar) or an image already loaded
# (ID or reference); `run-server.sh image` checks it against tools/kmip-server/pinned-image.properties
# and nothing runs if it is not the pinned one, unless --server-unpinned (then PROVENANCE.txt says
# UNPINNED). VERSIONS: the KMIP versions of the dtest, default 1.4,2.1,3.0 (one cluster per
# version, in one JVM). LEASE_STATES: the server's --lease-states, default its own default
# (active-deactivated: Deactivated keys are leased too); `active` leases only Active keys. The
# KMS's Lease Time is 120 s.
set -uo pipefail
umask 077
unpinned=
if [ "${1:-}" = --server-unpinned ]; then unpinned=1; shift; fi
[ $# -ge 3 ] && [ $# -le 6 ] || { echo "usage: $0 [--server-unpinned] CASSANDRA_DIR SDK_JAR OUT [SERVER_IMAGE [VERSIONS [LEASE_STATES]]]" >&2; exit 2; }
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
cassandra=$(cd "$1" && pwd)
sdk=$(readlink -f "$2")
mkdir -p "$3"
out=$(cd "$3" && pwd)
image=${4:-}
[ -z "$image" ] || [ ! -f "$image" ] || image=$(readlink -f "$image")
versions=${5:-1.4,2.1,3.0}
lease_states=${6:-}
helper=$repo/tools/kmip-server/run-server.sh
[ -z "$(ls -A "$out")" ] || { echo "$out is not empty" >&2; exit 2; }
unset GH_TOKEN GITHUB_TOKEN KEYTEND_SERVER_IMAGE KEYTEND_SERVER_UNPINNED
if [ -n "$image" ]; then
  # exit 0: the pinned image; 10: another one, allowed only by --server-unpinned; else refused
  [ -z "$unpinned" ] || export KEYTEND_SERVER_UNPINNED=1
  rc=0; image_id=$("$helper" image "$image") || rc=$?
  if [ $rc -eq 0 ]; then pin=pinned
  elif [ $rc -eq 10 ] && [ -n "$unpinned" ]; then pin=UNPINNED
  else echo "server image $image refused (run-server.sh image exit $rc)" >&2; exit 2; fi
  # every start of either replica runs exactly this image
  export KEYTEND_SERVER_IMAGE=$image_id
  server_version=$("$helper" version) || { echo "run-server.sh version failed" >&2; exit 2; }
fi

{
  echo "date_utc=$(date -u +%FT%TZ)"
  echo "keytend-kmip_checkout=$repo head=$(git -C "$repo" rev-parse HEAD) dirty_files=$(git -C "$repo" status --porcelain | wc -l)"
  echo "sdk_jar=$sdk"
  echo "cassandra=$cassandra head=$(git -C "$cassandra" rev-parse HEAD)"
  for p in "$here"/patches/000*.patch; do
    if git -C "$cassandra" apply --reverse --check "$p" 2>/dev/null; then s=applied; else s=NOT-APPLIED; fi
    echo "patch $(basename "$p") $s"
  done
  [ -z "$image" ] || echo "server_image=$image id=$image_id $pin version=$server_version kmip=$versions lease_states=${lease_states:-default}"
  echo "java=$(${JAVA_HOME:+$JAVA_HOME/bin/}java -version 2>&1 | head -1)"
  echo "ant=$(ant -version 2>&1)"
} > "$out/PROVENANCE.txt"
cat "$out/PROVENANCE.txt"

"$here/build.sh" "$cassandra" "$sdk" --install > "$out/build.log" 2>&1 || { tail -30 "$out/build.log"; exit 1; }

unit=(
  org.apache.cassandra.hints.HintsKeyUnavailableTest
  org.apache.cassandra.security.CipherFactoryTest
  org.apache.cassandra.security.EncryptionUtilsTest
  org.apache.cassandra.security.JKSKeyProviderTest
  org.apache.cassandra.config.DatabaseDescriptorTest
  org.apache.cassandra.db.commitlog.CommitLogDescriptorTest
  org.apache.cassandra.db.commitlog.SegmentReaderTest
  org.apache.cassandra.db.commitlog.BatchCommitLogTest   # CommitLogTest's cases (it is abstract), encrypted included
  org.apache.cassandra.db.commitlog.GroupCommitLogTest
  org.apache.cassandra.db.RecoveryManagerTest
  org.apache.cassandra.hints.HintsEncryptionTest
  org.apache.cassandra.hints.HintsDescriptorTest
  org.apache.cassandra.hints.HintsReaderTest
  org.apache.cassandra.hints.HintsServiceTest
  org.apache.cassandra.hints.HintsWriteExecutorTest
  org.apache.cassandra.hints.HintsStoreTest
  org.apache.cassandra.hints.HintsCatalogTest
)

status=0
summary="$out/SUMMARY.txt"
: > "$summary"
record() { # class log rc
  echo "$1 exit=$3 $(grep -ho 'Tests run: [0-9]*, Failures: [0-9]*, Errors: [0-9]*, Skipped: [0-9]*' "$2" | tail -1)" | tee -a "$summary"
}
cd "$cassandra" || exit 1
for t in "${unit[@]}"; do
  log="$out/unit-${t##*.}.log"
  timeout 3600 ant testsome -Dtest.name="$t" > "$log" 2>&1; rc=$?
  [ $rc -eq 0 ] || status=1
  record "$t" "$log" $rc
done

if [ -n "$image" ]; then
  kms=$out/kms
  "$here/qual/server-pki.sh" "$out/pki" > "$out/pki.log" 2>&1 || { cat "$out/pki.log"; exit 1; }
  # two loopback ports, each with its health port (+1000) free too
  read -r port_a port_b < <(python3 -I - <<'PY'
import socket
found = []
while len(found) < 2:
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0)); p = s.getsockname()[1]
    if p + 1000 > 65535 or p in found: continue
    try:
        with socket.socket() as h: h.bind(('127.0.0.1', p + 1000))
    except OSError: continue
    found.append(p)
print(*found)
PY
)
  # both replicas stopped and removed however this ends (server-kms.sh stop also cleans up their prefix)
  trap '[ ! -f "$kms/pair.env" ] || "$here/qual/server-kms.sh" stop "$kms" >> "$out/kms-stop.log" 2>&1' EXIT
  "$here/qual/server-kms.sh" start "$out/pki" "$kms" "$port_a" "$port_b" 120 ${lease_states:+--lease-states "$lease_states"} \
    > "$out/kms-start.log" 2>&1 || { cat "$out/kms-start.log"; exit 1; }
  export KEYTEND_SERVER_PKI=$out/pki KEYTEND_SERVER_WORK=$kms KEYTEND_SERVER_QUAL=$here/qual \
    KEYTEND_SERVER_ENDPOINTS=localhost:$port_a,localhost:$port_b KEYTEND_SERVER_VERSIONS=$versions \
    KEYTEND_SERVER_LEASE_STATES=${lease_states:-active-deactivated}
  t=org.apache.cassandra.distributed.test.KmipTdeRotationTest
  log="$out/dtest-KmipTdeRotationTest.log"
  start=$(date +%s)
  timeout 7200 ant test-jvm-dtest-some -Dtest.name="$t" > "$log" 2>&1; rc=$?
  [ $rc -eq 0 ] || status=1
  record "$t" "$log" $rc
  echo "  ($(( $(date +%s) - start )) s, KMIP $versions)" | tee -a "$summary"
  find build/test/output -name "TEST-$t*.xml" -newer "$out/PROVENANCE.txt" -exec cp {} "$out/" \;
  mkdir -p "$out/node-logs" && cp -r build/test/logs/. "$out/node-logs/" 2>/dev/null
fi
exit $status
