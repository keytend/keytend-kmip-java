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

# Opt-in benchmark (see README.md here): compiles Bench.java against the SDK jar, then runs it
# in-process, against the in-memory server behind loopback TLS, and (topology live) against two
# keytend-kmip-server containers with independent stores, once per KMIP version. The containers
# run the pinned image through tools/kmip-server/run-server.sh (KEYTEND_SERVER_IMAGE and
# KEYTEND_SERVER_UNPINNED=1 run another one; the caller's KMIP_* variables reach the servers).
#
#   tools/bench/run.sh [--jar sdk/target/keytend-kmip-X.Y.Z.jar]
#       [--testing-jar testing/target/keytend-kmip-testing-X.Y.Z.jar]
#       [--topologies "inmemory inmemory-tls live"] [--versions "2.1 1.4 3.0"] [--scale 1]
#       [--scenarios all|pinned,miss,...,localkeys,tls-handshake,chunked,movename,failover]
#       [--localkeys-threads 1,4,16,64]
#       [--work /tmp/dir]
#
# Exit status: 0 when every run finished, 1 otherwise.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
server=$repo/tools/kmip-server/run-server.sh
jar=
testing_jar=
topologies=
versions="2.1"
scale=1
scenarios=all
localkeys_threads=1,4,16,64
work=
java=${JAVA:-java}
while [ $# -gt 0 ]; do
  case $1 in
    --jar) jar=$2; shift 2 ;;
    --testing-jar) testing_jar=$2; shift 2 ;;
    --topologies) topologies=$2; shift 2 ;;
    --versions) versions=$2; shift 2 ;;
    --scale) scale=$2; shift 2 ;;
    --scenarios) scenarios=$2; shift 2 ;;
    --localkeys-threads) localkeys_threads=$2; shift 2 ;;
    --work) work=$2; shift 2 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
if [ -z "$jar" ]; then
  jar=$(ls "$repo"/sdk/target/keytend-kmip-*.jar 2>/dev/null | grep -v -e '-tests.jar' -e '-sources.jar' -e '-javadoc.jar' | head -1 || true)
fi
[ -n "$jar" ] && [ -f "$jar" ] || { echo "--jar: the SDK jar (./mvnw -pl sdk -am package -DskipTests)" >&2; exit 2; }
jar=$(cd "$(dirname "$jar")" && pwd)/$(basename "$jar")
# The SDK's runtime dependency, slf4j-api, from beside the JAR (a release ZIP's lib/) or from lib/
# beside it (sdk/target/lib/, which ./mvnw package fills).
deps=$(ls "$(dirname "$jar")"/slf4j-api-*.jar "$(dirname "$jar")"/lib/slf4j-api-*.jar 2>/dev/null | head -1 || true)
[ -n "$deps" ] || { echo "no slf4j-api JAR beside $jar or in its lib/ (./mvnw -pl sdk -am package -DskipTests)" >&2; exit 2; }
# The in-memory server (keytend-kmip-testing, a test artifact, not in a release ZIP's lib/): the one
# this repository built for the SDK JAR's version unless --testing-jar names another.
if [ -z "$testing_jar" ]; then
  version=$(basename "$jar" .jar)
  testing_jar=$repo/testing/target/keytend-kmip-testing-${version#keytend-kmip-}.jar
fi
[ -f "$testing_jar" ] || { echo "--testing-jar: no keytend-kmip-testing JAR at $testing_jar (./mvnw -pl sdk,testing -am package -DskipTests)" >&2; exit 2; }
cp=$jar:$deps:$testing_jar
[ -n "$topologies" ] || topologies="inmemory inmemory-tls"
live=
case " $topologies " in *" live "*) live=1 ;; esac
if [ -n "$live" ]; then
  # The server image: pinned (exit 0), or another one allowed by KEYTEND_SERVER_UNPINNED=1 (10).
  set +e
  image_id=$("$server" image)
  image_status=$?
  set -e
  case $image_status in
    0) image_pin=pinned ;;
    10) image_pin=UNPINNED ;;
    *) echo "the keytend-kmip-server image is refused (run-server.sh image exit $image_status)" >&2; exit 2 ;;
  esac
fi
[ -n "$work" ] || work=$(mktemp -d /tmp/keytend-kmip-bench.XXXXXX)
mkdir -p "$work"
work=$(cd "$work" && pwd)

echo "jar    $jar"
if [ -n "$live" ]; then
  echo "server $("$server" version), image $image_id ($image_pin)"
  echo "kmip_env $(env | grep '^KMIP_' | sort | paste -sd' ' || true)"
fi
echo "java   $(command -v "$java") ($("$java" -version 2>&1 | head -1))"
echo "work   $work"

# Test-only PKI: CA, server certificate for 127.0.0.1, two client certificates (the reload scenario
# switches between them) that the policy maps to one principal (as a renewed certificate is)
# allowed every operation. The server's files have the names run-server.sh's --pki takes.
pki=$work/pki
if [ ! -f "$pki/policy.json" ]; then
  mkdir -p "$pki"
  ( umask 077
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$pki/ca.key" -out "$pki/ca.pem" -days 2 \
      -subj /CN=keytend-kmip-bench-test-ca -addext basicConstraints=critical,CA:TRUE \
      -addext keyUsage=critical,keyCertSign,cRLSign >/dev/null 2>&1
    printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n' > "$pki/server.ext"
    printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n' > "$pki/client.ext"
    for name in server client client2; do
      ext=$name; [ "$name" = client2 ] && ext=client
      openssl req -new -newkey rsa:2048 -nodes -keyout "$pki/$name.key" -out "$pki/$name.csr" -subj "/CN=$name" >/dev/null 2>&1
      openssl x509 -req -in "$pki/$name.csr" -CA "$pki/ca.pem" -CAkey "$pki/ca.key" -CAcreateserial \
        -out "$pki/$name.pem" -days 2 -extfile "$pki/$ext.ext" >/dev/null 2>&1
    done
    python3 -I - "$pki" <<'PY'
import hashlib,json,pathlib,ssl,sys
p=pathlib.Path(sys.argv[1])
def der(n): return hashlib.sha256(ssl.PEM_cert_to_DER_cert((p/(n+'.pem')).read_text())).hexdigest()
ops=list(range(1,67))
(p/'policy.json').write_text(json.dumps({'principals':{der('client'):{'name':'bench','operations':ops},
  der('client2'):{'name':'bench','operations':ops}}},indent=2)+'\n')
PY
  )
fi

classes=$work/classes
mkdir -p "$classes"
javac -d "$classes" -cp "$cp" "$here/Bench.java"
jvm=(-Xms1g -Xmx1g -XX:+UseG1GC)

# The live servers are containers named $prefix<version>-<n>; every one this run started is removed
# on exit or interrupt.
prefix=keytend-bench-$$-
trap '"$server" cleanup "$prefix"' EXIT
trap 'exit 130' INT TERM

# Starts container $1, a keytend-kmip-server replica with its store in directory $2 and its log
# $3; sets started_port. KMIP 3.0 (the CSD02 draft) is offered only with --experimental-v3.
start_server() {
  local name=$1 data=$2 log=$3 out extra=()
  started_port=
  [ "${version:-}" = 3.0 ] && extra=(--experimental-v3)
  mkdir -p "$data"
  out=$("$server" start "$name" --data "$data" --pki "$pki" --log "$log" -- ${extra[@]+"${extra[@]}"}) \
    || { echo "server $name did not start; see $log" >&2; return 1; }
  started_port=$(printf '%s\n' "$out" | sed -n 's/^port=\([0-9]*\) .*/\1/p')
  [ -n "$started_port" ] || { echo "no port from run-server.sh: $out" >&2; return 1; }
}

status=0
for topology in $topologies; do
  if [ "$topology" != live ]; then
    log=$work/$topology.log
    set +e
    "$java" "${jvm[@]}" -cp "$classes:$cp" Bench --topology "$topology" --pki "$pki" --scale "$scale" \
      --scenarios "$scenarios" --localkeys-threads "$localkeys_threads" --work "$work" 2>&1 | tee "$log"
    [ "${PIPESTATUS[0]}" = 0 ] || status=1
    set -e
    continue
  fi
  [ -f "$pki/master.key" ] || "$server" master-key "$pki/master.key"
  for version in $versions; do
    dir=$work/live-v$version
    rm -rf "$dir"; mkdir -p "$dir"
    # Two servers, each with its own SQLite store: keytend-kmip-server is a single-server design
    # (its docs/deployment.md: more replicas are not an HA configuration).
    name1=$prefix$version-1 name2=$prefix$version-2
    start_server "$name1" "$dir/store-1" "$dir/server-1.log" || { "$server" cleanup "$prefix"; status=1; continue; }
    port1=$started_port
    start_server "$name2" "$dir/store-2" "$dir/server-2.log" || { "$server" cleanup "$prefix"; status=1; continue; }
    port2=$started_port
    echo "servers: 127.0.0.1:$port1 ($name1), 127.0.0.1:$port2 ($name2), independent stores in $dir/store-{1,2}"
    set +e
    "$java" "${jvm[@]}" -cp "$classes:$cp" Bench --topology live --version "$version" --pki "$pki" \
      --endpoints "127.0.0.1:$port1,127.0.0.1:$port2" --kill-command "$(printf '%q ' "$server" stop "$name1")" \
      --scale "$scale" --scenarios "$scenarios" --localkeys-threads "$localkeys_threads" --work "$work" 2>&1 \
      | tee "$dir/bench.log"
    [ "${PIPESTATUS[0]}" = 0 ] || status=1
    set -e
    "$server" stop "$name1" "$name2"
  done
done
echo "logs: $work/*.log, $work/live-v*/bench.log (server logs next to it)"
exit $status
