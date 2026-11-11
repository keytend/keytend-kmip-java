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

# Opt-in live probe (see README.md here): for each KMIP version, starts keytend-kmip-server from the
# pinned image (tools/kmip-server/run-server.sh) on a fresh store and free ports, runs ServerProbe
# against it with the given SDK jar, and removes the container.
#
#   tools/server-probe/run.sh [--jar sdk/target/keytend-kmip-X.Y.Z.jar]
#       [--versions "1.1 1.2 1.4 2.1 3.0"] [--scenarios all|...,tls] [--work /tmp/dir]
#
# The image is tools/kmip-server/pinned-image.properties's, or KEYTEND_SERVER_IMAGE (refused unless
# pinned, or KEYTEND_SERVER_UNPINNED=1). KMIP_* variables of the environment reach the server, so
# KMIP_DESTROYED_NAME_REUSE=reserve runs it under that policy.
#
# Exit status: 0 when every version's probe reported no FAIL, 1 otherwise.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
server=$repo/tools/kmip-server/run-server.sh
jar=
versions="1.1 1.2 1.4 2.1 3.0"
scenarios=all
work=
while [ $# -gt 0 ]; do
  case $1 in
    --jar) jar=$2; shift 2 ;;
    --versions) versions=$2; shift 2 ;;
    --scenarios) scenarios=$2; shift 2 ;;
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
cp=$jar:$deps
image=$("$server" image) || { code=$?; [ "$code" = 10 ] || exit 2; }
[ -n "$work" ] || work=$(mktemp -d /tmp/server-probe.XXXXXX)
mkdir -p "$work"
work=$(cd "$work" && pwd)

echo "server $("$server" version) image $image"
echo "jar    $jar"
echo "work   $work"
env | grep '^KMIP_' | sed 's/^/env    /' || true

# Test-only PKI: CA, server certificate for 127.0.0.1, one client certificate whose principal may
# call every operation, and a master key. Only the server's files are mounted into the container.
pki=$work/pki
if [ ! -f "$pki/policy.json" ]; then
  mkdir -p "$pki"
  ( umask 077
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$pki/ca.key" -out "$pki/ca.pem" -days 2 \
      -subj /CN=server-probe-test-ca -addext basicConstraints=critical,CA:TRUE \
      -addext keyUsage=critical,keyCertSign,cRLSign >/dev/null 2>&1
    printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n' > "$pki/server.ext"
    printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n' > "$pki/client.ext"
    for name in server client; do
      openssl req -new -newkey rsa:2048 -nodes -keyout "$pki/$name.key" -out "$pki/$name.csr" -subj "/CN=$name" >/dev/null 2>&1
      openssl x509 -req -in "$pki/$name.csr" -CA "$pki/ca.pem" -CAkey "$pki/ca.key" -CAcreateserial \
        -out "$pki/$name.pem" -days 2 -extfile "$pki/$name.ext" >/dev/null 2>&1
    done
    python3 -I - "$pki" <<'PYEOF'
import hashlib,json,pathlib,ssl,sys
p=pathlib.Path(sys.argv[1])
der=hashlib.sha256(ssl.PEM_cert_to_DER_cert((p/'client.pem').read_text())).hexdigest()
(p/'policy.json').write_text(json.dumps({'principals':{der:{'name':'probe','operations':list(range(1,67))}}},indent=2)+'\n')
PYEOF
    "$server" master-key "$pki/master.key"
  )
fi

classes=$work/classes
mkdir -p "$classes"
javac -d "$classes" -cp "$cp" "$here/ServerProbe.java"

prefix=server-probe-$$-
trap '"$server" cleanup "$prefix"' EXIT INT TERM

status=0
for version in $versions; do
  dir=$work/v$version
  rm -rf "$dir"; mkdir -p "$dir"
  name=${prefix}v$version
  if ! ports=$("$server" start "$name" --pki "$pki" --data "$dir" --log "$dir/server.log" -- --experimental-v3); then
    echo "server for $version did not start; see $dir/server.log" >&2; status=1; continue
  fi
  port=$(echo "$ports" | sed -n 's/^port=\([0-9]*\).*/\1/p')
  set +e
  java -cp "$classes:$cp" ServerProbe --endpoint "127.0.0.1:$port" --version "$version" --pki "$pki" \
    --scenarios "$scenarios" 2>&1 | tee "$dir/probe.log"
  code=${PIPESTATUS[0]}
  set -e
  [ "$code" = 0 ] || status=1
  "$server" stop "$name"
done
echo
grep -h '^SUMMARY' "$work"/v*/probe.log || true
echo "logs: $work/v*/probe.log, server logs: $work/v*/server.log"
exit $status
