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

set -euo pipefail
# Finite local work, with immutable candidate JARs and isolated disposable servers.
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
duration=${1:-PT24H}
run_dir=${2:-"$root/.cache/soak-$(date -u +%Y%m%dT%H%M%SZ)"}
mkdir -p "$run_dir"
run_dir=$(cd "$run_dir" && pwd)
container_engine=${CONTAINER_ENGINE:-podman}
java_bin=${JAVA_HOME:+"$JAVA_HOME/bin/"}java
# The version the build gives the JARs, so that a version bump needs no edit here.
version=$(python3 -I -c 'import sys, xml.etree.ElementTree as E; print(E.parse(sys.argv[1]).getroot().find("{http://maven.apache.org/POM/4.0.0}version").text)' pom.xml)
cp "sdk/target/keytend-kmip-$version.jar" "$run_dir/sdk.jar"
cp "integration-tests/target/keytend-kmip-integration-$version.jar" "$run_dir/integration.jar"
# The integration JAR's manifest names its runtime JARs (the SDK, slf4j-api, jackson-core,
# slf4j-simple) in lib/ beside it.
mkdir -p "$run_dir/lib"
cp integration-tests/target/lib/*.jar "$run_dir/lib/"
./integration/catalog/generate-pki.sh "$run_dir/certs" > "$run_dir/pki.log" 2>&1
client_commit=$(git rev-parse HEAD)
python3 - "$run_dir" "$duration" "$client_commit" <<'PYMETA'
import datetime, hashlib, json, pathlib, sys
folder = pathlib.Path(sys.argv[1])
metadata = {'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'requested_duration': sys.argv[2], 'client_commit': sys.argv[3],
            'candidate_artifacts': {name: hashlib.sha256((folder/name).read_bytes()).hexdigest()
                                    for name in ['sdk.jar', 'integration.jar']}}
(folder/'candidate.json').write_text(json.dumps(metadata, indent=2) + '\n')
PYMETA
py_container="keytend-soak-$$-py"
py_pid=
cleanup() {
  local exit_code=$?
  trap - EXIT TERM INT
  python3 - "$run_dir" "$exit_code" <<'PYSTATUS'
import datetime, json, pathlib, sys
folder = pathlib.Path(sys.argv[1])
code = int(sys.argv[2])
(folder/'run-status.json').write_text(json.dumps({'status': 'COMPLETED' if code == 0 else 'FAILED_OR_INTERRUPTED', 'exit_code': code, 'finished_at': datetime.datetime.now(datetime.timezone.utc).isoformat()}, indent=2) + '\n')
PYSTATUS
  if [[ -n "$py_pid" ]]; then kill "$py_pid" 2>/dev/null || true; fi
  "$container_engine" rm -f "$py_container" > "$run_dir/container-cleanup.log" 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' TERM INT
"$container_engine" image exists localhost/keytend-pykmip:catalog ||
  "$container_engine" build -t localhost/keytend-pykmip:catalog integration/pykmip > "$run_dir/build-pykmip.log" 2>&1
"$container_engine" run -d --name "$py_container" -p 127.0.0.1::5696 -v "$run_dir/certs:/certs:ro" localhost/keytend-pykmip:catalog > "$run_dir/py-container-id"
py_port=$("$container_engine" port "$py_container" 5696 | sed 's/.*://')
python3 - "$run_dir/certs" "$py_port" <<'PY'
import pathlib, socket, ssl, sys, time
certs = pathlib.Path(sys.argv[1])
context = ssl.create_default_context(cafile=str(certs/'ca.pem'))
context.load_cert_chain(str(certs/'client.pem'), str(certs/'client-key.pem'))
for port in sys.argv[2:]:
    deadline = time.monotonic() + 30
    while True:
        try:
            with socket.create_connection(('localhost', int(port)), timeout=2) as tcp:
                with context.wrap_socket(tcp, server_hostname='localhost'):
                    break
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(.1)
PY
launch() {
  local profile=$1 port=$2 version=$3 build=$4
  local image config_hash
  image=$("$container_engine" image inspect --format '{{.Id}}' "localhost/keytend-$profile:catalog")
  if [[ "$image" != sha256:* ]]; then image="sha256:$image"; fi
  config_hash=$(python3 - "$profile" <<'PY'
import hashlib, pathlib, sys
folder = pathlib.Path('integration') / sys.argv[1]
digest = hashlib.sha256()
for path in sorted(p for p in folder.rglob('*') if p.is_file()):
    digest.update(str(path.relative_to(folder)).encode())
    digest.update(path.read_bytes())
print(digest.hexdigest())
PY
)
  exec "$java_bin" -Dkmip.client.commit="$client_commit" -Dkmip.server.build="$build" \
    -Dkmip.server.image="$image" -Dkmip.server.configurationHash="$config_hash" \
    -cp "$run_dir/integration.jar" dev.keytend.kmip.interop.CatalogSoak \
    localhost "$port" "$run_dir/certs" "$profile" "$version" "$duration" "$run_dir/$profile.json" \
    > "$run_dir/$profile.log" 2>&1
}
launch pykmip "$py_port" 1.4 481563735cc96eb9f7b363df3c24b2ea68b9353f &
py_pid=$!
printf '%s\n' "$py_pid" > "$run_dir/py.pid"
status=0
wait "$py_pid" || status=$?
py_pid=
printf 'pykmip=%s\n' "$status" > "$run_dir/exit-status"
exit "$status"
