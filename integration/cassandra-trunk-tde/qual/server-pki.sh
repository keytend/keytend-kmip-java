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

# Throwaway mTLS PKI and keytend-kmip-server policy for the commit log and hints dtest:
#
#   qual/server-pki.sh DIR
#
# One CA (Key Usage keyCertSign, cRLSign); a server certificate for 127.0.0.1/localhost; an `admin`
# client (the operator's KmipTool, every operation); and one client per node, `node1` and `node2`,
# each its own identity. `node1-renewed` is a second certificate for node1's key (the dtest
# replaces node1's certificate on disk with it to show the credential reload). All map to the one
# ownership principal `cassandra-tde`, so the nodes see the keys the operator creates, but a node
# certificate may only Locate (8), Get (10), Get Attributes (11), Get Attribute List (12), Obtain
# Lease (16), Query (24) and Discover Versions (30): it cannot create, rotate, revoke or destroy a
# key. Writes DIR/policy.json, DIR/master.key (by the pinned image's generate-master-key, through
# tools/kmip-server/run-server.sh) and the PEMs: the files qual/server-kms.sh mounts are
# server.pem, server.key, ca.pem, policy.json and master.key.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
helper=$here/../../../tools/kmip-server/run-server.sh
[ $# -eq 1 ] || { echo "usage: $0 DIR" >&2; exit 2; }
dir=$1
mkdir -p "$dir"
dir=$(cd "$dir" && pwd)
umask 077
quiet() { "$@" >/dev/null 2>&1 || { echo "failed: $*" >&2; exit 1; }; }

quiet openssl req -x509 -newkey rsa:2048 -nodes -keyout "$dir/ca.key" -out "$dir/ca.pem" -days 7 \
  -subj /CN=keytend-cassandra-trunk-tde-ca -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign,cRLSign
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n' > "$dir/server.ext"
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n' > "$dir/client.ext"
issue() { # name ext [key]: a certificate for name, with a new key or the given one
  local name=$1 ext=$2 key=${3:-}
  if [ -n "$key" ]; then
    cp "$dir/$key.key" "$dir/$name.key"
    quiet openssl req -new -key "$dir/$name.key" -out "$dir/$name.csr" -subj "/CN=${key}"
  else
    quiet openssl req -new -newkey rsa:2048 -nodes -keyout "$dir/$name.key" -out "$dir/$name.csr" -subj "/CN=$name"
  fi
  quiet openssl x509 -req -in "$dir/$name.csr" -CA "$dir/ca.pem" -CAkey "$dir/ca.key" -CAcreateserial \
    -out "$dir/$name.pem" -days 7 -extfile "$dir/$ext"
}
issue server server.ext
issue admin client.ext
issue node1 client.ext
issue node1-renewed client.ext node1
issue node2 client.ext
python3 -I - "$dir" <<'PY'
import hashlib, json, pathlib, ssl, sys
d = pathlib.Path(sys.argv[1])
node_ops = [8, 10, 11, 12, 16, 24, 30]
principals = {}
for name in ['admin', 'node1', 'node1-renewed', 'node2']:
    der = hashlib.sha256(ssl.PEM_cert_to_DER_cert((d / f'{name}.pem').read_text())).hexdigest()
    principals[der] = {'name': 'cassandra-tde', 'operations': list(range(1, 67)) if name == 'admin' else node_ops}
(d / 'policy.json').write_text(json.dumps({'principals': principals}, indent=2) + '\n')
PY
"$helper" master-key "$dir/master.key"
echo "pki in $dir: admin, node1 (and node1-renewed), node2; policy $(sha256sum "$dir/policy.json" | cut -d' ' -f1)"
