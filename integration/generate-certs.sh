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
cert_dir="${1:-$(dirname "$0")/certs}"
mkdir -p "$cert_dir"
chmod 700 "$cert_dir"
openssl req -x509 -newkey rsa:2048 -nodes -days 7 -subj '/CN=keytend-kmip test CA' -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' -keyout "$cert_dir/ca-key.pem" -out "$cert_dir/ca.pem" 2>/dev/null
for name in server client; do
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$name/O=keytend-kmip" -keyout "$cert_dir/$name-key.pem" -out "$cert_dir/$name.csr" 2>/dev/null
  if [[ "$name" == server ]]; then
    cat > "$cert_dir/$name.ext" <<'EXT'
subjectAltName=DNS:localhost,DNS:pykmip,IP:127.0.0.1
extendedKeyUsage=serverAuth
keyUsage=digitalSignature,keyEncipherment
EXT
  else
    cat > "$cert_dir/$name.ext" <<'EXT'
extendedKeyUsage=clientAuth
keyUsage=digitalSignature
EXT
  fi
  openssl x509 -req -in "$cert_dir/$name.csr" -CA "$cert_dir/ca.pem" -CAkey "$cert_dir/ca-key.pem" -CAcreateserial -days 7 -extfile "$cert_dir/$name.ext" -out "$cert_dir/$name.pem" 2>/dev/null
 done
openssl pkcs12 -export -out "$cert_dir/client.p12" -inkey "$cert_dir/client-key.pem" -in "$cert_dir/client.pem" -certfile "$cert_dir/ca.pem" -passout pass:changeit
# Ephemeral test keys must be readable by the unprivileged container users.
chmod 755 "$cert_dir"
chmod 644 "$cert_dir"/server.pem "$cert_dir"/server-key.pem "$cert_dir"/ca.pem

openssl pkcs12 -export -out "$cert_dir/server.p12" -inkey "$cert_dir/server-key.pem" -in "$cert_dir/server.pem" -certfile "$cert_dir/ca.pem" -passout pass:changeit
chmod 644 "$cert_dir/server.p12"
# A correctly signed certificate with an intentionally wrong hostname exercises endpoint identification.
cat > "$cert_dir/mismatch.ext" <<'EXT'
subjectAltName=DNS:kmip.invalid
extendedKeyUsage=serverAuth
keyUsage=digitalSignature,keyEncipherment
EXT
openssl x509 -req -in "$cert_dir/server.csr" -CA "$cert_dir/ca.pem" -CAkey "$cert_dir/ca-key.pem" -CAcreateserial -days 7 -extfile "$cert_dir/mismatch.ext" -out "$cert_dir/mismatch.pem" 2>/dev/null
openssl pkcs12 -export -out "$cert_dir/mismatch.p12" -inkey "$cert_dir/server-key.pem" -in "$cert_dir/mismatch.pem" -certfile "$cert_dir/ca.pem" -passout pass:changeit
