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
cert_dir=$1
"$(dirname "$0")/../generate-certs.sh" "$cert_dir"
# openssl ca lets the test set validity windows without modifying the machine clock.
mkdir -p "$cert_dir/ca-db"
: > "$cert_dir/ca-db/index"
printf '1000\n' > "$cert_dir/ca-db/serial"
cat > "$cert_dir/ca.conf" <<EOF
[ca]
default_ca=issuer
[issuer]
database=$cert_dir/ca-db/index
serial=$cert_dir/ca-db/serial
new_certs_dir=$cert_dir/ca-db
certificate=$cert_dir/ca.pem
private_key=$cert_dir/ca-key.pem
default_md=sha256
default_days=7
policy=names
unique_subject=no
[names]
commonName=supplied
organizationName=optional
[client]
extendedKeyUsage=clientAuth
keyUsage=digitalSignature
[server]
subjectAltName=DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
keyUsage=digitalSignature,keyEncipherment
[intermediate]
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
EOF
for name in client-b client-renewed wrong-eku expired future replacement-server revoked-server intermediate; do
  subject=$name
  if [[ "$name" == client-renewed ]]; then subject=client; fi
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$subject/O=keytend-kmip" -keyout "$cert_dir/$name-key.pem" -out "$cert_dir/$name.csr" 2>/dev/null
  ext=client
  case "$name" in wrong-eku|expired|future|replacement-server|revoked-server) ext=server;; intermediate) ext=intermediate;; esac
  dates=()
  if [[ "$name" == expired ]]; then dates=(-startdate 20200101000000Z -enddate 20210101000000Z); fi
  if [[ "$name" == future ]]; then dates=(-startdate 20400101000000Z -enddate 20410101000000Z); fi
  openssl ca -batch -notext -config "$cert_dir/ca.conf" -extensions "$ext" "${dates[@]}" -in "$cert_dir/$name.csr" -out "$cert_dir/$name.pem" 2>/dev/null
  openssl pkcs12 -export -out "$cert_dir/$name.p12" -inkey "$cert_dir/$name-key.pem" -in "$cert_dir/$name.pem" -certfile "$cert_dir/ca.pem" -passout pass:changeit
 done
openssl req -x509 -newkey rsa:2048 -nodes -days 7 -subj '/CN=untrusted root' -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' -keyout "$cert_dir/other-ca-key.pem" -out "$cert_dir/other-ca.pem" 2>/dev/null
for name in untrusted-client rollover-server; do
 openssl req -newkey rsa:2048 -nodes -subj "/CN=$name" -keyout "$cert_dir/$name-key.pem" -out "$cert_dir/$name.csr" 2>/dev/null
 ext=client
 if [[ "$name" == rollover-server ]]; then ext=server; fi
 openssl x509 -req -in "$cert_dir/$name.csr" -CA "$cert_dir/other-ca.pem" -CAkey "$cert_dir/other-ca-key.pem" -CAcreateserial -days 7 -extfile "$cert_dir/ca.conf" -extensions "$ext" -out "$cert_dir/$name.pem" 2>/dev/null
 openssl pkcs12 -export -out "$cert_dir/$name.p12" -inkey "$cert_dir/$name-key.pem" -in "$cert_dir/$name.pem" -certfile "$cert_dir/other-ca.pem" -passout pass:changeit
 done
cat "$cert_dir/ca.pem" "$cert_dir/other-ca.pem" > "$cert_dir/overlap-ca.pem"
openssl req -newkey rsa:2048 -nodes -subj '/CN=chain-server' -keyout "$cert_dir/chain-server-key.pem" -out "$cert_dir/chain-server.csr" 2>/dev/null
openssl x509 -req -in "$cert_dir/chain-server.csr" -CA "$cert_dir/intermediate.pem" -CAkey "$cert_dir/intermediate-key.pem" -CAcreateserial -days 7 -extfile "$cert_dir/ca.conf" -extensions server -out "$cert_dir/chain-server.pem" 2>/dev/null
cat "$cert_dir/intermediate.pem" "$cert_dir/ca.pem" > "$cert_dir/chain.pem"
for variant in chain-server missing-chain; do
 args=()
 if [[ "$variant" == chain-server ]]; then args=(-certfile "$cert_dir/chain.pem"); fi
 openssl pkcs12 -export -out "$cert_dir/$variant.p12" -inkey "$cert_dir/chain-server-key.pem" -in "$cert_dir/chain-server.pem" "${args[@]}" -passout pass:changeit
 done
cat "$cert_dir/chain-server.pem" "$cert_dir/intermediate.pem" > "$cert_dir/full-chain-server.pem"
cat "$cert_dir/overlap-ca.pem" "$cert_dir/intermediate.pem" > "$cert_dir/admin-ca.pem"
chmod 755 "$cert_dir"
# All files are disposable synthetic lab material, with no production credentials.
chmod 644 "$cert_dir"/*.p12 "$cert_dir"/*-key.pem "$cert_dir"/*.pem

openssl ca -batch -config "$cert_dir/ca.conf" -revoke "$cert_dir/revoked-server.pem" 2>/dev/null
openssl ca -gencrl -config "$cert_dir/ca.conf" -crldays 7 -out "$cert_dir/revoked.crl" 2>/dev/null
