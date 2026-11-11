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

# Opt-in live run of the generic interop suite against keytend-kmip-server (see README.md here).
# For each KMIP version and program it starts the pinned server image, through
# tools/kmip-server/run-server.sh, on a fresh store and free loopback ports, runs the program, and
# stops the server (also on exit or interrupt).
#
#   integration/keytend-kmip-server/run-interop.sh \
#       --classpath sdk.jar:integration.jar:testing.jar --work /tmp/dir \
#       [--setup configured|minimal] [--programs "suite controls reversal renewal purpose"]
#       [--versions "1.1 ... 3.0"]
#
# The image is the pin of tools/kmip-server/pinned-image.properties; KEYTEND_SERVER_IMAGE and
# KEYTEND_SERVER_UNPINNED=1 run another one (recorded in run.txt as unpinned). The caller's KMIP_*
# variables reach the server (run-server.sh) and are recorded in run.txt.
#
# --setup minimal is the bare server: one principal allowed every operation and
# nothing else. --setup configured (the default) adds what the scenarios need from server policy:
# a Validate trust anchor (--validation-ca), a users-file administrator for the request-header
# credential of draft 3.0 System Objects and Login, and reverse-only client endpoints for the
# Set Endpoint Role reversal, and a provisioning CA (a sub-CA of the test CA, in the --ca bundle)
# for the client certificate renewal, whose server alone runs with --provisioning-ca. The purpose
# program starts one server for each provisioning CA shape of its table and compares what the
# server does with what the in-memory server does with the same files (ProvisioningCaShapes.java
# here, which needs the testing jar on the classpath). Exit status: 0 when every program passed on
# every version.
set -euo pipefail
umask 077

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
server=$repo/tools/kmip-server/run-server.sh
classpath=
work=
setup=configured
programs="suite controls reversal renewal purpose"
versions="1.1 1.2 1.3 1.4 2.0 2.1 3.0"
while [ $# -gt 0 ]; do
  case $1 in
    --classpath) classpath=$2; shift 2 ;;
    --work) work=$2; shift 2 ;;
    --setup) setup=$2; shift 2 ;;
    --programs) programs=$2; shift 2 ;;
    --versions) versions=$2; shift 2 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
[ -n "$classpath" ] || { echo "--classpath: the SDK and integration jars" >&2; exit 2; }
[ -n "$work" ] || { echo "--work: an evidence directory" >&2; exit 2; }
case $setup in configured|minimal) ;; *) echo "--setup configured|minimal" >&2; exit 2 ;; esac
if [ "$setup" = minimal ]; then programs=suite; fi
mkdir -p "$work"
work=$(cd "$work" && pwd)

# Never overwrite provenance or reuse partial PKI under a different setup policy.
if [ -e "$work/setup-mode" ]; then
  [ "$(cat "$work/setup-mode")" = "$setup" ] || {
    echo "work directory was initialized with another setup; use a fresh --work" >&2; exit 2;
  }
elif [ -e "$work/run.txt" ] || [ -e "$work/pki" ]; then
  echo "work directory has unversioned setup state; use a fresh --work" >&2; exit 2
else
  echo "$setup" > "$work/setup-mode"
fi

# The server image: pinned (exit 0), or another one allowed by KEYTEND_SERVER_UNPINNED=1 (10).
set +e
image_id=$("$server" image)
image_status=$?
set -e
case $image_status in
  0) image_pin=pinned ;;
  10) image_pin=UNPINNED ;;
  *) echo "the server image is refused (run-server.sh image exit $image_status)" >&2; exit 2 ;;
esac
{
  pin=$repo/tools/kmip-server/pinned-image.properties
  echo "pin       $(sed -n 's/^name=//p;s/^version=//p' "$pin" | paste -sd' ') ($(sed -n 's/^image_id=//p' "$pin"))"
  echo "image     ${KEYTEND_SERVER_IMAGE:-$(sed -n 's/^image=//p' "$pin")}"
  echo "image_id  $image_id ($image_pin)"
  echo "version   $("$server" version)"
  echo "kmip_env  $(env | grep '^KMIP_' | sort | paste -sd' ' || true)"
  for jar in ${classpath//:/ }; do echo "jar       $jar"; done
  echo "java      $(java -version 2>&1 | head -1)"
  echo "setup     $setup"
  echo "programs  $programs"
  echo "versions  $versions"
} | tee "$work/run.txt"

# Throwaway test PKI in the layout of integration/generate-certs.sh (ca.pem, ca-key.pem, client.pem,
# client-key.pem, client.csr, client.p12), plus one client certificate per reverse-only endpoint.
pki=$work/pki
if [ ! -f "$pki/policy.json" ]; then
  bash "$repo/integration/generate-certs.sh" "$pki" >/dev/null
  for name in reverse-2.0 reverse-2.1; do
    openssl req -newkey rsa:2048 -nodes -subj "/CN=$name/O=keytend-kmip" -keyout "$pki/$name-key.pem" \
      -out "$pki/$name.csr" 2>/dev/null
    openssl x509 -req -in "$pki/$name.csr" -CA "$pki/ca.pem" -CAkey "$pki/ca-key.pem" -CAcreateserial \
      -days 7 -extfile "$pki/client.ext" -out "$pki/$name.pem" 2>/dev/null
    openssl pkcs12 -export -out "$pki/$name.p12" -inkey "$pki/$name-key.pem" -in "$pki/$name.pem" \
      -certfile "$pki/ca.pem" -passout pass:changeit
  done
  # Re-Provision: a provisioning sub-CA (pathLen:0) in the --ca bundle, and two clients, in PEM and
  # in PKCS#12, that the renewal program renews. The clients last 6 days, one less than the rest of
  # this PKI and the provisioning CA, so a rerun of the same --work directory works for as long as
  # the rest does, and a renewal issues a certificate that outlives the one it replaces.
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj '/CN=keytend-kmip provisioning CA' \
    -keyout "$pki/provisioning-ca-key.pem" -out "$pki/provisioning-ca.csr" 2>/dev/null
  printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n' \
    > "$pki/provisioning-ca.ext"
  openssl x509 -req -in "$pki/provisioning-ca.csr" -CA "$pki/ca.pem" -CAkey "$pki/ca-key.pem" \
    -CAcreateserial -days 7 -extfile "$pki/provisioning-ca.ext" -out "$pki/provisioning-ca.pem" 2>/dev/null
  cat "$pki/ca.pem" "$pki/provisioning-ca.pem" > "$pki/ca-bundle.pem"
  for name in renewal renewal-store; do
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$name/O=keytend-kmip" \
      -keyout "$pki/$name-key.pem" -out "$pki/$name.csr" 2>/dev/null
    openssl x509 -req -in "$pki/$name.csr" -CA "$pki/ca.pem" -CAkey "$pki/ca-key.pem" -CAcreateserial \
      -days 6 -extfile "$pki/client.ext" -out "$pki/$name.pem" 2>/dev/null
  done
  openssl pkcs12 -export -out "$pki/renewal-store.p12" -inkey "$pki/renewal-store-key.pem" \
    -in "$pki/renewal-store.pem" -passout pass:changeit
  "$server" master-key "$pki/master.key"
  python3 -I - "$pki" "$setup" <<'PY'
import hashlib, json, pathlib, secrets, ssl, sys
pki, setup = pathlib.Path(sys.argv[1]), sys.argv[2]
def fingerprint(name):
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert((pki / name).read_text())).hexdigest()
every = list(range(1, 67))
principals = {fingerprint('client.pem'): {'name': 'interop', 'operations': every}}
# The clients the renewal program renews (Re-Provision is 53; Get, 10; Locate, 8, after a lost
# reply).
for name in ('renewal', 'renewal-store'):
    principals[fingerprint(f'{name}.pem')] = {'name': name, 'operations': every}
if setup == 'configured':
    # Set Endpoint Role Client needs a client endpoint in the principal's policy, in the request's
    # protocol version. Without dial-out fields its messages travel only over the reversed channel.
    for version in ('2.0', '2.1'):
        principals[fingerprint(f'reverse-{version}.pem')] = {
            'name': f'reverse-{version}', 'operations': every,
            'client_endpoint': {'protocol_version': version, 'operations': [27, 28]}}
    # Draft 3.0 System Objects and Login need a verified administrator in the request header: a
    # users-file user with a PBKDF2-HMAC-SHA-256 verifier of the server's parameters (600 000
    # iterations, 32-byte output; what `keytend-kmip-server password-verifier` prints).
    password = secrets.token_urlsafe(24)
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600000, 32)
    users = {'users': {fingerprint('client.pem'): [{
        'username': 'interop-admin', 'administrator': True,
        'password_verifier': {'algorithm': 'PBKDF2-HMAC-SHA-256', 'iterations': 600000,
                              'salt': salt.hex(), 'hash': digest.hex()}}]}}
    (pki / 'users.json').write_text(json.dumps(users, indent=2) + '\n')
    (pki / 'admin-credential.properties').write_text(
        f'# Test-only administrator of users.json\nusername=interop-admin\npassword={password}\n')
(pki / 'policy.json').write_text(json.dumps({'principals': principals}, indent=2) + '\n')
PY
  chmod 600 "$pki"/*-key.pem "$pki/master.key" "$pki/renewal-store.p12"
  [ -f "$pki/admin-credential.properties" ] && chmod 600 "$pki/admin-credential.properties"
fi

# The purpose program's provisioning CA shapes, each a directory of the CA (ca.pem, ca-key.pem) and
# the server's --ca bundle (bundle.pem), and what the pinned keytend-kmip-server does with it:
# "renews", or "refuses" to start with the message given, which the in-memory listener gives too,
# and, on keytend-kmip-server, the detail after it (the reason its listener's verification gave).
# Each CA is a P-256 sub-CA of the test CA, signed with SHA-256; root-serverauth's is a sub-CA of
# a root of its own whose Extended Key Usage is serverAuth only, and weak-root's of an RSA-1024 root
# of its own. weak-digest's CA is signed with SHA-1, and rsa-1024's has an RSA-1024 key. no-root's
# bundle holds the CA without its root, and not-in-bundle's the root without the CA.
fails="a client certificate from the provisioning CA fails the listener's verification"
shapes="
plain|basicConstraints=critical,CA:TRUE,pathlen:0;keyUsage=critical,keyCertSign,cRLSign|renews||
eku-clientauth|basicConstraints=critical,CA:TRUE,pathlen:0;keyUsage=critical,keyCertSign,cRLSign;extendedKeyUsage=clientAuth|renews||
eku-serverauth|basicConstraints=critical,CA:TRUE,pathlen:0;keyUsage=critical,keyCertSign,cRLSign;extendedKeyUsage=serverAuth|refuses|$fails|unsuitable certificate purpose (depth 1)
eku-any|basicConstraints=critical,CA:TRUE,pathlen:0;keyUsage=critical,keyCertSign,cRLSign;extendedKeyUsage=anyExtendedKeyUsage|refuses|$fails|unsuitable certificate purpose (depth 1)
ku-crlsign|basicConstraints=critical,CA:TRUE,pathlen:0;keyUsage=critical,cRLSign|refuses|the provisioning CA: Issuer key usage does not permit certificate signing|
no-ku|basicConstraints=critical,CA:TRUE,pathlen:0|refuses|the provisioning CA certificate lacks the keyCertSign key usage|
not-ca|basicConstraints=critical,CA:FALSE;keyUsage=critical,keyCertSign,cRLSign|refuses|the provisioning CA: Issuer certificate is not a CA|
no-bc-ku|keyUsage=critical,keyCertSign,cRLSign|refuses|the provisioning CA: Issuer certificate is not a CA|
no-bc-netscape-sslca|nsCertType=sslCA|refuses|the provisioning CA: Issuer certificate is not a CA|
root-serverauth|basicConstraints=critical,CA:TRUE,pathlen:0;keyUsage=critical,keyCertSign,cRLSign|refuses|$fails|unsuitable certificate purpose (depth 2)
no-root|basicConstraints=critical,CA:TRUE,pathlen:0;keyUsage=critical,keyCertSign,cRLSign|refuses|$fails|unable to get issuer certificate (depth 1)
not-in-bundle|basicConstraints=critical,CA:TRUE,pathlen:0;keyUsage=critical,keyCertSign,cRLSign|refuses|the provisioning CA must also be in the --ca bundle, so that the certificates it issues are accepted|
weak-digest|basicConstraints=critical,CA:TRUE,pathlen:0;keyUsage=critical,keyCertSign,cRLSign|refuses|the provisioning CA certificate is signed with a weak digest|
rsa-1024|basicConstraints=critical,CA:TRUE,pathlen:0;keyUsage=critical,keyCertSign,cRLSign|refuses|the provisioning CA certificate key has 80-bit security, below 112|
weak-root|basicConstraints=critical,CA:TRUE,pathlen:0;keyUsage=critical,keyCertSign,cRLSign|refuses|$fails|depth 2: key has 80-bit security, below 112
"
case " $programs " in
  *" purpose "*)
    printf '%s\n' "$classpath" | grep -q 'keytend-kmip-testing' \
      || { echo "--programs purpose: put the testing jar on --classpath" >&2; exit 2; }
    # Each shape is made once per work directory: a shape added later is made on the next run.
    mkdir -p "$pki/shapes"
    if [ ! -f "$pki/shapes/root-serverauth-root.pem" ]; then
      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 7 \
        -subj '/CN=keytend-kmip serverAuth root' -addext 'basicConstraints=critical,CA:TRUE' \
        -addext 'keyUsage=critical,keyCertSign,cRLSign' -addext 'extendedKeyUsage=serverAuth' \
        -keyout "$pki/shapes/root-serverauth-root-key.pem" -out "$pki/shapes/root-serverauth-root.pem" 2>/dev/null
      chmod 600 "$pki/shapes/root-serverauth-root-key.pem"
    fi
    if [ ! -f "$pki/shapes/weak-root-root.pem" ]; then
      openssl req -x509 -newkey rsa:1024 -nodes -days 7 -subj '/CN=keytend-kmip RSA-1024 root' \
        -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
        -keyout "$pki/shapes/weak-root-root-key.pem" -out "$pki/shapes/weak-root-root.pem" 2>/dev/null
      chmod 600 "$pki/shapes/weak-root-root-key.pem"
    fi
    while IFS='|' read -r shape extensions _; do
      [ -n "$shape" ] || continue
      d=$pki/shapes/$shape
      [ ! -f "$d/bundle.pem" ] || continue
      mkdir -p "$d"
      issuer=$pki/ca.pem issuer_key=$pki/ca-key.pem key=(-newkey ec -pkeyopt ec_paramgen_curve:P-256)
      digest=-sha256
      case $shape in
        root-serverauth|weak-root)
          issuer=$pki/shapes/$shape-root.pem issuer_key=$pki/shapes/$shape-root-key.pem ;;
        weak-digest) digest=-sha1 ;;
        rsa-1024) key=(-newkey rsa:1024) ;;
      esac
      openssl req "${key[@]}" -nodes -subj "/CN=provisioning CA $shape" \
        -keyout "$d/ca-key.pem" -out "$d/ca.csr" 2>/dev/null
      chmod 600 "$d/ca-key.pem"
      printf '%s\n' "$extensions" | tr ';' '\n' > "$d/ca.ext"
      openssl x509 -req -in "$d/ca.csr" -CA "$issuer" -CAkey "$issuer_key" -CAcreateserial -days 7 \
        "$digest" -extfile "$d/ca.ext" -out "$d/ca.pem" 2>/dev/null
      case $shape in
        root-serverauth|weak-root) cat "$pki/ca.pem" "$issuer" "$d/ca.pem" > "$d/bundle.pem.new" ;;
        no-root) cp "$d/ca.pem" "$d/bundle.pem.new" ;;
        not-in-bundle) cp "$pki/ca.pem" "$d/bundle.pem.new" ;;
        *) cat "$pki/ca.pem" "$d/ca.pem" > "$d/bundle.pem.new" ;;
      esac
      mv "$d/bundle.pem.new" "$d/bundle.pem"
    done <<< "$shapes"
    ;;
esac

extra=()
if [ "$setup" = configured ]; then
  extra=(--validation-ca "$pki/ca.pem" --users "$pki/users.json")
fi

# One container per version and program, named $prefix<program>-v<version>; every one this run
# started is removed on exit or interrupt.
prefix=keytend-interop-$$-
name=
stop() {
  [ -z "$name" ] || "$server" stop "$name" || true
  name=
}
trap '"$server" cleanup "$prefix"' EXIT
trap 'exit 130' INT TERM

start() { # <dir> <name> [--ca F] [option...]: a fresh store in <dir> and server <name>, its KMIP port in $port
  local dir=$1 out ca=$pki/ca.pem
  name=$2
  shift 2
  # A server with a provisioning CA needs it in the --ca bundle: the renewal program's, or a
  # purpose shape's (--ca).
  if [ "${1:-}" = --ca ]; then ca=$2; shift 2
  elif [ "${1:-}" = --provisioning-ca ]; then ca=$pki/ca-bundle.pem; fi
  if ! out=$("$server" start "$name" --data "$dir" --cert "$pki/server.pem" --key "$pki/server-key.pem" \
      --ca "$ca" --policy "$pki/policy.json" --master-key "$pki/master.key" \
      ${extra[@]+"${extra[@]}"} "$@" --log "$dir/server.log" -- --experimental-v3); then
    echo "server did not start; see $dir/server.log" >&2
    name=
    return 1
  fi
  port=$(printf '%s\n' "$out" | sed -n 's/^port=\([0-9]*\) .*/\1/p')
  [ -n "$port" ] || { echo "no port from run-server.sh: $out" >&2; stop; return 1; }
}

# For each shape, in <dir>/out.log: ok or FAIL, then the in-memory server's verdict and
# keytend-kmip-server's. Each must be the table's, exactly: both renew by the shape's CA, or both
# refuse to start with its message (keytend-kmip-server's followed by its detail, if any), so a
# check that refuses for another reason, on either side, fails the shape. Returns 1 if any fails.
purpose() { # <dir>
  local dir=$1 failed=0 shape extensions expected message detail d memory live code
  while IFS='|' read -r shape extensions expected message detail; do
    [ -n "$shape" ] || continue
    d=$pki/shapes/$shape
    mkdir -p "$dir/$shape"
    memory=$(java -cp "$classpath" "$here/ProvisioningCaShapes.java" in-memory "$pki" "$d" "$version" \
      "$dir/$shape/in-memory" 2>"$dir/$shape/in-memory.log") || memory="error: see $dir/$shape/in-memory.log"
    if start "$dir/$shape" "$prefix$shape-v$version" --ca "$d/bundle.pem" --provisioning-ca "$d/ca.pem" \
        --provisioning-ca-key "$d/ca-key.pem" 2>"$dir/$shape/start.log"; then
      live=$(java -cp "$classpath" "$here/ProvisioningCaShapes.java" live 127.0.0.1 "$port" "$pki" "$version" \
        "$dir/$shape/live" 2>"$dir/$shape/live.log") || live="error: see $dir/$shape/live.log"
      stop
    else
      # The error's causes, as anyhow lists them ("Caused by:", then one per line, numbered when
      # there are several), joined with ": " as the in-memory listener's message is.
      live="refused at start: $(awk '/^Caused by:/ { on = 1; next }
        on && NF { sub(/^ +/, ""); sub(/^[0-9]+: /, ""); s = s (s == "" ? "" : ": ") $0 }
        END { print s }' "$dir/$shape/server.log")"
    fi
    code=ok
    case $expected in
      renews)
        [ "$memory" = "renewed by CN=provisioning CA $shape" ] || code=FAIL
        [ "$live" = "renewed by CN=provisioning CA $shape" ] || code=FAIL ;;
      refuses)
        [ "$memory" = "refused at start: provisioningCa: $message" ] || code=FAIL
        [ "$live" = "refused at start: $message${detail:+: $detail}" ] || code=FAIL ;;
      *) code=FAIL ;;
    esac
    [ "$code" = ok ] || failed=1
    printf '%s %s\n  in-memory: %s\n  keytend-kmip-server: %s\n' "$code" "$shape" "$memory" "$live"
  done <<< "$shapes" > "$dir/out.log"
  echo "$failed" > "$dir/exit.txt"
  echo "KMIP $version purpose exit=$failed ($(grep -c '^ok ' "$dir/out.log") of $(grep -cE '^(ok|FAIL) ' "$dir/out.log") shapes agree)"
  return $failed
}

status=0
for version in $versions; do
  for program in $programs; do
    # Set Endpoint Role and Re-Provision are defined from 2.0.
    case $program in reversal|renewal|purpose) [ "${version%%.*}" != 1 ] || continue ;; esac
    dir=$work/$program/v$version
    rm -rf "$dir"; mkdir -p "$dir"
    if [ "$program" = purpose ]; then
      purpose "$dir" || status=1
      continue
    fi
    options=()
    if [ "$program" = renewal ]; then
      options=(--provisioning-ca "$pki/provisioning-ca.pem" --provisioning-ca-key "$pki/provisioning-ca-key.pem")
    fi
    if ! start "$dir" "$prefix$program-v$version" ${options[@]+"${options[@]}"}; then
      status=1; echo 1 > "$dir/exit.txt"; continue
    fi
    case $program in
      suite) main=(dev.keytend.kmip.interop.InteropApplication keytend-kmip-server 127.0.0.1 "$port" "$pki" "$dir/reports" "$version") ;;
      controls) main=(dev.keytend.kmip.interop.ServerSetupControls 127.0.0.1 "$port" "$pki" "$version") ;;
      reversal) main=(dev.keytend.kmip.interop.EndpointRoleReversal 127.0.0.1 "$port" "$pki" "$version") ;;
      renewal) main=(dev.keytend.kmip.interop.ClientCertificateRenewal 127.0.0.1 "$port" "$pki" "$version" "$dir/files") ;;
      *) echo "unknown program $program" >&2; exit 2 ;;
    esac
    set +e
    java -cp "$classpath" "${main[@]}" >"$dir/out.log" 2>&1
    code=$?
    set -e
    echo "$code" > "$dir/exit.txt"
    echo "KMIP $version $program exit=$code"
    [ "$code" = 0 ] || status=1
    stop
  done
done
exit $status
