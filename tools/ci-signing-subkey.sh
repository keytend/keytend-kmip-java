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

# Add this repository's CI signing subkey to the release key and give it to the release
# workflows (docs/releasing.md, "The release workflow").
#
#   tools/ci-signing-subkey.sh [--subkey FINGERPRINT]
#
# For the key holder only: it needs the release key's primary secret in the default gpg keyring,
# and asks once for its passphrase. It
#
# 1. adds an Ed25519 signing subkey, valid for two years (--subkey: uses that existing signing
#    subkey of the release key instead, such as one an earlier run added before it failed);
# 2. copies that subkey's secret alone (the primary as a stub) into a temporary keyring, removes
#    its passphrase there, checks that it signs with no passphrase, and stores it as the secret
#    KEYTEND_SIGNING_KEY of keytend/keytend-kmip-java, with its fingerprint as the variable
#    KEYTEND_SIGNING_SUBKEY;
# 3. prints the commands that publish the updated public key on both keyservers.
#
# The passphrase reaches gpg only through a pipe, never a command line. The secret without a
# passphrase never reaches the disk outside the temporary directory, which is removed on exit. Publish the key before the workflow's first release: the release's signatures verify
# only with the published key, and Central checks its signatures against keyserver.ubuntu.com
# and keys.openpgp.org. The subkey is this repository's alone: if the secret leaks, revoke this
# subkey only (docs/releasing.md, "The release key").
set -euo pipefail

PRIMARY=3A84912AFBE7D2B04EBA2A8A51E65DD49C6F987F
REPOSITORY=keytend/keytend-kmip-java

command -v gh >/dev/null || { echo "gh is needed to set the repository's secret" >&2; exit 1; }
# Field 15 of the sec line is "#" when only a stub of the primary is present.
gpg --batch --with-colons --list-secret-keys "$PRIMARY" 2>/dev/null | awk -F: '$1 == "sec" && $15 !~ /#/ {ok = 1} END {exit !ok}' ||
  { echo "the release key's primary secret is not in this keyring" >&2; exit 1; }

subkey=
case "${1:-}" in
  --subkey) [ $# = 2 ] || { echo "usage: $0 [--subkey FINGERPRINT]" >&2; exit 2; }; subkey=${2^^} ;;
  '') ;;
  *) echo "usage: $0 [--subkey FINGERPRINT]" >&2; exit 2 ;;
esac

read -rsp "Passphrase of the release key: " passphrase; echo
# gpg with the passphrase on file descriptor 3; printf is a builtin, so it is on no command line.
with_passphrase() { "$@" 3< <(printf '%s\n' "$passphrase"); }

subkeys() { gpg --batch --with-colons --list-keys "$PRIMARY" | awk -F: '$1 == "sub" && $12 ~ /s/ && $2 !~ /[erd]/ {s = 1; next} $1 == "sub" {s = 0} s && $1 == "fpr" {print $10; s = 0}'; }
if [ -n "$subkey" ]; then
  subkeys | grep -qx "$subkey" || { echo "$subkey is not a valid signing subkey of $PRIMARY" >&2; exit 1; }
  SUBKEY=$subkey
else
  before=$(subkeys)
  with_passphrase gpg --batch --pinentry-mode loopback --passphrase-fd 3 --quick-add-key "$PRIMARY" ed25519 sign 2y
  SUBKEY=$(comm -13 <(printf '%s\n' "$before" | sort) <(subkeys | sort))
  [ "$(printf '%s\n' "$SUBKEY" | grep -c .)" = 1 ] || { echo "could not find the new subkey" >&2; exit 1; }
  echo "new CI signing subkey: $SUBKEY"
fi

WORK=$(mktemp -d)
trap 'gpgconf --homedir "$WORK/strip" --kill all 2>/dev/null; gpgconf --homedir "$WORK/ci" --kill all 2>/dev/null; rm -rf -- "$WORK"' EXIT
mkdir -m 700 "$WORK/strip" "$WORK/ci"
# GnuPG 2.1 and later cannot export a subkey without its passphrase: copy it into a keyring of
# its own, change its passphrase there to none, and export it from there.
with_passphrase gpg --batch --pinentry-mode loopback --passphrase-fd 3 --armor --export-secret-subkeys "$SUBKEY!" > "$WORK/protected.asc"
gpg --homedir "$WORK/strip" --batch --quiet --import "$WORK/protected.asc"
# passwd selects the subkey (key 1: the stub primary is the only other key); gpg reads the
# commands and the old and new (empty) passphrase from stdin. It reports the stub primary as an
# error and exits 2 even when the subkey's passphrase changed: the check below decides.
printf 'key 1\npasswd\n%s\n\nsave\n' "$passphrase" |
  gpg --homedir "$WORK/strip" --batch --pinentry-mode loopback --command-fd 0 --edit-key "$PRIMARY" >/dev/null 2>&1 || true
unset passphrase
gpg --homedir "$WORK/strip" --batch --pinentry-mode loopback --passphrase '' --armor --export-secret-subkeys "$SUBKEY!" > "$WORK/subkey.asc"
# As the release workflow uses it: imported into an empty keyring, it signs with no passphrase.
gpg --homedir "$WORK/ci" --batch --quiet --import "$WORK/subkey.asc"
echo check > "$WORK/check"
status=$(gpg --homedir "$WORK/ci" --batch --pinentry-mode error --local-user "$SUBKEY!" --detach-sign "$WORK/check" 2>/dev/null &&
  gpg --homedir "$WORK/ci" --batch --status-fd 1 --verify "$WORK/check.sig" "$WORK/check" 2>/dev/null) || status=
if ! grep -q "^\[GNUPG:\] VALIDSIG $SUBKEY " <<<"$status"; then
  echo "the exported subkey does not sign without a passphrase; nothing was stored" >&2
  exit 1
fi
gh secret set KEYTEND_SIGNING_KEY -R "$REPOSITORY" < "$WORK/subkey.asc"
gh variable set KEYTEND_SIGNING_SUBKEY -R "$REPOSITORY" --body "$SUBKEY"
gpg --show-keys --with-subkey-fingerprints <(gpg --armor --export "$PRIMARY")

cat <<EOF

Done. Publish the key with its new subkey on both keyservers:
  gpg --export $PRIMARY | curl -fsS -T - https://keys.openpgp.org
  gpg --keyserver hkps://keyserver.ubuntu.com --send-keys $PRIMARY
EOF
