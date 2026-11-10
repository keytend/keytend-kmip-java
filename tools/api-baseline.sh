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

# Puts the released SDK JAR the API check compares against (-Papi-compat,
# docs/compatibility.md) at target/api-baseline/keytend-kmip-<version>.jar, after
# checking its SHA-256 against the released one. The release is pinned in one
# place, the api.baseline.name, api.baseline.version and api.baseline.sha256
# properties of sdk/pom.xml, which the api-compat profile's api.baseline.jar
# also uses. A keytend-kmip baseline is downloaded from its tag v<version> in
# keytend/keytend-kmip-java.
#
# The rule: the baseline is the latest release X.Y.Z, never a pre-release X.Y.Z-rc.N.
# The first release, 0.10.0, has no earlier release to compare with. While the
# tree builds 0.10.0 or one of its pre-releases (0.10.0-rc.N), sdk/pom.xml pins
# no baseline: the script says so and exits 3, and the release check records
# api-baseline as SKIP, the only SKIP it allows. Once 0.10.0 is published it
# becomes the baseline. A tree that builds any other version without a pin is
# refused (exit 2).
#
# Whether an incompatible change fails (--fails prints fail or report): while the
# major version is 0, a patch release (0.10.0 to 0.10.1) must not break the API
# and a minor release (0.10 to 0.11) may, saying so in its release notes; from
# 1.0, a minor or patch release must not, and a major release may. So the check
# fails against a baseline of the same 0.x minor version (or, from 1.0, the same
# major version) as the tree, and reports only against an earlier one
# (docs/compatibility.md). A patch release X.Y.Z (Z > 0) is compared with a
# release of its own X.Y: against an earlier one, --fails refuses (exit 2) and
# says to make X.Y.0 the API baseline, so a stale baseline cannot let a patch
# release break the API.
#
#   tools/api-baseline.sh                            # gh release download v<version>
#   tools/api-baseline.sh path/to/RELEASE-X.Y.Z.zip  # the release ZIP
#   tools/api-baseline.sh path/to/RELEASE-X.Y.Z.jar  # the SDK JAR from it
#   tools/api-baseline.sh --version               # prints the pinned version
#   tools/api-baseline.sh --sha256                # prints the pinned SHA-256
#   tools/api-baseline.sh --fails                 # fail or report (above), or exit 2
#
# Then: ./mvnw -Papi-compat verify (the report is in sdk/target/japicmp/).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
# The pin: the SDK JAR in lib/ of the GitHub release v<version>'s ZIP. Empty when none is pinned.
pinned() {
  python3 -I -c 'import sys, xml.etree.ElementTree as E
v = E.parse(sys.argv[1]).getroot().findtext("{http://maven.apache.org/POM/4.0.0}properties/{http://maven.apache.org/POM/4.0.0}" + sys.argv[2])
print(v.strip() if v else "")' "$root/sdk/pom.xml" "$1"
}
# The first release: the one version a tree may build without a baseline, with its pre-releases.
first_release=0.10.0
name=$(pinned api.baseline.name)
version=$(pinned api.baseline.version)
sha256=$(pinned api.baseline.sha256)
case "${1:-}" in
  -h|--help) sed -n '/^# Puts/,/^# Then/s/^# \{0,1\}//p' "$0"; exit 0 ;;
esac
building=$(python3 -I -c 'import sys, xml.etree.ElementTree as E
print(E.parse(sys.argv[1]).getroot().findtext("{http://maven.apache.org/POM/4.0.0}version").strip())' "$root/pom.xml")
# The series a version X.Y.Z(-rc.N) is in: 0.Y while the major version is 0, else X.
series() {
  local major=${1%%.*} rest=${1#*.}
  if [[ "$major" == 0 ]]; then echo "0.${rest%%.*}"; else echo "$major"; fi
}
if [[ -z "$name$version$sha256" ]]; then
  if [[ "${building%%-rc.*}" != "$first_release" ]]; then
    echo "sdk/pom.xml pins no API baseline, but the tree builds $building: only the first release, $first_release, and its pre-releases have none (docs/releasing.md)" >&2
    exit 2
  fi
  echo "sdk/pom.xml pins no API baseline: the tree builds $building, of the first release, $first_release, and there is no earlier keytend-kmip release to compare with" >&2
  exit 3
fi
case "${1:-}" in
  --version) echo "$version"; exit 0 ;;
  --sha256) echo "$sha256"; exit 0 ;;
  --fails)
    # X.Y of a version X.Y.Z(-rc.N), and its patch number Z.
    release=${building%%-*}
    patch=${release##*.}
    if [[ "$patch" != 0 && "${release%.*}" != "$(echo "$version" | cut -d. -f1,2)" ]]; then
      echo "the tree builds $building, a patch release of ${release%.*}, but the API baseline is" \
        "$version, of another minor version: make ${release%.*}.0 the API baseline" \
        "(docs/releasing.md, \"Make the release the API baseline\")" >&2
      exit 2
    fi
    if [[ "$(series "$building")" == "$(series "$version")" ]]; then
      echo "the tree builds $building, of the series $(series "$version") of the baseline" \
        "$version: an incompatible change fails" >&2
      echo fail
    else
      echo "the tree builds $building, after the series $(series "$version") of the baseline" \
        "$version: an incompatible change is reported, and the release notes list it" >&2
      echo report
    fi
    exit 0 ;;
esac
known=keytend-kmip
if ! [[ " $known " == *" $name "* && "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$sha256" =~ ^[0-9a-f]{64}$ ]]; then
  echo "sdk/pom.xml pins a malformed baseline: name '$name', version '$version', SHA-256 '$sha256'" >&2
  exit 2
fi
out="$root/target/api-baseline"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
source=${1:-}
if [[ -z "$source" && "$name" != keytend-kmip ]]; then
  echo "the baseline is $name $version, released outside keytend/keytend-kmip-java: pass its ZIP or JAR" >&2
  exit 2
fi
if [[ -z "$source" ]]; then
  gh release download "v$version" -R keytend/keytend-kmip-java -p "*-$version.zip" -D "$work"
  source=$(find "$work" -maxdepth 1 -name "*-$version.zip" | head -1)
fi
case "$source" in
  *.zip)
    # The SDK JAR: lib/NAME-X.Y.Z.jar, not the integration JAR beside it.
    entry=$(unzip -Z1 "$source" | grep -E "^[^/]+/lib/[^/]+-$version\.jar\$" | grep -v -- '-integration-' | head -1 || true)
    [ -n "$entry" ] || { echo "$source has no lib/*-$version.jar" >&2; exit 2; }
    unzip -q -j "$source" "$entry" -d "$work"; jar="$work/$(basename "$entry")" ;;
  *.jar) jar="$source" ;;
  *) echo "Expected the release ZIP or its SDK JAR: $source" >&2; exit 2 ;;
esac
actual=$(sha256sum "$jar" | cut -d' ' -f1)
if [[ "$actual" != "$sha256" ]]; then
  echo "$jar has SHA-256 $actual, not the released $version JAR's $sha256" >&2
  exit 1
fi
mkdir -p "$out"
cp "$jar" "$out/keytend-kmip-$version.jar"
echo "$out/keytend-kmip-$version.jar (SHA-256 $sha256)"
