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

# The pre-release gate in one command (docs/releasing.md, step 1). Every check runs in a clean
# git worktree of HEAD under the run directory, one Maven at a time; the caller's checkout is not
# touched. Every log is kept in the run directory; the script ends with a PASS/FAIL table and
# exits 1 if anything failed.
#
#   tools/release-check.sh [--out DIR] [--jdks "17 21 25"] [--integration]
#       [--skip-verify] [--skip-api] [--skip-repro] [--server DOCKER-TAR|IMAGE [--server-unpinned]]
#       [--baseline RELEASE-X.Y.Z.zip|RELEASE-X.Y.Z.jar]
#       [--api-fail|--no-api-fail] [--allow-dirty] [--keep-trees]
#
# A release is built, tested, reported, then packaged: the checks run first, their reports go to
# the run directory's validation/ (release-check.txt, the table of the checks before packaging;
# with --integration the workflow suite's and the catalog's summaries; with --server the live
# results against keytend-kmip-server, live-server.json, and their logs), and the two
# distribution builds are packaged with them (tools/package-release.py --reports
# --in-release-check), as the binary ZIP's validation/. No local path goes into the reports, and
# no test output: the Surefire and Failsafe reports stay in the run directory (surefire-*/).
#
# test runs on JDK 17 (the phases before package, as an IDE runs the tests; the SDK's own in verify); verify
# runs on each JDK (17 with -Pdistribution, the whole test matrix and SpotBugs, 21 with Error Prone); the API report is against the release
# sdk/pom.xml pins (api.baseline.version), failing on incompatible changes when the baseline is of
# the same 0.x minor version, or from 1.0 the same major (tools/api-baseline.sh --fails); against an
# earlier series it reports them, and RELEASE.md's section of the release must list them under
# "## Incompatible changes" (SKIP, the only SKIP allowed, while none is pinned: only for the first
# release, 0.10.0, and its pre-releases, which have no earlier release); the distribution is built
# and
# packaged twice, in two worktrees, under umask 0022 and then 0077 with another time zone, and every
# JAR, the SBOMs and both ZIPs must be byte-identical; the second is a Central dry run, and its bundle's
# JARs must be those SHA256SUMS lists. Each JDK is the newest patch release of that version SDKMAN has;
# set JDK17_HOME, JDK21_HOME and JDK25_HOME to choose others, or for non-SDKMAN
# installations. --integration needs Docker or Podman (DOCKER_HOST; the rootless Podman socket when
# DOCKER_HOST is unset); a release needs its reports (tools/release_reports.py,
# integration_problems). release-check.txt records the arguments without a local path: the run
# directory as <run directory>, the server's archive and the baseline by their file names.
# --server runs the live probe against keytend-kmip-server from that Docker
# archive or loaded image (podman), which must be the build tools/kmip-server/pinned-image.properties
# pins: the archive's SHA-256 and the image ID are checked by tools/kmip-server/run-server.sh
# (--server-unpinned runs another and records the check as UNPIN, which is not a pass). The probe
# runs under the server's defaults and under each other setting it accepts
# (KMIP_DESTROYED_NAME_REUSE=reserve, KMIP_LEASE_STATES=active, KMIP_MAX_LEASE_SECONDS=0), the
# interop suite (integration/keytend-kmip-server/run-interop.sh) with the configured and the
# minimal setup, and the benchmark's smoke run (tools/bench/run.sh, --scale 0.05), all at once,
# each on servers of its own. The probe's all includes the full tls-issue-repeat from KMIP 1.4.
# live-pin fails if a live result the release would ship failed or is of another server build than
# the pin's
# (tools/release_reports.py pinned). live-run fails unless this run passed every live check it
# runs with --server, at every KMIP version (tools/release_reports.py complete): a run without
# --server cannot make a release, and tools/publish-release.sh refuses its ZIP.
set -uo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
out=
jdks="17 21 25"
integration=false
skip_verify=false
skip_api=false
skip_repro=false
server=
server_unpinned=false
baseline=
api_fail=auto
allow_dirty=false
keep_trees=false
# The arguments as release-check.txt records them, without a local path (the release's reports
# hold none, and tools/package-release.py refuses one): the run directory named, the server's
# Docker archive and the API baseline by their file names.
args=()
# shown PATH: a file argument's name; an image reference as given.
shown() { case $1 in /*|./*|../*|~*) basename -- "$1" ;; *) [ -f "$1" ] && basename -- "$1" || printf '%s\n' "$1" ;; esac; }
while [ $# -gt 0 ]; do
  case $1 in
    --out|--jdks|--server|--baseline) [ $# -ge 2 ] || { echo "$1 needs a value" >&2; exit 2; } ;;
  esac
  case $1 in
    --out) out=$2; args+=(--out "<run directory>"); shift 2; continue ;;
    --server|--baseline) args+=("$1" "$(shown "$2")") ;;
    *) args+=("$1") ;;
  esac
  case $1 in
    --jdks) jdks=$2; args+=("$2"); shift 2 ;;
    --integration) integration=true; shift ;;
    --skip-verify) skip_verify=true; shift ;;
    --skip-api) skip_api=true; shift ;;
    --skip-repro) skip_repro=true; shift ;;
    --server) server=$2; shift 2 ;;
    --server-unpinned) server_unpinned=true; shift ;;
    --baseline) baseline=$(cd "$(dirname "$2")" && pwd)/$(basename "$2"); shift 2 ;;
    --api-fail) api_fail=true; shift ;;
    --no-api-fail) api_fail=false; shift ;;
    --allow-dirty) allow_dirty=true; shift ;;
    --keep-trees) keep_trees=true; shift ;;
    -h|--help) sed -n '/^# The pre-release gate/,/^set -uo pipefail/{/^set /d;s/^# \{0,1\}//p}' "$0"; exit 0 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
if $server_unpinned && [ -z "$server" ]; then
  echo "--server-unpinned needs --server" >&2; exit 2
fi
if [ -n "$server" ] && [ -e "$server" ]; then server=$(cd "$(dirname "$server")" && pwd)/$(basename "$server"); fi
args="${args[*]}"
server_shown=$(shown "$server")

commit=$(git -C "$root" rev-parse HEAD)
epoch=$(git -C "$root" show -s --format=%ct HEAD)
if [ -n "$(git -C "$root" status --porcelain)" ]; then
  if ! $allow_dirty; then
    echo "The working tree has uncommitted changes; the gate checks commits only. Commit them, or" >&2
    echo "pass --allow-dirty to check HEAD ($commit) without them." >&2
    exit 2
  fi
  echo "WARNING: uncommitted changes are NOT checked; checking HEAD $commit" >&2
fi
[ -n "$out" ] || out=/tmp/keytend-kmip-release-check.$(date +%Y%m%dT%H%M%S)
if [ -e "$out" ] && [ -n "$(ls -A "$out")" ]; then echo "$out exists and is not empty" >&2; exit 2; fi
mkdir -p "$out/logs" "$out/validation"
out=$(cd "$out" && pwd)
logs=$out/logs
# The reports the binary ZIP carries as validation/ (tools/package-release.py --reports).
reports=$out/validation
# scrub SOURCE DEST: the report file or directory SOURCE copied to DEST with the server
# archive's and the baseline's paths reduced to their file names, and the run directory's, the
# checkout's and the home directory's paths named, not spelled out, also in gzip files (no local
# path goes into the binary ZIP; tools/package-release.py refuses one).
scrub() {
  local named=()
  [ -f "$server" ] && named+=(--replace "$server=$server_shown")
  [ -n "$baseline" ] && named+=(--replace "$baseline=$(basename -- "$baseline")")
  python3 "${check_tree:-$root}/tools/release_reports.py" scrub "$1" "$2" ${named[@]+"${named[@]}"} \
    --replace "$out=<run directory>" --replace "$root=<checkout>" --replace "$HOME=~"
}

trees=()
cleanup() {
  for tree in ${trees[@]+"${trees[@]}"}; do
    if $keep_trees; then echo "kept worktree $tree (git worktree remove --force $tree)"
    else git -C "$root" worktree remove --force "$tree" >/dev/null 2>&1 || true; fi
  done
}
trap cleanup EXIT

names=() results=() notes=()
record() {
  names+=("$2") results+=("$1") notes+=("$3")
  printf '  %-4s %-28s %s\n' "$1" "$2" "$3"
}

# A detached worktree of HEAD under the run directory.
new_tree() {
  local tree=$out/$1
  git -C "$root" worktree add --detach "$tree" "$commit" >"$logs/worktree-$1.log" 2>&1 || {
    echo "cannot create worktree $tree (see $logs/worktree-$1.log)" >&2; exit 1; }
  trees+=("$tree")
}
check_tree=
ensure_check_tree() { [ -n "$check_tree" ] || { new_tree check; check_tree=$out/check; }; }

jdk_home() {
  local var="JDK${1}_HOME" path candidate
  path="${!var:-}"
  if [ -z "$path" ]; then
    # The newest patch release SDKMAN has (version order, not name order: 21.0.13 after 21.0.4).
    while IFS= read -r candidate; do
      if [ -x "$candidate/bin/java" ]; then path=$candidate; fi
    done < <(printf '%s\n' "$HOME"/.sdkman/candidates/java/"$1".* | sort -V)
  fi
  [ -x "$path/bin/java" ] && echo "$path"
}

# mvn TREE JDK LOG ARGS...
mvn() {
  local tree=$1 jdk=$2 log=$3
  shift 3
  echo "\$ JAVA_HOME=$jdk mvnw -B -ntp $*" >"$log"
  JAVA_HOME="$jdk" PATH="$jdk/bin:$PATH" "$tree/mvnw" -B -ntp -f "$tree/pom.xml" "$@" >>"$log" 2>&1
}

# surefire DIR [CLASS]: "<tests> tests, <failures> failures, <errors> errors, <skipped> skipped";
# fails if any failed, or if CLASS has no report or ran no test.
surefire() {
  python3 -I - "$@" <<'PY'
import glob, sys, xml.etree.ElementTree as ET
directory, wanted = sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None
total = [0, 0, 0, 0]
found = False
for path in glob.glob(directory + '/**/TEST-*.xml', recursive=True):
    suite = ET.parse(path).getroot()
    counts = [int(suite.get(k, 0)) for k in ('tests', 'failures', 'errors', 'skipped')]
    if wanted is None or suite.get('name', '').endswith('.' + wanted):
        found = found or wanted is not None
        total = [a + b for a, b in zip(total, counts)]
print(f'{total[0]} tests, {total[1]} failures, {total[2]} errors, {total[3]} skipped')
sys.exit(1 if total[1] or total[2] or (wanted and (not found or total[0] == 0)) else 0)
PY
}

jdk17=$(jdk_home 17) || { echo "Set JDK17_HOME to a JDK 17 installation (the release JDK)" >&2; exit 2; }
{
  echo "commit $commit ($(git -C "$root" describe --always --tags HEAD 2>/dev/null))"
  echo "epoch $epoch"
  echo "started $(date -Is) on $(hostname)"
  echo "arguments $args"
  for v in 17 21 25; do home=$(jdk_home "$v") && echo "jdk$v $home: $("$home/bin/java" -version 2>&1 | head -1)"; done
} >"$out/run.txt"
echo "release check of $commit in $out"
sed 's/^/  /' "$out/run.txt"

if $integration && [ -z "${DOCKER_HOST:-}" ] && [ -S "/run/user/$(id -u)/podman/podman.sock" ]; then
  DOCKER_HOST=unix:///run/user/$(id -u)/podman/podman.sock
  export DOCKER_HOST
  export TESTCONTAINERS_RYUK_DISABLED=${TESTCONTAINERS_RYUK_DISABLED:-true}
fi

# The reactor's modules, from the parent POM: every one's test reports are kept.
modules=$(python3 -I -c 'import sys, xml.etree.ElementTree as E; print(" ".join(m.text for m in E.parse(sys.argv[1]).getroot().iter("{http://maven.apache.org/POM/4.0.0}module")))' "$root/pom.xml")

# copy_reports TREE DIR: each module's Surefire and Failsafe reports, as DIR/MODULE-KIND.
copy_reports() {
  local module kind
  mkdir -p "$2"
  for module in $modules; do
    for kind in surefire-reports failsafe-reports; do
      [ -d "$1/$module/target/$kind" ] && cp -r "$1/$module/target/$kind" "$2/$module-$kind"
    done
  done
}

# Whether the verify runs include JDK $1.
verifies() { case " $jdks " in *" $1 "*) return 0 ;; esac; return 1; }

if ! $skip_verify; then
  ensure_check_tree
  # ./mvnw test, which stops before package, as a contributor or an IDE runs it: every module's
  # tests run against the SDK's classes, not its JAR (the JAR's own checks are integration-test's).
  # The SDK's own tests run the same way in verify-jdk17 (same JDK, same classes), so they are
  # skipped here when that runs.
  # The modules after the SDK build four at a time (not the distribution builds, which stay serial).
  test_args=(-T 4)
  verifies 17 && test_args+=(-Dsdk.skipTests)
  mvn "$check_tree" "$jdk17" "$logs/test-jdk17.log" clean test ${test_args[@]+"${test_args[@]}"}
  status=$?
  copy_reports "$check_tree" "$out/surefire-test-jdk17"
  note=$(surefire "$out/surefire-test-jdk17")
  result=PASS
  [ $status -eq 0 ] || result=FAIL
  for module in $modules; do
    [ "$module" = sdk ] && verifies 17 && continue
    [ -n "$(ls -A "$out/surefire-test-jdk17/$module-surefire-reports" 2>/dev/null)" ] || {
      result=FAIL; note="$note; no reports from $module"; }
  done
  verifies 17 && note="$note (the SDK's in verify-jdk17)"
  record "$result" "test-jdk17" "$note; logs/test-jdk17.log"
  for v in $jdks; do
    jdk=$(jdk_home "$v") || { record FAIL "verify-jdk$v" "no JDK $v (set JDK${v}_HOME)"; continue; }
    profiles=()
    [ "$v" = 17 ] && profiles+=(-Pdistribution -Dkeytend.matrix=full)
    # Static analysis once per check: SpotBugs on 17, Error Prone on 21 (the same sources and
    # versions of both on every JDK); a JDK without the other's run keeps it.
    [ "$v" != 17 ] && verifies 17 && profiles+=(-Dspotbugs.skip=true)
    [ "$v" != 21 ] && [ "$v" -ge 21 ] 2>/dev/null && verifies 21 && profiles+=('-P!errorprone')
    if $integration; then
      profiles+=(-Pintegration)
    fi
    mvn "$check_tree" "$jdk" "$logs/verify-jdk$v.log" clean verify -T 4 ${profiles[@]+"${profiles[@]}"}
    status=$?
    # The Surefire and Failsafe reports stay in the run directory: they are not the release's
    # reports ($reports), which the binary ZIP carries.
    surefire_dir=$out/surefire-jdk$v
    copy_reports "$check_tree" "$surefire_dir"
    note=$(surefire "$surefire_dir")
    [ $status -eq 0 ] && [ -n "$(ls -A "$surefire_dir")" ] && result=PASS || result=FAIL
    record "$result" "verify-jdk$v ${profiles[*]}" "$note; logs/verify-jdk$v.log"
    note=$(surefire "$surefire_dir" PersistedFormatsTest) && result=PASS || result=FAIL
    record "$result" "format-fixtures-jdk$v" "PersistedFormatsTest: $note"
    note=$(surefire "$surefire_dir" LicenseHeadersTest) && result=PASS || result=FAIL
    record "$result" "license-headers-jdk$v" "LicenseHeadersTest: $note"
  done
fi

ensure_check_tree
python3 "$check_tree/tools/license_headers.py" --check >"$logs/license-headers.log" 2>&1 && result=PASS || result=FAIL
record "$result" license_headers.py "$(tail -1 "$logs/license-headers.log")"

# What has newer releases (docs/dependencies.md, "Keeping versions current"): a report, recorded
# with the run; it passes when the report was written.
mvn "$check_tree" "$jdk17" "$logs/versions.log" versions:display-dependency-updates \
  versions:display-plugin-updates versions:display-property-updates && result=PASS || result=FAIL
record "$result" dependency-updates "$(grep -c -- ' -> ' "$logs/versions.log") newer releases listed; logs/versions.log"

if ! $skip_api && ! "$check_tree/tools/api-baseline.sh" --version >/dev/null 2>&1; then
  # Exit 3: sdk/pom.xml pins no baseline (no earlier release); anything else is a malformed pin.
  "$check_tree/tools/api-baseline.sh" --version >"$logs/api-baseline.log" 2>&1
  [ $? -eq 3 ] && record SKIP api-baseline "$(tail -1 "$logs/api-baseline.log")" || record FAIL api-baseline "logs/api-baseline.log"
elif ! $skip_api; then
  version=$("$check_tree/tools/api-baseline.sh" --version)
  # An incompatible change fails against a baseline of the same 0.x minor version, or from 1.0 the
  # same major; a release of a later series may make one, and its notes must say so
  # (docs/compatibility.md, tools/api-baseline.sh --fails).
  # Fails closed: unless --fails exits 0 and prints exactly fail or report, api-compat is FAIL.
  series=$("$check_tree/tools/api-baseline.sh" --fails 2>"$logs/api-series.log") && series_status=0 || series_status=$?
  case "$series_status:$series" in
    0:fail|0:report) ;;
    *) series_error="tools/api-baseline.sh --fails exited $series_status and printed \"$series\", not fail or report; logs/api-series.log"
       series=error ;;
  esac
  [ "$api_fail" = auto ] && api_fail=$([ "$series" = report ] && echo false || echo true)
  if [ "$series" = error ]; then
    record FAIL api-compat "$series_error"
  elif "$check_tree/tools/api-baseline.sh" ${baseline:+"$baseline"} >"$logs/api-baseline.log" 2>&1; then
    record PASS api-baseline "keytend-kmip-$version.jar, SHA-256 checked"
    # SpotBugs already ran on this commit's SDK in verify-jdk17.
    api_args=()
    ! $skip_verify && verifies 17 && api_args+=(-Dspotbugs.skip=true)
    mvn "$check_tree" "$jdk17" "$logs/api-compat.log" -pl sdk clean verify -Papi-compat -DskipTests \
      -Dapi.compat.fail=$api_fail ${api_args[@]+"${api_args[@]}"}
    status=$?
    [ -d "$check_tree/sdk/target/japicmp" ] && cp -r "$check_tree/sdk/target/japicmp" "$out/japicmp"
    note=$(python3 -I - "$out/japicmp/api-compat.xml" <<'PY' 2>/dev/null
import sys, xml.etree.ElementTree as ET
root = ET.parse(sys.argv[1]).getroot()
classes = root.findall('.//class')
binary = sum(1 for e in root.iter() if e.get('binaryCompatible') == 'false')
source = sum(1 for e in root.iter() if e.get('sourceCompatible') == 'false')
print(f'{len(classes)} classes changed, {binary} binary- and {source} source-incompatible elements')
PY
)
    [ $status -eq 0 ] && [ -n "$note" ] && result=PASS || result=FAIL
    # Incompatible changes reported against an earlier series: RELEASE.md's section of the release
    # lists them under "## Incompatible changes".
    case $note in
      *" 0 binary- and 0 source-incompatible"*|"") ;;
      *) if [ "$api_fail" = false ] \
           && ! python3 -I - "$check_tree/RELEASE.md" "$check_tree/pom.xml" <<'PY'
import re, sys, xml.etree.ElementTree as E
release = E.parse(sys.argv[2]).getroot().findtext('{http://maven.apache.org/POM/4.0.0}version')
release = release.split('-', 1)[0]
text = open(sys.argv[1], encoding='utf-8').read()
start = re.search(r'^# keytend-kmip ' + re.escape(release) + r'\b.*$', text, re.M)
end = start and re.search(r'^# ', text[start.end():], re.M)
section = start and text[start.end():start.end() + end.start() if end else len(text)]
sys.exit(0 if section and re.search(r'^## Incompatible changes', section, re.M) else 1)
PY
         then
           result=FAIL
           note="$note; RELEASE.md's section of the release has no \"## Incompatible changes\""
         fi ;;
    esac
    record "$result" api-compat \
      "vs $version (${series:-?}, fail=$api_fail): ${note:-no report}; japicmp/"
  else
    record FAIL api-baseline "logs/api-baseline.log"
  fi
fi

# build_distribution NAME MAVEN-ARGS...: the distribution built (clean -Pdistribution MAVEN-ARGS,
# as docs/releasing.md builds it) in a fresh worktree ($out/tree-NAME, removed at exit).
build_distribution() {
  local name=$1
  shift
  new_tree "tree-$name"
  mvn "$out/tree-$name" "$jdk17" "$logs/distribution-$name.log" clean -Pdistribution "$@" -DskipTests \
    -Dproject.build.outputTimestamp="$epoch"
}

# package_distribution NAME: that build packaged with the run's reports (package-release.py
# --reports); artifacts copied to $out/dist-NAME, which is kept.
package_distribution() {
  local name=$1 tree=$out/tree-$1 version dest status=0
  env -u KEYTEND_GPG_KEY python3 "$tree/tools/package-release.py" --reports "$reports" \
    --in-release-check >"$logs/package-$name.log" 2>&1 || status=1
  version=$(python3 -I -c 'import sys, xml.etree.ElementTree as E; print(E.parse(sys.argv[1]).getroot().findtext("{http://maven.apache.org/POM/4.0.0}version"))' "$tree/pom.xml")
  dest=$out/dist-$name/artifacts
  mkdir -p "$dest"
  # Every module's JARs (keytend-kmip*-VERSION*.jar: the JAR, -sources, -javadoc, the samples'
  # -tests; keytend-kmip-testing's too, which is published but not in the ZIPs), the SDK's runtime
  # JARs (sdk/target/lib/, which the server probe runs with), each module's SBOM, the binary ZIP
  # (which also holds the applications' third-party JARs and the reports), the source ZIP, the
  # test-only assets beside them (the same files as testing/target's), each published file's
  # .sha256 and SHA256SUMS.
  for f in "$tree"/*/target/keytend-kmip*-"$version"*.jar "$tree"/sdk/target/lib/*.jar \
      "$tree"/*/target/keytend-kmip*-"$version"-cyclonedx.json \
      "$tree"/target/releases/keytend-kmip-"$version".zip "$tree"/target/releases/keytend-kmip-"$version"-src.zip \
      "$tree"/target/releases/SHA256SUMS "$tree"/target/releases/*.sha256; do
    [ -f "$f" ] && cp "$f" "$dest/"
  done
  # The test-only assets beside the ZIPs must be testing/target's (their names are the same here).
  for f in "$tree"/target/releases/keytend-kmip-testing-"$version"*; do
    case $f in *.sha256|*.asc) continue ;; esac
    [ -e "$f" ] || continue
    cmp -s "$f" "$dest/$(basename "$f")" || { echo "$f differs from testing/target's" >&2; status=1; }
  done
  (cd "$dest" && sha256sum -- * >../sha256.txt 2>/dev/null)
  return $status
}

# doc_block FILE NAME: the fenced block after the line "<!-- release-check: NAME -->" in FILE; with
# several such markers, every block, one after another.
doc_block() {
  python3 -I - "$@" <<'PY'
import re, sys
text = open(sys.argv[1], encoding='utf-8').read()
blocks = re.findall(r'^<!-- release-check: ' + re.escape(sys.argv[2]) + r' -->\n```[a-z]*\n(.*?)^```$', text,
                    re.M | re.S)
if not blocks:
    sys.exit('%s: no block marked release-check: %s' % (sys.argv[1], sys.argv[2]))
sys.stdout.write(''.join(blocks))
PY
}

# run_block DIR LOG FILE NAME: runs that block in DIR with bash -euo pipefail, X.Y.Z as $version, and
# gpg a stub (the check's release is unsigned; PackageReleaseSigningTest and the publish script's
# test check signatures). mvn is $user_bin/mvn: the tree's wrapper, on an empty local repository.
run_block() {
  local dir=$1 log=$2 block
  block=$(doc_block "$3" "$4" 2>&1) || { echo "$block" >>"$log"; return 1; }
  block=${block//X.Y.Z/$version}
  {
    echo "\$ (cd $dir) # $3, release-check: $4"
    echo "$block"
  } >>"$log"
  (cd "$dir" && PATH="$user_bin:$PATH" bash -euo pipefail -c \
    'gpg() { echo "gpg $* (not run: the release check packages unsigned)"; }; '"$block") >>"$log" 2>&1
}

# user_commands TREE: what the docs tell users to run, on the release TREE packaged, in empty
# directories: SECURITY.md's verification of a whole download, of the binary ZIP alone (and that
# it still catches a wrong hash), of the source ZIP alone, and of the in-memory server alone; a
# build of the unpacked source ZIP; docs/releasing.md's check of a release; publish-release.sh
# --unsigned; and getting-started's install of the SDK and the
# in-memory server from the release into an empty local Maven repository, then its test, built
# and run against them. The local repository reads plugins from the caller's, without dev.keytend
# (a build from source puts the project's POMs there).
user_commands() {
  local tree=$1 releases=$1/target/releases work=$out/user-commands log=$logs/user-commands.log
  local version release failed=() f entry
  version=$(python3 -I -c 'import sys, xml.etree.ElementTree as E; print(E.parse(sys.argv[1]).getroot().findtext("{http://maven.apache.org/POM/4.0.0}version"))' "$tree/pom.xml")
  # The release a pre-release X.Y.Z-rc.N is of: its RELEASE.md section is the notes.
  release=${version%%-*}
  local zip=keytend-kmip-$version.zip src=keytend-kmip-$version-src.zip testing=keytend-kmip-testing-$version
  mkdir -p "$work"
  : >"$log"
  user_bin=$work/bin
  mkdir -p "$user_bin" "$work/m2" "$work/m2-tail/dev"
  local caller_repo=${MAVEN_REPO_LOCAL:-$HOME/.m2/repository}
  for entry in "$caller_repo"/*; do
    [ "$(basename "$entry")" = dev ] || ln -s "$entry" "$work/m2-tail/$(basename "$entry")"
  done
  for entry in "$caller_repo"/dev/*; do
    [ -e "$entry" ] && [ "$(basename "$entry")" != keytend ] && ln -s "$entry" "$work/m2-tail/dev/$(basename "$entry")"
  done
  printf '#!/usr/bin/env bash\nJAVA_HOME=%q PATH=%q exec %q -B -ntp -Dmaven.repo.local=%q -Dmaven.repo.local.tail=%q "$@"\n' \
    "$jdk17" "$jdk17/bin:$PATH" "$tree/mvnw" "$work/m2" "$work/m2-tail" >"$user_bin/mvn"
  chmod +x "$user_bin/mvn"
  download() {   # download NAME FILE...: an empty directory holding copies of those assets
    mkdir -p "$work/$1"
    local name=$1; shift
    for f in "$@"; do cp "$releases/$f" "$work/$name/"; done
  }
  download all "$zip" "$src" "$testing.jar" "$testing-sources.jar" "$testing-cyclonedx.json" SHA256SUMS
  for f in "$zip" "$src" "$testing.jar" "$testing-sources.jar" "$testing-cyclonedx.json"; do cp "$releases/$f.sha256" "$work/all/"; done
  run_block "$work/all" "$log" "$tree/SECURITY.md" verify || failed+=("SECURITY.md verify")
  rm -rf "$work/all/keytend-kmip-$version"
  run_block "$work/all" "$log" "$tree/docs/releasing.md" verify-all || failed+=("releasing.md verify-all")
  download zip-only "$zip" "$zip.sha256" SHA256SUMS
  run_block "$work/zip-only" "$log" "$tree/SECURITY.md" verify || failed+=("SECURITY.md verify, the ZIP alone")
  # The same with one JAR of the ZIP listed with another hash: the block must fail.
  download wrong "$zip" "$zip.sha256" SHA256SUMS
  sed -i "s/^[0-9a-f]\{64\}  \(keytend-kmip-$version\/lib\/keytend-kmip-$version\.jar\)\$/$(printf '0%.0s' $(seq 64))  \1/" "$work/wrong/SHA256SUMS"
  if ! grep -q "^0\{64\}  keytend-kmip-$version/lib/keytend-kmip-$version.jar\$" "$work/wrong/SHA256SUMS"; then
    failed+=("no line of the SDK JAR in SHA256SUMS")
  elif run_block "$work/wrong" "$log" "$tree/SECURITY.md" verify; then
    failed+=("SECURITY.md verify passed a wrong hash of the ZIP's SDK JAR")
  fi
  download testing-only "$testing.jar" "$testing.jar.sha256"
  run_block "$work/testing-only" "$log" "$tree/SECURITY.md" verify-testing || failed+=("SECURITY.md verify-testing")
  # The source ZIP alone, then a build of it, without Git: every module packages.
  download source-only "$src" "$src.sha256"
  run_block "$work/source-only" "$log" "$tree/SECURITY.md" verify-source || failed+=("SECURITY.md verify-source")
  local unpacked=$work/source-only/keytend-kmip-$version-src
  if [ -d "$unpacked" ]; then
    { echo "\$ (cd $unpacked) mvnw -B -ntp -T 4 package -DskipTests"
      JAVA_HOME="$jdk17" PATH="$jdk17/bin:$PATH" "$unpacked/mvnw" -B -ntp -T 4 -f "$unpacked/pom.xml" \
        package -DskipTests; } >>"$log" 2>&1 || failed+=("a build of the source ZIP")
    [ -f "$unpacked/sdk/target/keytend-kmip-$version.jar" ] && [ -f "$unpacked/cli/target/keytend-kmip-cli-$version.jar" ] \
      || failed+=("the source ZIP's build made no SDK or CLI JAR")
  else
    failed+=("the source ZIP did not unpack to keytend-kmip-$version-src/")
  fi
  # The publish script's checks, on a copy of the release; the notes from RELEASE.md as they will
  # be once its heading drops "(unreleased)" (step 1).
  mkdir -p "$work/publish"
  cp "$releases"/* "$work/publish/"
  sed "s/^# keytend-kmip $release (unreleased)\$/# keytend-kmip $release/" "$tree/RELEASE.md" >"$work/RELEASE.md"
  { echo "\$ tools/publish-release.sh $version --dir $work/publish --unsigned --release-md $work/RELEASE.md"
    "$tree/tools/publish-release.sh" "$version" --dir "$work/publish" --unsigned --release-md "$work/RELEASE.md"; } \
    >>"$log" 2>&1 || failed+=("publish-release.sh --unsigned")
  # getting-started: the SDK from the ZIP, the in-memory server beside it, into an empty repository.
  download maven "$zip" "$testing.jar"
  (cd "$work/maven" && unzip -q "$zip") || failed+=("unzip")
  run_block "$work/maven" "$log" "$tree/docs/getting-started.md" install-sdk || failed+=("getting-started install-sdk")
  run_block "$work/maven" "$log" "$tree/docs/getting-started.md" install-testing || failed+=("getting-started install-testing")
  local consumer=$work/maven/consumer dependencies test_class
  mkdir -p "$consumer/src/test/java"
  dependencies=$(doc_block "$tree/docs/getting-started.md" dependency) || failed+=("getting-started dependency blocks")
  test_class=$(doc_block "$tree/docs/getting-started.md" test) || failed+=("getting-started test block")
  printf '%s\n' "$test_class" >"$consumer/src/test/java/$(sed -n 's/^class \([A-Za-z0-9_]*\).*/\1/p' <<<"$test_class" | head -1).java"
  python3 -I - "$tree/pom.xml" "$dependencies" >"$consumer/pom.xml" <<'PY' || failed+=("the consumer POM")
import sys, xml.etree.ElementTree as ET
ns = {'m': 'http://maven.apache.org/POM/4.0.0'}
parent = ET.parse(sys.argv[1]).getroot()
def plugin(artifact):
    for p in parent.iterfind('m:build/m:pluginManagement/m:plugins/m:plugin', ns):
        if p.findtext('m:artifactId', namespaces=ns) == artifact:
            return p.findtext('m:version', namespaces=ns)
    sys.exit('no ' + artifact + ' in the parent POM')
junit = parent.findtext('m:properties/m:junit.version', namespaces=ns)
plugins = ''.join(f'<plugin><groupId>org.apache.maven.plugins</groupId><artifactId>{a}</artifactId>'
                  f'<version>{plugin(a)}</version></plugin>'
                  for a in ['maven-resources-plugin', 'maven-compiler-plugin', 'maven-surefire-plugin'])
print(f"""<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>example</groupId><artifactId>consumer</artifactId><version>1</version>
  <properties><maven.compiler.release>17</maven.compiler.release>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding></properties>
  <dependencies>
{sys.argv[2]}
    <dependency><groupId>org.junit.jupiter</groupId><artifactId>junit-jupiter</artifactId>
      <version>{junit}</version><scope>test</scope></dependency>
  </dependencies>
  <build><plugins>{plugins}</plugins></build>
</project>""")
PY
  { echo "\$ mvn -f $consumer/pom.xml test"; "$user_bin/mvn" -f "$consumer/pom.xml" test; } >>"$log" 2>&1 \
    || failed+=("getting-started's test against the installed release")
  local tests
  tests=$(surefire "$consumer/target/surefire-reports") || failed+=("getting-started's test: $tests")
  case $tests in "0 tests"*) failed+=("getting-started's test ran no test") ;; esac
  [ ${#failed[@]} -eq 0 ] && result=PASS || result=FAIL
  local summary="verify (all, binary ZIP alone, a wrong hash refused, source ZIP alone and built, in-memory server alone), releasing.md, publish --unsigned, install from the release + test ($tests)"
  [ ${#failed[@]} -eq 0 ] || summary="failed: $(IFS=';'; echo "${failed[*]}")"
  record "$result" user-commands "$summary; logs/user-commands.log"
}

# central_bundle TREE: after TREE's Central dry run and packaging, every JAR of the Central bundle
# must be the one in its module's target/, every one SHA256SUMS lists must have that hash, and
# every JAR of the published modules SHA256SUMS lists must be in the bundle: Central and the GitHub
# release have the same bytes (SECURITY.md), whatever the umask the build ran under.
central_bundle() {
  local tree=$1 log=$logs/central-bundle.log
  if ! grep -q 'Skipping the upload of the bundle' "$logs/distribution-b.log"; then
    record FAIL central-bundle "the dry run did not say it skipped the upload; logs/distribution-b.log"
    return
  fi
  python3 -I - "$tree" >"$log" 2>&1 <<'PY' && result=PASS || result=FAIL
import glob, hashlib, os, sys, zipfile
tree = sys.argv[1]
sha = lambda content: hashlib.sha256(content).hexdigest()
listed = {}
for line in open(os.path.join(tree, 'target/releases/SHA256SUMS'), encoding='utf-8'):
    digest, _, path = line.rstrip('\n').partition('  ')
    listed[os.path.basename(path)] = digest
failed, compared = [], 0
with zipfile.ZipFile(os.path.join(tree, 'target/central-publishing/central-bundle.zip')) as bundle:
    jars = {os.path.basename(n): sha(bundle.read(n)) for n in bundle.namelist() if n.endswith('.jar')}
for name, digest in sorted(jars.items()):
    built = glob.glob(os.path.join(tree, '*/target', name))
    if len(built) != 1 or sha(open(built[0], 'rb').read()) != digest:
        failed.append(f'{name}: not the one in target/')
    if name in listed:
        compared += 1
        print(('same     ' if listed[name] == digest else 'DIFFERENT'), digest, listed[name], name)
        if listed[name] != digest:
            failed.append(f'{name}: not the SHA-256 SHA256SUMS lists')
missing = sorted(n for n in listed if n.endswith('.jar') and n.startswith('keytend-kmip')
                 and not n.startswith(('keytend-kmip-cli-', 'keytend-kmip-integration-')) and n not in jars)
failed += [f'{n}: listed in SHA256SUMS, not in the bundle' for n in missing]
for f in failed:
    print('FAILED', f)
print(f'{compared} of the bundle\'s {len(jars)} JARs are in SHA256SUMS, ' + (
    'every one with its hash' if not failed else f'{len(failed)} failures'))
sys.exit(1 if failed or not compared else 0)
PY
  record "$result" central-bundle "$(tail -1 "$log") (umask 0077); logs/central-bundle.log"
}

sdk_jar() {
  local f
  for f in "$1"/keytend-kmip-[0-9]*.jar; do
    case $f in *-tests.jar|*-sources.jar|*-javadoc.jar) ;; *) [ -f "$f" ] && echo "$f" && return 0 ;; esac
  done
  return 1
}

# Build: the two distribution builds, each under a umask of its own, whatever the caller's: an
# ordinary one, then a restrictive one (files 0600, directories 0700 on disk, which the archivers
# copy into the JARs). The second is docs/releasing.md's Central deploy, a dry run: unsigned,
# nothing installed or uploaded. They are packaged after the reports (below).
if ! $skip_repro; then
  trees+=("$out/tree-a" "$out/tree-b")   # made in subshells, which have their own copy of trees
  (umask 0022; build_distribution a verify) && built_a=true || built_a=false
  (umask 0077; export TZ=Pacific/Chatham; build_distribution b -Pcentral deploy -DskipUpload=true \
    -Dmaven.install.skip=true -Dgpg.skip=true) && built_b=true || built_b=false
fi

# Test against keytend-kmip-server, on the first distribution build's JARs: the probe under the
# server's defaults and under each other setting it accepts (its all includes the full
# tls-issue-repeat from KMIP 1.4),
# the interop suite with the configured and the minimal setup, and the
# benchmark's smoke run. They run at once, each on servers of its own. Each run's results replace
# their entries in validation/live-server.json, and its logs go beside it.
if [ -n "$server" ]; then
  version=$(python3 -I -c 'import sys, xml.etree.ElementTree as E; print(E.parse(sys.argv[1]).getroot().findtext("{http://maven.apache.org/POM/4.0.0}version"))' "$root/pom.xml")
  if [ -n "$(sdk_jar "$out/tree-a/sdk/target" 2>/dev/null)" ]; then
    jars=$out/tree-a
  else
    mvn "$check_tree" "$jdk17" "$logs/server-package.log" -pl sdk,testing,integration-tests -am clean package -DskipTests
    jars=$check_tree
  fi
  jar=$(sdk_jar "$jars/sdk/target")
  testing_jar=$jars/testing/target/keytend-kmip-testing-$version.jar
  interop_classpath=$jar:$jars/integration-tests/target/keytend-kmip-integration-$version.jar
  interop_classpath=$interop_classpath:$testing_jar
  helper="$check_tree/tools/kmip-server/run-server.sh"
  pin="$check_tree/tools/kmip-server/pinned-image.properties"
  pinned_name="$(sed -n 's/^name=//p' "$pin") $(sed -n 's/^version=//p' "$pin")"
  # The helper checks the archive's SHA-256 and the image ID against the pin; 0 pinned, 10 another
  # image run under --server-unpinned, anything else refused.
  image=$(KEYTEND_SERVER_UNPINNED=$($server_unpinned && echo 1 || echo 0) "$helper" image "$server" 2>"$logs/server-image.log")
  pinned=$?
  unpinned_env=$([ $pinned -eq 10 ] && echo 1 || echo 0)
  if [ $pinned -eq 0 ]; then
    build="$pinned_name (the pinned image $image)"
  else
    build="$server_shown (image ${image:-none}) is NOT the pinned $pinned_name"
  fi
  # live NAME RESULT NOTE: an unpinned image never passes the gate: UNPIN (an experiment that
  # passed) or FAIL.
  live() {
    local result=$2
    if [ $pinned -ne 0 ]; then
      if $server_unpinned && [ "$result" = PASS ]; then result=UNPIN; else result=FAIL; fi
    fi
    record "$result" "$1" "$build; $3"
  }
  if [ $pinned -eq 0 ] || [ $pinned -eq 10 ]; then
    server_version=$(KEYTEND_SERVER_IMAGE=$image KEYTEND_SERVER_UNPINNED=$unpinned_env "$helper" version 2>>"$logs/server-image.log" | head -1)
    identity=(--server "${server_version:-$pinned_name}" --image "$image"
      --pinned "$([ $pinned -eq 0 ] && echo yes || echo no)" --jdk 17 --date "$(date -u +%F)")
    # Every live tool runs the pinned image (or, with --server-unpinned, the given one) on JDK 17.
    server_env=(KEYTEND_SERVER_IMAGE="$image" KEYTEND_SERVER_UNPINNED="$unpinned_env"
      JAVA_HOME="$jdk17" PATH="$jdk17/bin:$PATH")
    # The probe's runs: NAME, scenarios, versions and the server setting (KMIP_* variables reach
    # the server; none is its defaults). The settings are those the probe accepts besides the
    # defaults (tools/server-probe/README.md, "Configuration").
    all="1.1 1.2 1.4 2.1 3.0"
    probes=("server-probe|all|$all|"
      "server-probe-name-reuse-reserve|all|$all|KMIP_DESTROYED_NAME_REUSE=reserve"
      "server-probe-lease-states-active|all|$all|KMIP_LEASE_STATES=active"
      "server-probe-max-lease-0|raw-leases,tls|1.4 2.1 3.0|KMIP_MAX_LEASE_SECONDS=0")
    # The benchmark's smoke run: every scenario against two servers, twenty times shorter. It
    # checks the tool; its figures are not results.
    scale=0.05
    # background NAME COMMAND...: COMMAND in the background, its output in logs/NAME.log and its
    # exit status in NAME.exit.
    background() {
      local name=$1
      shift
      ( "$@" >"$logs/$name.log" 2>&1; echo $? >"$out/$name.exit" ) &
    }
    exited() { [ "$(cat "$out/$1.exit" 2>/dev/null)" = 0 ]; }
    for spec in "${probes[@]}"; do
      IFS='|' read -r name scenarios versions setting <<<"$spec"
      background "$name" env ${setting:+"$setting"} "${server_env[@]}" \
        "$check_tree/tools/server-probe/run.sh" --jar "$jar" --scenarios "$scenarios" \
        --versions "$versions" --work "$out/$name"
    done
    for setup in configured minimal; do
      name=interop$([ $setup = configured ] || echo "-$setup")
      background "$name" env "${server_env[@]}" \
        "$check_tree/integration/keytend-kmip-server/run-interop.sh" --setup "$setup" \
        --classpath "$interop_classpath" --work "$out/$name"
    done
    background bench-smoke env "${server_env[@]}" "$check_tree/tools/bench/run.sh" --jar "$jar" \
      --testing-jar "$testing_jar" --topologies live --versions "1.4 2.1 3.0" --scale "$scale" \
      --work "$out/bench"
    wait
    for spec in "${probes[@]}"; do
      IFS='|' read -r name scenarios versions setting <<<"$spec"
      exited "$name" && result=PASS || result=FAIL
      python3 "$check_tree/tools/release_reports.py" probe "$reports/live-server.json" \
        "$out/$name" --scenarios "$scenarios" ${setting:+--env "$setting"} "${identity[@]}" \
        >>"$logs/$name.log" 2>&1 || result=FAIL
      mkdir -p "$reports/$name"
      for log in "$out/$name"/v*/probe.log; do
        [ -f "$log" ] && scrub "$log" "$reports/$name/$(basename "$(dirname "$log")").log"
      done
      summaries=$(grep -h 'SUMMARY' "$out/$name"/v*/probe.log 2>/dev/null | tr '\n' ' ')
      live "$name" "$result" "${setting:+$setting: }${summaries}logs/$name.log"
    done
    # The interop suite: the configured setup, where every program must exit 0, and the minimal
    # one (the suite on a bare server), which must fail exactly the checks a bare server refuses
    # (tools/release_reports.py, minimal_refusals).
    for setup in configured minimal; do
      name=interop$([ $setup = configured ] || echo "-$setup")
      result=PASS
      [ $setup = minimal ] || exited "$name" || result=FAIL
      python3 "$check_tree/tools/release_reports.py" interop "$reports/live-server.json" \
        "$logs/$name.log" --setup "$setup" --work "$out/$name" "${identity[@]}" \
        >"$out/$name.entries" 2>&1 || result=FAIL
      cat "$out/$name.entries" >>"$logs/$name.log"
      mkdir -p "$reports/$name"
      scrub "$logs/$name.log" "$reports/$name/run.log"
      for log in "$out/$name"/*/v*/out.log; do
        program=$(basename "$(dirname "$(dirname "$log")")")
        [ -f "$log" ] && scrub "$log" "$reports/$name/$program-$(basename "$(dirname "$log")").log"
      done
      runs=$(grep -c '^KMIP .* exit=' "$logs/$name.log")
      if [ $setup = minimal ]; then
        note="$(grep -c '^PASS ' "$out/$name.entries") of $runs versions failed only the checks"
        note="$note a bare server refuses"
      else
        note="$(grep -c ' exit=0' "$logs/$name.log") of $runs program runs passed"
      fi
      live "$name" "$result" "$setup setup: $note; logs/$name.log"
    done
    exited bench-smoke && result=PASS || result=FAIL
    python3 "$check_tree/tools/release_reports.py" bench "$reports/live-server.json" "$out/bench" \
      --scale "$scale" "${identity[@]}" >>"$logs/bench-smoke.log" 2>&1 || result=FAIL
    mkdir -p "$reports/bench-smoke"
    for log in "$out"/bench/live-v*/bench.log; do
      [ -f "$log" ] && scrub "$log" "$reports/bench-smoke/$(basename "$(dirname "$log")").log"
    done
    note="KMIP 1.4, 2.1 and 3.0 at --scale $scale, a smoke run (its figures are not results)"
    live bench-smoke "$result" "$note; logs/bench-smoke.log"
  else
    note=$(tail -1 "$logs/server-image.log")
    [ -f "$server" ] && note=${note//"$server"/$server_shown}
    live server-probe FAIL "not run: $note"
  fi
fi

# The run's own live results: every live check the release check runs with --server, at every KMIP
# version, passed in this run on the pinned image. Without --server none is there, and the run
# cannot make a release (tools/publish-release.sh refuses the same).
python3 "$check_tree/tools/release_reports.py" complete "$reports/live-server.json" \
  >"$logs/live-run.log" 2>&1 && result=PASS || result=FAIL
if [ $result = PASS ]; then
  record PASS live-run "$(tail -1 "$logs/live-run.log")"
elif [ -z "$server" ]; then
  record FAIL live-run "not run: --server is needed to make a release; logs/live-run.log"
else
  record FAIL live-run "$(sed -n 's/^  //p' "$logs/live-run.log" | head -1); logs/live-run.log"
fi

# The live results the release would ship, the recorded ones with this run's over them: each of
# the pinned server build, and recorded only when the release check cannot run it
# (tools/release_reports.py pinned; the packaging and the publish script refuse the same).
python3 "$check_tree/tools/release_reports.py" pinned \
  "$check_tree/validation/recorded/live-server.json" --run "$reports/live-server.json" \
  >"$logs/live-pin.log" 2>&1 && result=PASS || result=FAIL
if [ $result = PASS ]; then
  record PASS live-pin "$(tail -1 "$logs/live-pin.log")"
else
  record FAIL live-pin "$(sed -n 's/^  //p' "$logs/live-pin.log" | head -1); logs/live-pin.log"
fi

# Report: the workflow suite's and the catalog's summaries of the -Pintegration verify runs, and
# the SBOM scan.
if $integration && ! $skip_verify; then
  junit=()
  for v in $jdks; do [ -d "$out/surefire-jdk$v" ] && junit+=(--junit "$v=$out/surefire-jdk$v"); done
  # Written in the run directory, then copied to the reports with local paths named.
  {
    python3 "$check_tree/tools/summarize-validation.py" --out "$out/workflows" \
      --reports "$check_tree/integration/reports" ${junit[@]+"${junit[@]}"} &&
    python3 "$check_tree/tools/render-validation.py" --dir "$out/workflows" &&
    python3 "$check_tree/tools/summarize-catalog.py" --out "$out/catalog" \
      --reports "$check_tree/integration/reports/catalog" ${junit[@]+"${junit[@]}"} &&
    python3 "$check_tree/tools/render-catalog.py" --dir "$out/catalog" &&
    scrub "$out/workflows" "$reports/workflows" && scrub "$out/catalog" "$reports/catalog"
  } >"$logs/reports.log" 2>&1 && result=PASS || result=FAIL
  record "$result" reports "workflow suite and catalog summaries (validation/workflows, validation/catalog); logs/reports.log"
fi
if command -v osv-scanner >/dev/null; then
  sboms=$(ls "$out"/tree-a/*/target/keytend-kmip*-cyclonedx.json 2>/dev/null)
  if [ -n "$sboms" ]; then
    scan=$out/sbom-scan
    mkdir -p "$scan"
    # OSV-Scanner recognizes an SBOM by its file name (*.cdx.json).
    for sbom in $sboms; do cp "$sbom" "$scan/$(basename "$sbom" -cyclonedx.json).cdx.json"; done
    (cd "$scan" && osv-scanner scan source $(printf -- '-L %s ' *.cdx.json)) >"$out/osv-scanner.txt" 2>&1 \
      && result=PASS || result=FAIL
    scrub "$out/osv-scanner.txt" "$reports/osv-scanner.txt" || result=FAIL
    record "$result" sbom-scan "$(tail -1 "$reports/osv-scanner.txt"); validation/osv-scanner.txt"
  fi
else
  # Not a check without the scanner (SKIP is the API baseline's alone): release-check.txt says so.
  sbom_note="osv-scanner is not installed: the SBOM scan did not run (docs/releasing.md)"
fi

# The table of the checks so far, with the run's identity: validation/release-check.txt, which
# the binary ZIP carries and tools/publish-release.sh reads.
{
  echo "keytend-kmip release check, before packaging"
  echo "commit $commit"
  echo "arguments $args"
  for v in 17 21 25; do home=$(jdk_home "$v") && echo "jdk$v $("$home/bin/java" -version 2>&1 | head -1)"; done
  echo "finished $(date -u -Is)"
  [ -z "${sbom_note:-}" ] || echo "note $sbom_note"
  echo
  printf '%-4s  %-34s %s\n' RESULT CHECK DETAIL
  failed=0
  for i in "${!names[@]}"; do
    printf '%-4s  %-34s %s\n' "${results[$i]}" "${names[$i]}" "${notes[$i]}"
    [ "${results[$i]}" = PASS ] || [ "${results[$i]}" = SKIP ] || failed=$((failed + 1))
  done
  echo
  [ $failed -eq 0 ] && echo "PASSED BEFORE PACKAGING (${#names[@]} checks)" \
    || echo "FAILED BEFORE PACKAGING ($failed of ${#names[@]} checks)"
} >"$out/release-check.txt"
scrub "$out/release-check.txt" "$reports/release-check.txt"

# Package: both builds with the reports, then the checks of what was packaged.
if ! $skip_repro; then
  { $built_a && (umask 0022; package_distribution a); } && result=PASS || result=FAIL
  record "$result" distribution-a "$(wc -l <"$out/dist-a/sha256.txt") artifacts (umask 0022); logs/distribution-a.log, logs/package-a.log"
  { $built_b && (umask 0077; export TZ=Pacific/Chatham; package_distribution b); } && result=PASS || result=FAIL
  record "$result" distribution-b "$(wc -l <"$out/dist-b/sha256.txt") artifacts (TZ=Pacific/Chatham, umask 0077, Central dry run)"
  central_bundle "$out/tree-b"
  python3 -I - "$out/dist-a/sha256.txt" "$out/dist-b/sha256.txt" >"$out/repro-compare.txt" <<'PY'
import sys
a, b = ({line.split(None, 1)[1].strip(): line.split()[0] for line in open(p) if line.strip()} for p in sys.argv[1:])
for name in sorted(set(a) | set(b)):
    print(('same' if a.get(name) == b.get(name) else 'DIFFERENT'), a.get(name, '-'), b.get(name, '-'), name)
PY
  total=$(wc -l <"$out/repro-compare.txt")
  differing=$(grep -c '^DIFFERENT' "$out/repro-compare.txt")
  zip=$(grep -c '\.zip$' "$out/repro-compare.txt")
  [ "$differing" -eq 0 ] && [ "$total" -ge 10 ] && [ "$zip" -eq 2 ] && result=PASS || result=FAIL
  record "$result" reproducible "$((total - differing)) of $total identical (JARs, SBOMs, binary and source ZIPs, SHA256SUMS); repro-compare.txt"
  # One Javadoc JAR per module (SDK, testing, Micrometer, OpenTelemetry, CLI, integration
  # application), every one identical.
  javadocs=$(grep -c -- '-javadoc\.jar$' "$out/repro-compare.txt")
  javadoc=$(grep -- '-javadoc\.jar$' "$out/repro-compare.txt" | grep -c '^same')
  [ "$javadoc" -eq "$javadocs" ] && [ "$javadocs" -ge 6 ] && result=PASS || result=FAIL
  record "$result" reproducible-javadoc "$javadoc of $javadocs Javadoc JARs identical"
  user_commands "$out/tree-a"
fi

{
  printf '%-4s  %-34s %s\n' RESULT CHECK DETAIL
  failed=0
  for i in "${!names[@]}"; do
    printf '%-4s  %-34s %s\n' "${results[$i]}" "${names[$i]}" "${notes[$i]}"
    # SKIP: a check with nothing to check (the API report before the first release).
    [ "${results[$i]}" = PASS ] || [ "${results[$i]}" = SKIP ] || failed=$((failed + 1))
  done
  echo
  echo "commit $commit; run directory $out; finished $(date -Is)"
  [ $failed -eq 0 ] && echo "RELEASE CHECK PASSED (${#names[@]} checks)" || echo "RELEASE CHECK FAILED ($failed of ${#names[@]} checks)"
} | tee "$out/summary.txt"
grep -q '^RELEASE CHECK PASSED' "$out/summary.txt"
