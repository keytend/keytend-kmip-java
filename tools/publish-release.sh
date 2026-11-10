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

# Checks a packaged release (docs/releasing.md, step 2) and prints the exact command that creates
# its GitHub release with every asset; with --publish it runs that command. Nothing is published
# without --publish.
#
#   tools/publish-release.sh VERSION [--dir target/releases] [--notes FILE | --release-md FILE]
#       [--fingerprint FPR | --unsigned] [--publish [--draft]]
#
# VERSION is the POMs' version: X.Y.Z, or a pre-release X.Y.Z-rc.N of the release X.Y.Z.
# It refuses (exit 1) unless the directory holds every asset tools/package-release.py writes. The
# published files are the binary ZIP keytend-kmip-VERSION.zip, the source ZIP
# keytend-kmip-VERSION-src.zip and, beside them (not in them), the in-memory test server's
# keytend-kmip-testing-VERSION.jar, -sources.jar and -cyclonedx.json. Each has a .sha256 (one line,
# naming that file with its SHA-256). SHA256SUMS must be the binary ZIP's own SHA256SUMS with each
# path under keytend-kmip-VERSION/, then that file's SHA-256, then each published file's. The
# binary ZIP holds no source tree, and its release.json names VERSION, its commit and whether it is
# a pre-release. Its validation/release-check.txt must be of that commit and say the release checks
# before packaging passed, with every row a release needs passing and no argument that leaves out a
# check, with --integration (tools/release_reports.py, release_check_problems). Its
# validation/live-server.json must hold the run's own passing result of every live check the
# release check runs, at every KMIP version it runs it (run_problems), so a run without --server is
# refused; and passing live results of the pinned keytend-kmip-server build only
# (tools/kmip-server/pinned-image.properties), each recorded one of a check the release check
# cannot run, or it is refused with the command that runs the check again. It must hold the
# workflow suite's and the catalog's reports, on each JDK (integration_problems). Its other reports
# must hold no test output and no local path (report_problems).
#
# The ZIP cannot show that the checks of what was packaged passed (the run's summary.txt is not in
# it): a release signature stands for that, since tools/package-release.py signs only a full run
# that passed. So --publish refuses --unsigned, and a signed release is refused unless its
# release.json says "packaged": "release" (the release check's own packaging, unsigned, says "in
# release check"). --unsigned without --publish checks the assets without signatures, as the
# release check does with its own packaging, and publishes nothing.
# Every entry of the source ZIP is under keytend-kmip-VERSION-src/, and it holds
# pom.xml. Unless --unsigned, each published file and SHA256SUMS has a detached signature (.asc), a
# good one (gpg --verify) by the release key, made by its primary or one of its valid signing
# subkeys: the primary key fingerprint SECURITY.md publishes under "Release key fingerprint", or
# --fingerprint FPR. The release notes are the "# keytend-kmip X.Y.Z" section of RELEASE.md (or of
# --release-md FILE), without development blocks, followed by a list of the assets, written to the
# directory, or --notes FILE; a section still marked "(unreleased)" is refused. The notes of a
# pre-release X.Y.Z-rc.N are its release's section, after a line that names it. Their relative
# links are made links to the repo's files at the tag vVERSION, since a release page cannot
# resolve them. The release is made in keytend/keytend-kmip-java whatever the clone's remotes
# are. With --publish, the tag vVERSION must have been pushed there and name release.json's
# commit (gh api), and so must a local tag vVERSION of this clone, if it has one; gh's
# --verify-tag checks the tag again. An -rc.N version is marked a pre-release (--prerelease); a
# release X.Y.Z is not, whatever its major version. --draft makes the release a draft, which only
# the repository's maintainers see until one of them publishes it (the release workflow,
# .github/workflows/release.yml).
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
version=
dir=$root/target/releases
notes=
release_md=$root/RELEASE.md
fingerprint=
signed=true
publish=false
draft=false
while [ $# -gt 0 ]; do
  case $1 in
    --dir) dir=$2; shift 2 ;;
    --notes) notes=$2; shift 2 ;;
    --release-md) release_md=$2; shift 2 ;;
    --fingerprint) fingerprint=$2; shift 2 ;;
    --unsigned) signed=false; shift ;;
    --publish) publish=true; shift ;;
    --draft) draft=true; shift ;;
    -h|--help) sed -n '/^# Checks a packaged/,/^# version\.$/s/^# \{0,1\}//p' "$0"; exit 0 ;;
    -*) echo "unknown argument $1" >&2; exit 2 ;;
    *) [ -z "$version" ] || { echo "one version only" >&2; exit 2; }; version=$1; shift ;;
  esac
done
if $publish && ! $signed; then
  echo "REFUSED: --publish with --unsigned: a release is signed, and its signature stands for a full release check that passed (tools/package-release.py --sign --reports)" >&2
  exit 1
fi
if $draft && ! $publish; then echo "--draft needs --publish" >&2; exit 2; fi
[ -n "$version" ] || { echo "usage: $0 VERSION [--dir DIR] [--notes FILE | --release-md FILE] [--fingerprint FPR | --unsigned] [--publish [--draft]]" >&2; exit 2; }
# X.Y.Z, or a pre-release X.Y.Z-rc.N; release is X.Y.Z, whose RELEASE.md section is the notes.
[[ $version =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-rc\.[1-9][0-9]*)?$ ]] \
  || { echo "not a release version (X.Y.Z or X.Y.Z-rc.N): $version" >&2; exit 2; }
release=${version%%-*}
candidate=${version#"$release"}
candidate=${candidate#-rc.}
[ -d "$dir" ] || { echo "no directory $dir: run tools/package-release.py first" >&2; exit 1; }
dir=$(cd "$dir" && pwd)

zip=keytend-kmip-$version.zip
src=keytend-kmip-$version-src.zip
testing=keytend-kmip-testing-$version
# The files a user downloads: the binary and source ZIPs, and the test-only module's JAR, sources
# and SBOM beside them.
published=("$zip" "$src" "$testing.jar" "$testing-sources.jar" "$testing-cyclonedx.json")
assets=()
for f in "${published[@]}"; do assets+=("$f" "$f.sha256"); done
assets+=(SHA256SUMS)
if $signed; then for f in "${published[@]}" SHA256SUMS; do assets+=("$f.asc"); done; fi
missing=()
for a in "${assets[@]}"; do [ -s "$dir/$a" ] || missing+=("$a"); done
if [ ${#missing[@]} -gt 0 ]; then
  echo "REFUSED: $dir lacks ${missing[*]}" >&2
  $signed && echo "(a release is signed: tools/package-release.py --sign; --unsigned only checks, and publishes nothing)" >&2
  exit 1
fi
# Each .sha256 a user checks with sha256sum -c: one line, this file's name, this file's hash.
for f in "${published[@]}"; do
  actual=$(sha256sum "$dir/$f" | cut -d' ' -f1)
  if [ "$(wc -l < "$dir/$f.sha256")" != 1 ] || ! read -r listed name < "$dir/$f.sha256" \
      || [ "${name#\*}" != "$f" ] || [ "$listed" != "$actual" ]; then
    echo "REFUSED: $f.sha256 is not one line \"$actual  $f\"" >&2
    exit 1
  fi
done
# SHA256SUMS: the ZIP's own, each path under keytend-kmip-VERSION/ (where the ZIP unpacks), that
# file's SHA-256, then each published file's, so that sha256sum -c SHA256SUMS beside the
# unpacked ZIP checks every one.
# The checks print the commit release.json names, kept for the tag check.
commit_file=$(mktemp)
trap 'rm -f "$commit_file"' EXIT
python3 -I - "$root" "$dir" "$version" "$signed" "${published[@]}" >"$commit_file" <<'PY' || exit 1
import hashlib, json, os, re, sys, zipfile
root, directory, version, signed, published = (sys.argv[1], sys.argv[2], sys.argv[3],
                                               sys.argv[4] == 'true', sys.argv[5:])
sys.path.insert(0, os.path.join(root, 'tools'))
import release_reports
top = 'keytend-kmip-%s/' % version
def refuse(why):
    sys.exit('REFUSED: ' + why)
try:
    with zipfile.ZipFile(os.path.join(directory, published[0])) as z:
        inner = z.read(top + 'SHA256SUMS')
except (OSError, KeyError, zipfile.BadZipFile) as e:
    refuse('no %sSHA256SUMS in %s (%s)' % (top, published[0], e))
outer = open(os.path.join(directory, 'SHA256SUMS'), 'rb').read().decode('utf-8', 'replace').splitlines()
lines = inner.decode('utf-8', 'replace').splitlines()
if not lines or not all(re.fullmatch(r'[0-9a-f]{64}  \S.*', line) for line in lines):
    refuse('the SHA256SUMS in %s is not in the form sha256sum -c reads' % published[0])
expected = [line[:66] + top + line[66:] for line in lines]
expected.append(hashlib.sha256(inner).hexdigest() + '  ' + top + 'SHA256SUMS')
if outer[:len(expected)] != expected:
    refuse('SHA256SUMS differs from the one in %s (each path under %s, then its own SHA-256)'
           % (published[0], top))
assets = [hashlib.sha256(open(os.path.join(directory, f), 'rb').read()).hexdigest() + '  ' + f for f in published]
if outer[len(expected):] != assets:
    refuse('SHA256SUMS does not end with exactly these lines:\n' + '\n'.join(assets))
# The binary ZIP: no source tree, and the reports of release checks that passed before packaging.
top_level = {'README.md', 'LICENSE', 'NOTICE', 'release.json', 'SHA256SUMS', 'bin', 'lib', 'validation'}
with zipfile.ZipFile(os.path.join(directory, published[0])) as z:
    names = z.namelist()
    other = [n for n in names if not n.startswith(top) or n[len(top):].split('/', 1)[0] not in top_level]
    if other:
        refuse('%s holds %s: a binary ZIP holds only bin/, lib/, validation/ and its top-level '
               'files, no source tree' % (published[0], other[0]))
    try:
        metadata = json.loads(z.read(top + 'release.json'))
    except (KeyError, ValueError) as e:
        refuse('%s has no release.json (%s)' % (published[0], e))
    commit = metadata.get('commit') if isinstance(metadata, dict) else None
    if metadata.get('version') != version or not re.fullmatch(r'[0-9a-f]{40}', commit or ''):
        refuse('%s: release.json names version %s and commit %s, not %s and a commit'
               % (published[0], metadata.get('version'), commit, version))
    if metadata.get('prerelease') is not ('-rc.' in version):
        refuse('%s: release.json says prerelease %s, but only an X.Y.Z-rc.N is a pre-release'
               % (published[0], metadata.get('prerelease')))
    # A release is packaged from a full run that passed (package-release.py --reports, without
    # --in-release-check); the release check's own packaging is checked unsigned only.
    packaged = metadata.get('packaged')
    if packaged != 'release':
        if signed:
            refuse('%s: release.json says packaged %s, not release: a release is packaged with the '
                   'reports of a full release check that passed (tools/package-release.py --sign '
                   '--reports)' % (published[0], json.dumps(packaged)))
        print('NOTE: release.json says packaged %s: checked as the release check checks its own '
              'packaging, which cannot be published' % json.dumps(packaged), file=sys.stderr)
    try:
        check = z.read(top + 'validation/release-check.txt').decode('utf-8', 'replace')
    except KeyError:
        refuse('%s has no validation/release-check.txt: package it with the release check\'s '
               'reports (tools/package-release.py --reports)' % published[0])
    problems = release_reports.release_check_problems(
        check, commit, version, '%s: validation/release-check.txt' % published[0])
    if problems:
        refuse('a release is made from a full release check run that passed:\n'
               + '\n'.join(problems))
    # The reports: no test output, no local path (recorded/ is the commit's evidence).
    reports = {n[len(top + 'validation/'):]: z.read(n) for n in names
               if n.startswith(top + 'validation/') and not n.endswith('/')
               and not n.startswith(top + 'validation/recorded/')}
    problems = release_reports.report_problems(reports)
    if problems:
        refuse('%s: validation/ holds what a release does not ship (test output or a local '
               'path):\n' % published[0] + '\n'.join(problems))
    # The workflow suite's and the catalog's reports (--integration), on each JDK.
    problems = release_reports.integration_problems(reports, '%s: validation/' % published[0])
    if problems:
        refuse('a release ships the workflow suite\'s and the catalog\'s reports '
               '(tools/release-check.sh --integration):\n' + '\n'.join(problems))
    # The live results: every one of the pinned keytend-kmip-server build, none recorded that the
    # release check runs (tools/release_reports.py, pin_problems).
    try:
        live = z.read(top + 'validation/' + release_reports.LIVE).decode('utf-8', 'replace')
    except KeyError:
        refuse('%s has no validation/%s: package it with tools/package-release.py'
               % (published[0], release_reports.LIVE))
    where = '%s: validation/%s' % (published[0], release_reports.LIVE)
    problems = release_reports.pin_problems(release_reports.parse(live, where),
                                            release_reports.read_pin(), where)
    if problems:
        refuse('a release ships live results of the pinned server build only '
               '(tools/kmip-server/pinned-image.properties):\n' + '\n'.join(problems))
    # The run's own live results: every live check the release check runs, at every KMIP
    # version, passed in this run on the pinned image. A run without --server has none.
    problems = release_reports.run_problems(release_reports.parse(live, where),
                                            release_reports.read_pin(), where)
    if problems:
        refuse('a release ships the live results of its own release check run '
               '(tools/release-check.sh --server):\n' + '\n'.join(problems))
# The source ZIP: the source tree under keytend-kmip-VERSION-src/.
src_top = 'keytend-kmip-%s-src/' % version
try:
    with zipfile.ZipFile(os.path.join(directory, published[1])) as z:
        names = z.namelist()
except (OSError, zipfile.BadZipFile) as e:
    refuse('%s is not a ZIP (%s)' % (published[1], e))
if not names or any(not n.startswith(src_top) for n in names) or src_top + 'pom.xml' not in names:
    refuse('%s is not the source tree under %s with its pom.xml' % (published[1], src_top))
print(commit)
PY
commit=$(cat "$commit_file")

if $signed; then
  if [ -z "$fingerprint" ]; then
    # The line "**Release key fingerprint:** ...": 40 hex digits, plain or in groups of four, maybe in backticks.
    fingerprint=$(grep -m1 '^\*\*Release key fingerprint:\*\*' "$root/SECURITY.md" \
      | grep -oE '([0-9A-Fa-f]{4} ?){9}[0-9A-Fa-f]{4}' | head -1 || true)
  fi
  fingerprint=$(printf '%s' "$fingerprint" | tr -d ' ' | tr 'a-f' 'A-F')
  [[ $fingerprint =~ ^[0-9A-F]{40}$ ]] || {
    echo "REFUSED: no release key fingerprint (SECURITY.md \"Release key fingerprint\", or --fingerprint FPR)" >&2; exit 1; }
  command -v gpg >/dev/null || { echo "REFUSED: gpg is needed to verify the signatures" >&2; exit 1; }
  for signed_file in "${published[@]}" SHA256SUMS; do
    status=$(gpg --batch --status-fd 1 --verify "$dir/$signed_file.asc" "$dir/$signed_file" 2>/dev/null || true)
    # Accepted only with GOODSIG and VALIDSIG, VALIDSIG's last field the primary fingerprint
    # (whichever of its keys signed: the release key's CI signing subkey, or the primary), and none
    # of the signature-level failures. KEYEXPIRED and KEYREVOKED are NOT refusals: gpg prints them
    # for any expired or revoked subkey of the key, also when another, valid subkey signed. An
    # expired or revoked signing subkey is refused through EXPKEYSIG or REVKEYSIG.
    if ! grep -q '^\[GNUPG:\] GOODSIG ' <<<"$status" \
        || ! grep -qE "^\[GNUPG:\] VALIDSIG ([^ ]+ )+$fingerprint\$" <<<"$status" \
        || grep -qE '^\[GNUPG:\] (EXPKEYSIG|REVKEYSIG|BADSIG|ERRSIG|NO_PUBKEY|EXPSIG)( |$)' <<<"$status"; then
      echo "REFUSED: $signed_file.asc is not a good signature of $signed_file by the release key $fingerprint" >&2
      exit 1
    fi
  done
fi

if [ -z "$notes" ]; then
  notes=$dir/release-notes-$version.md
  python3 -I - "$release_md" "$release" "$notes" "$candidate" "$version" <<'PY' || exit 1
import re, sys
text = open(sys.argv[1], encoding='utf-8').read()
heading = re.compile(r'^# keytend-kmip (\S+)(.*)$', re.M)
found = [m for m in heading.finditer(text) if m.group(1) == sys.argv[2]]
if not found:
    sys.exit('REFUSED: RELEASE.md has no "# keytend-kmip %s" section' % sys.argv[2])
m = found[0]
if 'unreleased' in m.group(2):
    sys.exit('REFUSED: RELEASE.md still marks %s "(unreleased)" (step 1)' % sys.argv[2])
# The section ends at the next top-level heading of any name (the sections before the rename keep
# the former one).
after = re.compile(r'^# ', re.M).search(text, m.end())
section = text[m.end():after.start() if after else len(text)]
# Development notes in a shared RELEASE.md are not release notes: drop any block between the
# marker lines (named in two parts here, so that this script is not itself cut).
start, end = 'dev-only' + ':start', 'dev-only' + ':end'
kept, inside = [], False
for line in section.split('\n'):
    if start in line: inside = True
    elif end in line: inside = False
    elif not inside: kept.append(line)
section = '\n'.join(kept).strip() + '\n'
# A release page resolves a relative link under /releases/tag/, where it is not found: point each
# link to a file of the repo at the release's tag instead. Code is left as it is.
blob = 'https://github.com/keytend/keytend-kmip-java/blob/v%s/' % sys.argv[5]
def absolute(target):
    if re.match(r'(?i)([a-z][a-z0-9+.-]*:|#|/)', target):
        return target
    return blob + (target[2:] if target.startswith('./') else target)
inline = re.compile(r'(\]\()([^)\s]+)')
reference = re.compile(r'^(\s{0,3}\[[^\]]+\]:\s*)(\S+)')
lines, fenced = [], False
for line in section.split('\n'):
    if line.lstrip().startswith('```'):
        fenced = not fenced
    elif not fenced:
        parts = re.split(r'(`[^`]*`)', line)
        parts = [p if p.startswith('`') else inline.sub(lambda m: m.group(1) + absolute(m.group(2)), p)
                 for p in parts]
        line = reference.sub(lambda m: m.group(1) + absolute(m.group(2)), ''.join(parts))
    lines.append(line)
section = '\n'.join(lines)
if sys.argv[4]:
    section = ('This is keytend-kmip %s-rc.%s, a pre-release of %s.\n\n'
               % (sys.argv[2], sys.argv[4], sys.argv[2])) + section
open(sys.argv[3], 'w', encoding='utf-8').write(section)
PY
  # What each asset is, after the notes.
  {
    echo
    echo "## Assets"
    echo
    echo "- \`$zip\`: the binary distribution: in \`lib/\` each module's JAR, \`-sources\` and \`-javadoc\` JARs and SBOM, and the libraries the command-line tool and the lab run with; the tool's launcher in \`bin/\`; and the release's test reports in \`validation/\`."
    echo "- \`$src\`: the source tree that builds the release."
    echo "- \`$testing.jar\`: the in-memory KMIP server (\`dev.keytend.kmip.testing\`), for tests only: add it in test scope. It is not in the ZIPs."
    echo "- \`$testing-sources.jar\` and \`$testing-cyclonedx.json\`: its sources and its CycloneDX SBOM."
    echo "- \`.sha256\`: each of those files' SHA-256, for \`sha256sum -c\`."
    echo "- \`SHA256SUMS\`: the SHA-256 of each file the binary ZIP's own \`SHA256SUMS\` lists (under \`keytend-kmip-$version/\`), of that file, and of each file above. Run \`sha256sum -c --ignore-missing SHA256SUMS\` where the ZIP is unpacked: it skips the files you did not download."
    if $signed; then
      echo "- \`.asc\`: the detached OpenPGP signature of each file above and of \`SHA256SUMS\`, by the release key ([verifying release artifacts](https://github.com/keytend/keytend-kmip-java/blob/v$version/SECURITY.md#verifying-release-artifacts))."
    else
      echo "- No \`.asc\` files: this release is unsigned."
    fi
  } >>"$notes"
fi
[ -s "$notes" ] || { echo "REFUSED: no release notes in $notes" >&2; exit 1; }

command=(gh release create "v$version" -R keytend/keytend-kmip-java --verify-tag --title "keytend-kmip $version" --notes-file "$notes")
# An -rc.N version is a pre-release; a release X.Y.Z is not, whatever its major version.
if [ -n "$candidate" ]; then command+=(--prerelease); fi
if $draft; then command+=(--draft); fi
for a in "${assets[@]}"; do command+=("$dir/$a"); done
echo "Every asset is present and consistent ($($signed && echo "signed by $fingerprint" || echo UNSIGNED)). The release command:"
printf '%q ' "${command[@]}"; echo
if $publish; then
  # The tag must name the commit the release was packaged from (release.json), on GitHub and in
  # this clone if it has the tag.
  tagged=$(gh api "repos/keytend/keytend-kmip-java/commits/v$version" --jq .sha 2>/dev/null || true)
  if [ "$tagged" != "$commit" ]; then
    echo "REFUSED: the tag v$version of keytend/keytend-kmip-java names ${tagged:-nothing}," \
      "not the release's commit $commit (release.json); push the tag of that commit" >&2
    exit 1
  fi
  local_tag=$(git -C "$root" rev-parse -q --verify "refs/tags/v$version^{commit}" 2>/dev/null \
    || true)
  if [ -n "$local_tag" ] && [ "$local_tag" != "$commit" ]; then
    echo "REFUSED: this clone's tag v$version names $local_tag, not the release's commit" \
      "$commit (release.json)" >&2
    exit 1
  fi
  "${command[@]}"
else
  echo "Not published: run it, or this script with --publish."
fi
