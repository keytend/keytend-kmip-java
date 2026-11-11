#!/usr/bin/env python3
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

"""Package a release as two deterministic ZIPs: the binary distribution and the source.

The version is the POMs': X.Y.Z, or a pre-release X.Y.Z-rc.N of X.Y.Z (VERSION_PATTERN).

The binary ZIP, keytend-kmip-VERSION.zip (top directory keytend-kmip-VERSION/), holds no source tree:
lib/, the CLI's launcher (bin/keytend-kmip-cli), the release's reports (validation/),
release.json, SHA256SUMS, LICENSE, NOTICE and a short README.md. The source ZIP,
keytend-kmip-VERSION-src.zip (top directory keytend-kmip-VERSION-src/), holds the committed source tree,
as git archive gives it, which builds the release (./mvnw).

validation/ holds the release check's reports of this commit (--reports DIRECTORY: the run's
validation/ directory, whose release-check.txt names this commit), the evidence the release check
cannot produce (the source tree's validation/recorded/, checked by release_reports.py check), and
live-server.json: the recorded live results with this run's over them, one per scope and KMIP
version (release_reports.merge). With --reports, every one of them must be PASS and of the pinned
keytend-kmip-server build (tools/kmip-server/pinned-image.properties), and a recorded one of a
check the release check runs is refused (release_reports.check_pinned). The reports must hold no
test output (TEST-*.xml, Surefire or Failsafe reports) and no local path
(release_reports.report_problems). Without --reports the ZIP holds the recorded evidence alone,
and tools/publish-release.sh refuses it.

Before it writes or signs anything, --reports DIRECTORY must be of a full release check run that
passed (release_reports.check_run): its release-check.txt of this commit, PASSED BEFORE PACKAGING,
with every required row passing and no argument that leaves out a check (--skip-verify,
--skip-api, --skip-repro, --allow-dirty, --no-api-fail, --server-unpinned); its live-server.json
with this run's passing result of every live check the release check runs, on the pinned image;
and the run's summary.txt, beside DIRECTORY, of this commit, ending RELEASE CHECK PASSED, with
the checks of what was packaged (distribution-a and -b, central-bundle, reproducible,
reproducible-javadoc, user-commands) passing; and its workflow and catalog reports, which the
release check writes with --integration (release_reports.integration_problems). --in-release-check
is the release check's own packaging, before it has run those checks: the run's results are not
required, nothing is signed (a key refuses it), it is refused once the run's summary.txt exists,
and its release.json says "packaged": "in release check" (otherwise "release" with --reports,
"without reports" without).

tools/publish-release.sh checks what it can of the ZIP: its validation/release-check.txt, live
results, workflow and catalog reports and the absence of local paths. It cannot see summary.txt,
which is not in the ZIP. That the whole run passed, the checks of what was packaged included, is
what a release signature stands for: this script signs only after check_run accepted the full
run. So publish-release.sh --publish refuses an unsigned release (--unsigned) and a ZIP whose
release.json does not say "packaged": "release".

The binary ZIP's lib/ holds each module's JAR with its -sources and -javadoc JARs (MODULES) and its
CycloneDX SBOM, and the third-party JARs the applications run with (APPLICATIONS: what each copies
to its target/lib/), flat, under their Maven file names. Each application JAR's manifest Class-Path names
its runtime JARs; every one, by file name, must be in lib/.

The in-memory test server (keytend-kmip-testing, TEST_ONLY) is not in lib/: it is a test dependency,
published on its own, and its source is in the source ZIP. No JAR in lib/ may hold a class
of its package (TEST_ONLY_PACKAGE), and no SBOM may list it. Its JAR, -sources JAR and SBOM are
assets of the release beside the ZIPs (write_beside), checked as the modules' are; its JAR holds
its own package alone.
The SDK JAR bundles Caffeine, relocated (sdk/pom.xml, "The bundled Caffeine"): the checks tell
its classes, sources and license from the project's own (BUNDLED).

With --central-bundle FILE (signed releases only), the unsigned Central bundle of the same build
(./mvnw -Pdistribution,central deploy -DskipUpload=true) gets a detached signature of each of its
files but the checksums, and is published as keytend-kmip-VERSION-central-bundle.zip:
.github/workflows/publish-central.yml uploads it to Maven Central as it is.

Beside the ZIPs: each published file (the two ZIPs, those assets and the Central bundle) with its
.sha256, and SHA256SUMS. The binary ZIP holds its own SHA256SUMS (every other file in it), unchanged; the one
beside it lists those same files under the binary ZIP's top directory, keytend-kmip-VERSION/, then that
SHA256SUMS itself, then each published file. So `sha256sum -c SHA256SUMS`, where the ZIP is
downloaded and unpacked, checks all of them.

Every JAR it packages must already have the entry modes 0644 and 0755 (canonical_modes), which the
distribution profile gives them before Maven signs or deploys any (--canonical-modes DIRECTORY):
it refuses one without them, so the release's JARs are the ones on Maven Central.

Signing (--sign, or --sign-key KEY / KEYTEND_GPG_KEY for another key) gives each published file
and the SHA256SUMS beside them detached ASCII-armored signatures (.asc), verified after signing;
without it the artifacts are UNSIGNED. The signatures stay outside the ZIPs, so the ZIPs stay
reproducible.
Releases are signed by the release key's dedicated signing subkey (SIGNING_SUBKEY, exactly that
subkey: KEY!), from its own GnuPG home, unattended:

    KEYTEND_SIGNING_HOME             the GnuPG home holding the subkey's secret
                                     (default ~/.config/keytend-kmip-java/signing/gnupg)
    KEYTEND_SIGNING_PASSPHRASE_FILE  the file holding its passphrase, mode 0600 or stricter
                                     (default ~/.config/keytend-kmip-java/signing/passphrase)

gpg reads the passphrase from the file itself (--passphrase-file, loopback pinentry): it is never
read into this process or put in an argument. A missing home or file, or a file others can read,
refuses before anything is packaged. --check-signing checks the setup by signing and verifying a
scratch file, and packages nothing.
"""
import argparse
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile

# release_reports.py beside this script, also when it is loaded by path (python3 -I, the tests).
sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_reports  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
# The release key's signing subkey (SECURITY.md, "Release key fingerprint", is its primary's).
SIGNING_SUBKEY = 'AAE2AF4DD7F2427F52B800D494E026FE1BF6C09E'
# gpg's signature-level failure statuses (KEYEXPIRED and KEYREVOKED are about other subkeys).
FAILURES = {'EXPKEYSIG', 'REVKEYSIG', 'BADSIG', 'ERRSIG', 'NO_PUBKEY', 'EXPSIG'}
SIGNING_DIR = Path.home() / '.config' / 'keytend-kmip-java' / 'signing'
# The modules whose JARs (main, -sources and -javadoc) the release ships: (directory, artifactId).
MODULES = [
    ('sdk', 'keytend-kmip'),
    ('micrometer', 'keytend-kmip-micrometer'),
    ('opentelemetry', 'keytend-kmip-opentelemetry'),
    ('cli', 'keytend-kmip-cli'),
    ('integration-tests', 'keytend-kmip-integration'),
]
# The applications among them, whose runtime JARs (target/lib/) the ZIP's lib/ also carries.
APPLICATIONS = ['cli', 'integration-tests']
# Third-party code bundled in a module's JAR (sdk/pom.xml's shade execution), by artifactId: the
# Maven coordinates, the package it is relocated from and to, its license file in the JAR (and in
# the -sources JAR), and a line of the license header every one of its sources keeps from upstream.
BUNDLED = {
    'keytend-kmip': [dict(group='com.github.ben-manes.caffeine', artifact='caffeine',
                          version_property='caffeine.version',
                          original='com.github.benmanes.caffeine',
                          relocated='dev.keytend.kmip.internal.shaded.caffeine',
                          license='META-INF/licenses/caffeine/LICENSE',
                          upstream_header=b'Licensed under the Apache License, Version 2.0 (the "License")')],
}
PROJECT_HEADER = (b'Copyright 2026 Jeremiah Jordan', b'Licensed under the Apache License, Version 2.0')
# CycloneDX property that marks a component the SDK JAR bundles; its value is the package.
SHADED_PROPERTY = 'keytend:shaded'
JAVA_17 = 61

# Published for applications' tests, never shipped in lib/: (directory, artifactId), and its package.
TEST_ONLY = ('testing', 'keytend-kmip-testing')
TEST_ONLY_PACKAGE = 'dev/keytend/kmip/testing/'
# The CLI's launcher, from the source tree, at bin/ of the binary ZIP (lib/ beside it).
LAUNCHER = ('cli/bin/keytend-kmip-cli', 'bin/keytend-kmip-cli')
# The top-level entries of the binary ZIP: anything else would be source.
BINARY_TOP = {'README.md', 'LICENSE', 'NOTICE', 'release.json', 'SHA256SUMS', 'bin', 'lib',
              'validation'}
# The report of the checks the release check ran before packaging (tools/release-check.sh).
RELEASE_CHECK = 'release-check.txt'
# A release version: X.Y.Z, or a pre-release X.Y.Z-rc.N of the release X.Y.Z.
VERSION_PATTERN = r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-rc\.[1-9]\d*)?'
BINARY_README = """# keytend-kmip VERSION

The binary distribution of keytend-kmip VERSION, a Java KMIP client for JDK 17 and later. The
source tree that builds it is the release's `keytend-kmip-VERSION-src.zip`.

- `lib/`: each module's JAR with its `-sources` and `-javadoc` JARs and its CycloneDX SBOM
  (`-cyclonedx.json`), and the libraries the command-line tool and the interop lab run with.
- `bin/keytend-kmip-cli`: the command-line tool's launcher.
- `validation/`: the release's test reports (below).
- `release.json`: the source commit, the build time and each artifact's SHA-256.
- `SHA256SUMS`: the SHA-256 of every other file here, for `sha256sum -c SHA256SUMS`.
- `LICENSE` and `NOTICE`.

The in-memory KMIP server for tests, `keytend-kmip-testing-VERSION.jar`, is a separate asset of the
release, not in this ZIP.

## validation/

- `release-check.txt`: the release checks that ran before packaging, with their results.
- `workflows/`: the workflow suite against each lab server, KMIP version and JDK: `summary.json`,
  `overview.html` and each run's report.
- `catalog/`: the interoperability catalog: `summary.json`, `cases.csv`, `overview.html`,
  `policy-coverage.html`, and each run's records in `results/`.
- `live-server.json`: the latest result of each check against keytend-kmip-server, one entry per
  check and KMIP version. Its `source` says whether this release's checks ran it or it was
  recorded earlier.
- `server-probe/` and `interop/`: the logs of this release's runs against keytend-kmip-server.
- `recorded/`: evidence the release checks cannot produce, such as the OASIS replay runs.
  `recorded/index.json` gives each file's date and server.

How to read them:
<https://github.com/keytend/keytend-kmip-java/blob/vVERSION/docs/validation.md#how-to-read-the-results>.
"""


def source_zip(version):
    """The source ZIP's file name."""
    return f'keytend-kmip-{version}-src.zip'


def central_bundle_name(version):
    """The signed Central bundle's file name, a published file of a signed release."""
    return f'keytend-kmip-{version}-central-bundle.zip'


# The checksum files Maven writes beside each file of a Central bundle; Central wants no signature of them.
CHECKSUMS = ('.md5', '.sha1', '.sha256', '.sha512')


def sign_central_bundle(source, destination, version, signer, zip_time):
    """--central-bundle: the unsigned bundle at source (./mvnw -Pdistribution,central deploy
    -DskipUpload=true, without a key name), with a detached signature (.asc) of every file but the
    checksums, as a deterministic ZIP at destination. Every file must be under
    dev/keytend/ARTIFACT/VERSION/, none may be a signature already, and every JAR must be the one in
    its module's target/, which the release packages."""
    with zipfile.ZipFile(source) as bundle:
        files = {n: bundle.read(n) for n in bundle.namelist() if not n.endswith('/')}
    wrong = sorted(n for n in files if not re.fullmatch(rf'dev/keytend/[a-z0-9-]+/{re.escape(version)}/[^/]+', n))
    if not files or wrong:
        raise SystemExit(f'REFUSED: {source} is not a Central bundle of {version}: {wrong[:5] or "empty"}')
    if any(n.endswith('.asc') for n in files):
        raise SystemExit(f'REFUSED: {source} is signed already; give the unsigned bundle')
    if not any(n.endswith('.pom') for n in files):
        raise SystemExit(f'REFUSED: {source} holds no POM')
    # Every JAR the bundle holds must be this build's own (*/target/), byte for byte.
    for name, content in sorted(files.items()):
        if name.endswith('.jar'):
            built = sorted(ROOT.glob(f'*/target/{Path(name).name}'))
            if len(built) != 1 or built[0].read_bytes() != content:
                raise SystemExit(f'REFUSED: {Path(name).name} in {source} is not the one in */target/')
    entries = {n: (content, 0o100644 << 16) for n, content in files.items()}
    with tempfile.TemporaryDirectory() as scratch:
        for name, content in files.items():
            if name.endswith(CHECKSUMS):
                continue
            path = Path(scratch) / name.replace('/', '_')
            path.write_bytes(content)
            signature, _ = signer.sign(path)
            entries[name + '.asc'] = (signature.read_bytes(), 0o100644 << 16)
    write_zip(destination, '', entries, zip_time)


def test_only_assets(version):
    """The test-only module's files the release publishes beside the ZIPs: JAR, -sources JAR and
    SBOM."""
    return [f'{TEST_ONLY[1]}-{version}{suffix}' for suffix in ('.jar', '-sources.jar', '-cyclonedx.json')]


def canonical_modes(path, write=True):
    """Gives each entry of the ZIP or JAR at path that records Unix permissions the canonical ones,
    0644 for a file and 0755 for a directory, in place: only the central directory's external
    attributes change, nothing is recompressed. The archivers copy each file's permissions from
    disk, so a restrictive umask (0077: 0600 and 0700) would otherwise change the release's bytes.
    Returns the number of entries changed; a second call changes none. With write false it only
    counts the entries it would change."""
    data = bytearray(path.read_bytes())
    end = data.rfind(b'PK\x05\x06', max(0, len(data) - 22 - 0xFFFF))
    if end < 0 or end + 22 > len(data):
        raise SystemExit(f'{path}: not a ZIP archive (no end of central directory)')
    count, size, offset = struct.unpack_from('<HII', data, end + 10)
    if count == 0xFFFF or size == 0xFFFFFFFF or offset == 0xFFFFFFFF:
        raise SystemExit(f'{path}: a ZIP64 archive, which this release never builds')
    changed = 0
    position = offset
    for _ in range(count):
        if data[position:position + 4] != b'PK\x01\x02':
            raise SystemExit(f'{path}: malformed central directory at {position}')
        made_by, = struct.unpack_from('<H', data, position + 4)
        names, extra, comment = struct.unpack_from('<HHH', data, position + 28)
        attributes, = struct.unpack_from('<I', data, position + 38)
        mode = attributes >> 16
        if made_by >> 8 == 3 and mode:  # Unix permissions recorded
            kind = stat.S_IFMT(mode)
            canonical = kind | (0o755 if kind == stat.S_IFDIR else 0o644)
            if canonical != mode:
                struct.pack_into('<I', data, position + 38, canonical << 16 | attributes & 0xFFFF)
                changed += 1
        position += 46 + names + extra + comment
    if position != offset + size:
        raise SystemExit(f'{path}: the central directory is not {size} bytes')
    if changed and write:
        path.write_bytes(bytes(data))
    return changed


def canonical_modes_of(directory):
    """--canonical-modes DIRECTORY: canonical_modes on every JAR directly in it, in place. The
    distribution profile (pom.xml) runs it on each module's target/ after the last JAR is written
    (pre-integration-test) and before anything signs, installs or deploys one (verify onwards), so
    every JAR Maven publishes, on Central or in the GitHub release, has these bytes whatever the
    umask. A directory that does not exist has none."""
    jars = sorted(directory.glob('*.jar')) if directory.is_dir() else []
    changed = sum(canonical_modes(jar) for jar in jars)
    print(f'canonical modes: {changed} entries changed in {len(jars)} JARs of {directory}')


def refuse_other_modes(jars):
    """Exits naming the first of jars with an entry canonical_modes would change: the release
    packages the JARs exactly as Maven made, signed and deployed them."""
    for jar in jars:
        if canonical_modes(jar, write=False):
            raise SystemExit(f'{jar}: entries without the modes 0644 and 0755; build with '
                             './mvnw -Pdistribution verify (or deploy), which gives them before signing')


def sha256_line(path):
    """The line `sha256sum` writes for a file in the current directory: its hash, two spaces, its name."""
    return hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + path.name + '\n'


def outer_sums(version, inner, published):
    """The SHA256SUMS beside the ZIPs: the binary ZIP's own (inner) with each path under its top
    directory, that file itself, then each published file (paths beside it)."""
    top = f'keytend-kmip-{version}/'
    lines = []
    for line in inner.decode('utf-8').splitlines():
        digest, sep, path = line.partition('  ')
        if not re.fullmatch(r'[0-9a-f]{64}', digest) or not sep or not path:
            raise SystemExit(f'the ZIP\'s SHA256SUMS has a line not in sha256sum\'s form: {line!r}')
        lines.append(f'{digest}  {top}{path}\n')
    lines.append(f'{hashlib.sha256(inner).hexdigest()}  {top}SHA256SUMS\n')
    lines += [sha256_line(path) for path in published]
    return ''.join(lines).encode('utf-8')


def write_beside(output, version, zip_path, inner, test_only, signer, central=False):
    """Writes the release's files beside its ZIPs in output: the test-only assets (test_only, name
    to content: exactly test_only_assets(version)), each published file's .sha256, SHA256SUMS
    (outer_sums) and, with a signer, the .asc of each of them. The published files are the binary
    ZIP (zip_path), the source ZIP beside it, the test-only assets and, with central, the signed
    Central bundle already in output (central_bundle_name). Stale .asc files are removed
    first, and every signature if one cannot be made. Returns the published files, the signatures
    and the key that signed (None, unsigned)."""
    expected = test_only_assets(version)
    if sorted(test_only) != sorted(expected):
        missing = sorted(set(expected) - set(test_only)) or sorted(set(test_only) - set(expected))
        raise SystemExit(f'REFUSED: the test-only assets are not {expected}: {missing}')
    if zip_path != output / f'keytend-kmip-{version}.zip' or not zip_path.is_file():
        raise SystemExit(f'REFUSED: no {zip_path.name} in {output}')
    if not (output / source_zip(version)).is_file():
        raise SystemExit(f'REFUSED: no {source_zip(version)} in {output}')
    published = [zip_path, output / source_zip(version)] + [output / name for name in expected]
    if central:
        if not (output / central_bundle_name(version)).is_file():
            raise SystemExit(f'REFUSED: no {central_bundle_name(version)} in {output}')
        published.append(output / central_bundle_name(version))
    signed = published + [output / 'SHA256SUMS']
    for path in signed:
        path.with_name(path.name + '.asc').unlink(missing_ok=True)
    for name in expected:
        (output / name).write_bytes(test_only[name])
    for path in published:
        path.with_name(path.name + '.sha256').write_text(sha256_line(path))
    (output / 'SHA256SUMS').write_bytes(outer_sums(version, inner, published))
    if not signer:
        return published, [], None
    made = []
    try:
        for path in signed:
            made.append(signer.sign(path))
    except SystemExit:
        for path in signed:
            path.with_name(path.name + '.asc').unlink(missing_ok=True)
        raise
    return published, [signature for signature, _ in made], made[0][1]


def sdk_runtime_allowlist():
    """The groupId:artifactId pairs the SDK's enforcer allowlist admits outside test scope."""
    ns = {'m': 'http://maven.apache.org/POM/4.0.0'}
    pom = ET.parse(ROOT / 'sdk' / 'pom.xml').getroot()
    for execution in pom.iterfind('.//m:plugin/m:executions/m:execution', ns):
        if execution.findtext('m:id', namespaces=ns) == 'runtime-dependency-allowlist':
            includes = execution.iterfind('.//m:bannedDependencies/m:includes/m:include', ns)
            return {tuple(include.text.split(':')[:2]) for include in includes}
    raise SystemExit('sdk/pom.xml: no runtime-dependency-allowlist execution')


def manifest_class_path(content):
    """The Class-Path entries of a JAR's manifest (continuation lines joined)."""
    with zipfile.ZipFile(io.BytesIO(content)) as jar:
        manifest = jar.read('META-INF/MANIFEST.MF').decode('utf-8')
    manifest = manifest.replace('\r\n ', '').replace('\n ', '')
    match = re.search(r'^Class-Path: (.*)$', manifest, re.MULTILINE)
    return match.group(1).split() if match else []


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT)


def relocate_source(code, original, relocated):
    """maven-shade-plugin 3.6.2's source relocation (SimpleRelocator.applyToSourceContent), which
    shadeSourcesContent applies to the -sources JAR: each occurrence of the package name, and of its
    path form, at word boundaries, is renamed, except after '.', '/' or a space that does not follow
    a Java keyword, '{@link', or one of {}(=;, or */ (where it is part of another name or of prose)."""
    keyword = re.compile(r'\b(import|package|public|protected|private|static|final|synchronized|abstract'
                         r'|volatile|extends|implements|throws) $|\{@link( \*)* $|([{}(=;,]|\*/) $')
    for old, new in ((original, relocated), (original.replace('.', '/'), relocated.replace('.', '/'))):
        snippets = re.split(r'\b' + old.replace('.', '[.]') + r'\b', code)
        while len(snippets) > 1 and snippets[-1] == '':  # Java's split drops trailing empty strings
            snippets.pop()
        out = [snippets[0]]
        for previous, snippet in zip(snippets, snippets[1:]):
            line = re.sub(r'\s+', ' ', previous)
            keep = re.search(r'[./ ]$', line) and not keyword.search(line)
            out.append((old if keep else new) + snippet)
        code = ''.join(out)
    return code


def pom_property(name):
    ns = {'m': 'http://maven.apache.org/POM/4.0.0'}
    value = ET.parse(ROOT / 'pom.xml').getroot().findtext(f'm:properties/m:{name}', namespaces=ns)
    if not value:
        raise SystemExit(f'pom.xml: no property {name}')
    return value


def class_major(content):
    return struct.unpack('>H', content[6:8])[0]


def validation_entries(source, reports, commit):
    """The binary ZIP's validation/ entries (path in the ZIP to content): the release check's
    reports of this commit (reports, a directory, or None), the recorded evidence of the committed
    tree (source: the source ZIP's entries, path to (content, mode)) and live-server.json, the
    recorded live results with the run's over them."""
    release_reports.check_recorded()
    recorded_dir = 'validation/recorded/'
    recorded = {path[len(recorded_dir):]: content for path, (content, _) in source.items()
                if path.startswith(recorded_dir)}
    on_disk = {p.relative_to(release_reports.RECORDED).as_posix()
               for p in release_reports.RECORDED.rglob('*')
               if p.is_file() and '__pycache__' not in p.parts}
    if set(recorded) != on_disk:
        raise SystemExit('validation/recorded/ differs from the commit: '
                         f'{sorted(set(recorded) ^ on_disk)}')
    out = {recorded_dir + name: content for name, content in recorded.items()}
    run_entries = []
    if reports is not None:
        reports = Path(reports)
        check = reports / RELEASE_CHECK
        if not check.is_file():
            raise SystemExit(f'REFUSED: {reports} has no {RELEASE_CHECK}: '
                             'not a release check\'s reports')
        named = re.findall(r'^commit ([0-9a-f]{40})$', check.read_text(encoding='utf-8'), re.M)
        if named != [commit]:
            raise SystemExit(f'REFUSED: {check} is of commit {named}, not of HEAD {commit}')
        for path in sorted(reports.rglob('*')):
            if not path.is_file():
                continue
            name = path.relative_to(reports).as_posix()
            if name.startswith('recorded/'):
                raise SystemExit(f'REFUSED: {path}: recorded evidence comes from the committed '
                                 'validation/recorded/, not from the reports')
            if name == release_reports.LIVE:
                run_entries = release_reports.load(path)
                if any(entry['source'] != 'release check' for entry in run_entries):
                    raise SystemExit(f'REFUSED: {path} holds entries the release check '
                                     'did not make')
                continue
            out['validation/' + name] = path.read_bytes()
        # No test output and no local path: the reports go to users as they are.
        release_reports.check_reports(release_reports.reports_of(reports), str(reports))
    with tempfile.TemporaryDirectory() as scratch:
        merged = Path(scratch) / release_reports.LIVE
        recorded_live = Path(scratch) / 'recorded.json'
        recorded_live.write_bytes(recorded.get(release_reports.LIVE, b'{"entries": []}\n'))
        live = release_reports.merge(release_reports.load(recorded_live), run_entries)
        if reports is not None:
            # A release ships live results of the pinned server build only: a recorded one of
            # another build is refused, with the command that records it again.
            release_reports.check_pinned(live, release_reports.read_pin(), release_reports.LIVE)
        release_reports.dump(merged, live)
        out['validation/' + release_reports.LIVE] = merged.read_bytes()
    return out


def write_zip(destination, prefix, entries, zip_time):
    """A deterministic ZIP of entries (path to (content, mode)) under prefix, in path order, every
    entry at zip_time; checked after it is written."""
    with zipfile.ZipFile(destination, 'w', compression=zipfile.ZIP_DEFLATED,
                         compresslevel=9) as bundle:
        for path, (content, mode) in sorted(entries.items()):
            info = zipfile.ZipInfo(prefix + path, zip_time)
            info.external_attr = mode
            info.compress_type = zipfile.ZIP_DEFLATED
            bundle.writestr(info, content, compresslevel=9)
    with zipfile.ZipFile(destination) as bundle:
        if bundle.testzip() is not None:
            raise SystemExit(f'{destination.name} failed integrity verification')


class Signer:
    """gpg in the signing home, with the passphrase file; the key exactly as named."""

    def __init__(self, key):
        self.key = key
        self.home = Path(os.environ.get('KEYTEND_SIGNING_HOME') or SIGNING_DIR / 'gnupg')
        self.passphrase = Path(os.environ.get('KEYTEND_SIGNING_PASSPHRASE_FILE') or SIGNING_DIR / 'passphrase')
        if not self.home.is_dir():
            raise SystemExit(f'REFUSED: no signing keyring at {self.home} (KEYTEND_SIGNING_HOME): cannot sign the release')
        if not self.passphrase.is_file():
            raise SystemExit(f'REFUSED: no passphrase file at {self.passphrase} (KEYTEND_SIGNING_PASSPHRASE_FILE): '
                             'cannot sign the release')
        mode = stat.S_IMODE(self.passphrase.stat().st_mode)
        if mode & 0o077:
            raise SystemExit(f'REFUSED: {self.passphrase} has mode {mode:04o}; it must be 0600 or stricter '
                             f'(chmod 600 {self.passphrase})')
        self.primary = self.fingerprints()[0]

    def gpg(self, *args):
        try:
            return subprocess.run(['gpg', '--batch', *args], capture_output=True, stdin=subprocess.DEVNULL,
                                  env=dict(os.environ, GNUPGHOME=str(self.home)))
        except FileNotFoundError:
            raise SystemExit('gpg is not installed: cannot sign the release')

    def fingerprints(self):
        """The primary key fingerprint of the secret key named, which must be unique, or exit."""
        listed = self.gpg('--with-colons', '--list-secret-keys', '--', self.key.rstrip('!'))
        lines = listed.stdout.decode().splitlines()
        primaries = [line for line in lines if line.startswith('sec:')]
        fingerprints = [line.split(':')[9] for line in lines if line.startswith('fpr:')]
        if listed.returncode != 0 or len(primaries) != 1 or not fingerprints:
            raise SystemExit(f'REFUSED: {self.home} has no unique secret key for {self.key!r}: cannot sign the release\n'
                             + listed.stderr.decode())
        return fingerprints

    def sign(self, path):
        signature = path.with_name(path.name + '.asc')
        signature.unlink(missing_ok=True)
        signed = self.gpg('--pinentry-mode', 'loopback', '--passphrase-file', str(self.passphrase),
                          '--armor', '--detach-sign', '--local-user', self.key, '--output', str(signature), str(path))
        if signed.returncode != 0:
            signature.unlink(missing_ok=True)
            raise SystemExit(f'gpg could not sign {path.name} with {self.key!r}:\n' + signed.stderr.decode())
        verified = self.gpg('--status-fd', '1', '--verify', str(signature), str(path))
        status = verified.stdout.decode().splitlines()
        valid = [line.split() for line in status if line.startswith('[GNUPG:] VALIDSIG ')]
        good = any(line.startswith('[GNUPG:] GOODSIG ') for line in status)
        # The rule tools/publish-release.sh applies: GOODSIG and VALIDSIG, VALIDSIG's last field the
        # primary, and no signature-level failure. KEYEXPIRED and KEYREVOKED are not failures: gpg
        # prints them for any expired or revoked subkey of the key, also when another one signed.
        failed = [line.split()[1] for line in status if len(line.split()) > 1 and line.split()[1] in FAILURES]
        # VALIDSIG: the key that signed (field 2), the primary key (the last field). A key named
        # exactly (KEY!) must be the one that signed.
        exact = self.key.endswith('!')
        if (verified.returncode != 0 or not good or failed or len(valid) != 1 or valid[0][-1] != self.primary
                or (exact and valid[0][2] != self.key[:-1].upper())):
            signature.unlink()
            raise SystemExit(f'The signature of {path.name} does not verify as {self.key} of {self.primary}:\n'
                             + verified.stderr.decode())
        return signature, valid[0][2]


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--sign', action='store_true', help=f'sign with the signing subkey {SIGNING_SUBKEY}!')
    parser.add_argument('--sign-key', default=os.environ.get('KEYTEND_GPG_KEY') or None,
                        help='sign with this key instead (default: $KEYTEND_GPG_KEY; none: unsigned)')
    parser.add_argument('--check-signing', action='store_true',
                        help='check the signing setup on a scratch file and package nothing')
    parser.add_argument('--canonical-modes', metavar='DIRECTORY', type=Path,
                        help='give the JARs in DIRECTORY the modes 0644 and 0755 (the distribution '
                             'profile runs it) and package nothing')
    parser.add_argument('--reports', metavar='DIRECTORY', type=Path,
                        help="the release check's reports of this commit (its run directory's "
                             "validation/), packaged as the binary ZIP's validation/")
    parser.add_argument('--central-bundle', metavar='FILE', type=Path,
                        help='the unsigned Central bundle of this build (./mvnw -Pdistribution,central '
                             'deploy -DskipUpload=true), signed into a published file of the release')
    parser.add_argument('--in-release-check', action='store_true',
                        help="tools/release-check.sh's own packaging, before its last checks: "
                             "unsigned, and the run's results are not required")
    options = parser.parse_args()
    if options.canonical_modes:
        canonical_modes_of(options.canonical_modes)
        return
    key = options.sign_key or (SIGNING_SUBKEY + '!' if options.sign or options.check_signing else None)
    if options.in_release_check and (key or not options.reports):
        raise SystemExit('--in-release-check packages a running release check\'s --reports, '
                         'unsigned')
    if options.central_bundle and not (key and options.reports):
        raise SystemExit('--central-bundle needs a signing key and --reports: Central refuses an unsigned bundle')
    signer = Signer(key) if key else None
    if options.check_signing:
        with tempfile.TemporaryDirectory() as scratch:
            probe = Path(scratch) / 'signing-check'
            probe.write_text('keytend-kmip signing check\n')
            _, by = signer.sign(probe)
        print(json.dumps({'signing_home': str(signer.home), 'key': key, 'signed_by': by, 'primary': signer.primary}))
        return
    if git('status', '--porcelain').strip():
        raise SystemExit('Commit source changes before packaging a release')
    ns = {'m': 'http://maven.apache.org/POM/4.0.0'}
    version = ET.parse(ROOT / 'pom.xml').getroot().findtext('m:version', namespaces=ns)
    if not re.fullmatch(VERSION_PATTERN, version or ''):
        raise SystemExit(f'A release version is required (X.Y.Z or X.Y.Z-rc.N), not {version}')
    for module, _ in MODULES + [TEST_ONLY]:
        parent = ET.parse(ROOT / module / 'pom.xml').getroot().findtext(
            'm:parent/m:version', namespaces=ns)
        if parent != version:
            raise SystemExit(f'{module}: parent version differs from release')
    commit = git('rev-parse', 'HEAD').decode().strip()
    # A release is made from a full release check run that passed, checked before anything is
    # written or signed.
    if options.reports:
        release_reports.check_run(options.reports, commit, version, options.in_release_check)
    epoch = int(git('show', '-s', '--format=%ct', 'HEAD'))
    timestamp = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
    zip_time = timestamp.timetuple()[:6]
    prefix = f'keytend-kmip-{version}/'
    # The JARs this build made already have the canonical modes: the distribution profile gave them
    # before Maven signed, installed or deployed any (canonical_modes_of). Changing them here would
    # make the release's bytes differ from Central's and from Maven's signatures, so a JAR without
    # them (a build that stopped at package, or ran without the profile) is refused.
    refuse_other_modes(sorted(ROOT.glob(f'*/target/keytend-kmip*-{version}*.jar'))
                       + sorted(ROOT.glob('*/target/lib/keytend-kmip*.jar')))
    # The source ZIP: the committed tree, as git archive gives it.
    source = {}
    with zipfile.ZipFile(io.BytesIO(git('archive', '--format=zip', 'HEAD'))) as archive:
        for info in archive.infolist():
            if not info.is_dir():
                source[info.filename] = (archive.read(info), info.external_attr)
    for required in ['pom.xml', 'mvnw', '.mvn/wrapper/maven-wrapper.properties', 'LICENSE', 'NOTICE']:
        if required not in source:
            raise SystemExit(f'the source tree has no {required}: it would not build')
    # The binary ZIP: no source tree.
    entries = {}
    artifacts = []

    def add(path, content):
        entries[path] = (content, 0o100644 << 16)
        artifacts.append({'path': path, 'sha256': hashlib.sha256(content).hexdigest(), 'bytes': len(content)})

    # The test-only module's assets, published beside the ZIP: name to content.
    beside = {}
    for module, artifact in MODULES + [TEST_ONLY]:
        bundled = BUNDLED.get(artifact, [])
        relocated_paths = tuple(b['relocated'].replace('.', '/') + '/' for b in bundled)
        test_only_module = (module, artifact) == TEST_ONLY
        for classifier in ['', '-sources'] if test_only_module else ['', '-sources', '-javadoc']:
            name = f'{artifact}-{version}{classifier}.jar'
            if not (ROOT / module / 'target' / name).is_file():
                raise SystemExit(f'{module}/target/{name}: missing; run the distribution build (-Pdistribution)')
            content = (ROOT / module / 'target' / name).read_bytes()
            with zipfile.ZipFile(io.BytesIO(content)) as jar:
                names = jar.namelist()
                for notice in ['LICENSE', 'NOTICE']:
                    if jar.read('META-INF/' + notice) != (ROOT / notice).read_bytes():
                        raise SystemExit(f'{name}: incorrect {notice}')
                if jar.testzip() is not None:
                    raise SystemExit(f'{name}: corrupted archive')
                test_only = [n for n in jar.namelist() if n.startswith(TEST_ONLY_PACKAGE)]
                if test_only_module:
                    # Its own package and descriptor alone: no class or source of the SDK's.
                    code = [n for n in names if n.endswith(('.class', '.java'))]
                    other = [n for n in code if not n.startswith(TEST_ONLY_PACKAGE)
                             and n not in ('module-info.class', 'module-info.java')]
                    if other:
                        raise SystemExit(f'{name}: holds {other[0]}, outside {TEST_ONLY_PACKAGE}')
                    if not test_only:
                        raise SystemExit(f'{name}: holds nothing of {TEST_ONLY_PACKAGE}')
                elif test_only:
                    raise SystemExit(f'{name}: holds the in-memory test server ({test_only[0]}), which is '
                                     f'{TEST_ONLY[1]}\'s alone')
                for b in bundled:
                    original = b['original'].replace('.', '/') + '/'
                    if any(n.startswith(original) for n in names):
                        raise SystemExit(f'{name}: {b["artifact"]} under its own name, {original}')
                    if classifier != '-javadoc' and jar.read(b['license']) != (
                            ROOT / module / 'src/main/resources' / b['license']).read_bytes():
                        raise SystemExit(f'{name}: incorrect {b["license"]}')
                if not classifier:
                    properties = jar.read(f'META-INF/maven/dev.keytend/{artifact}/pom.properties')
                    if f'version={version}'.encode() not in properties.splitlines():
                        raise SystemExit(f'{name}: incorrect embedded version')
                    for b in bundled:
                        coordinates = jar.read(f'META-INF/maven/{b["group"]}/{b["artifact"]}/pom.properties')
                        if f'version={pom_property(b["version_property"])}'.encode() not in coordinates.splitlines():
                            raise SystemExit(f'{name}: no pom.properties of the bundled {b["artifact"]}')
                    # The project's classes are Java 17's; the bundled ones run on 17 (not newer), and
                    # the descriptor (moditect writes it, at Java 9's class version) too.
                    classes = [n for n in names if n.endswith('.class')]
                    own = [n for n in classes if not n.startswith(relocated_paths) and n != 'module-info.class']
                    if not own or any(class_major(jar.read(n)) != JAVA_17 for n in own):
                        raise SystemExit(f'{name}: expected Java 17 bytecode')
                    if bundled and not any(n.startswith(relocated_paths) for n in classes):
                        raise SystemExit(f'{name}: the bundled classes are missing')
                    if any(class_major(jar.read(n)) > JAVA_17 for n in classes):
                        raise SystemExit(f'{name}: a class newer than Java 17')
                if classifier == '-sources':
                    committed = {f.relative_to(ROOT / module / 'src/main/java').as_posix()
                                 for f in (ROOT / module / 'src/main/java').rglob('*.java')}
                    sources = [n for n in names if n.endswith('.java')]
                    for name_in_jar in sources:
                        code = jar.read(name_in_jar)
                        if name_in_jar.startswith(relocated_paths):
                            # Bundled sources keep their own headers, never this project's.
                            b = next(b for b in bundled if name_in_jar.startswith(b['relocated'].replace('.', '/') + '/'))
                            if b['upstream_header'] not in code or PROJECT_HEADER[0] in code:
                                raise SystemExit(f'{name}: {name_in_jar} lacks its upstream header')
                            continue
                        if not all(line in code for line in PROJECT_HEADER):
                            raise SystemExit(f'{name}: missing Apache header in {name_in_jar}')
                        expected = (ROOT / module / 'src/main/java' / name_in_jar).read_text(encoding='utf-8')
                        for b in bundled:
                            expected = relocate_source(expected, b['original'], b['relocated'])
                        if code != expected.encode('utf-8'):
                            raise SystemExit(f'{name}: source differs from release commit: {name_in_jar}')
                    if committed - set(sources):
                        raise SystemExit(f'{name}: sources missing: {sorted(committed - set(sources))[:5]}')
                    if bundled and not any(n.startswith(relocated_paths) for n in sources):
                        raise SystemExit(f'{name}: the bundled sources are missing')
                if classifier == '-javadoc':
                    # The SDK's API only: no page of a bundled package, and no page or index naming one.
                    for b in bundled:
                        marks = [b[k].replace('.', '/') for k in ('relocated', 'original')]
                        marks += [b[k] for k in ('relocated', 'original')]
                        for n in names:
                            if any(m in n for m in marks) or (n.endswith(('.html', '.js')) and any(
                                    m.encode() in jar.read(n) for m in marks)):
                                raise SystemExit(f'{name}: {n} documents the bundled {b["artifact"]}')
            if test_only_module:
                beside[name] = content
            else:
                add('lib/' + name, content)
    # The applications' third-party runtime JARs, flat into lib/ beside the module JARs. A JAR two
    # applications use must be the same file; their copies of the project's own JARs must be the
    # ones shipped above.
    for module in APPLICATIONS:
        for jar_path in sorted((ROOT / module / 'target' / 'lib').glob('*.jar')):
            content = jar_path.read_bytes()
            path = 'lib/' + jar_path.name
            if path in entries:
                if entries[path][0] != content:
                    raise SystemExit(f'{module}/target/lib/{jar_path.name} differs from the lib/ JAR of that name')
                continue
            if jar_path.name.startswith(TEST_ONLY[1]):
                raise SystemExit(f'{module}/target/lib/{jar_path.name}: the in-memory test server is not a runtime '
                                 'library of any application')
            if jar_path.name.startswith('keytend-kmip'):
                raise SystemExit(f'{module}/target/lib/{jar_path.name}: not a JAR this build shipped')
            with zipfile.ZipFile(io.BytesIO(content)) as jar:
                if jar.testzip() is not None:
                    raise SystemExit(f'{module}/target/lib/{jar_path.name}: corrupted archive')
            add(path, content)
    in_lib = {path.rsplit('/', 1)[-1] for path in entries if path.startswith('lib/')}
    if any(name.startswith(TEST_ONLY[1]) for name in in_lib):
        raise SystemExit(f'lib/ holds {TEST_ONLY[1]}: the in-memory test server is not part of the release runtime')
    for module, artifact in MODULES:
        if module not in APPLICATIONS:
            continue
        class_path = manifest_class_path(entries[f'lib/{artifact}-{version}.jar'][0])
        if not class_path:
            raise SystemExit(f'{artifact}-{version}.jar: no Class-Path in its manifest')
        for element in class_path:
            if element.rsplit('/', 1)[-1] not in in_lib:
                raise SystemExit(f'{artifact}-{version}.jar: its Class-Path names {element}, which lib/ does not have')
    # Each module's SBOM: the SDK's lists exactly its allowlisted runtime dependencies (sdk/pom.xml);
    # an application's lists the SDK and exactly the third-party JARs lib/ carries for it. The
    # test-only module's (published beside the ZIP) lists exactly the SDK and slf4j-api.
    sboms = []
    for module, artifact in MODULES + [TEST_ONLY]:
        sbom_name = f'{artifact}-{version}-cyclonedx.json'
        sbom_file = ROOT / module / 'target' / sbom_name
        if not sbom_file.is_file():
            raise SystemExit(f'{module}/target/{sbom_name}: missing; run the distribution build online '
                             '(the CycloneDX plugin skips itself when Maven is offline, -o)')
        content = sbom_file.read_bytes()
        sbom = json.loads(content)
        purl = f'pkg:maven/dev.keytend/{artifact}@{version}?type=jar'
        if sbom.get('bomFormat') != 'CycloneDX' or sbom.get('metadata', {}).get('component', {}).get('purl') != purl:
            raise SystemExit(f'{sbom_name}: not a CycloneDX SBOM of {purl}')
        listed = sbom.get('components', [])
        if module == 'sdk':
            # Exactly the SDK's allowlisted runtime dependencies, under their own coordinates; the
            # bundled ones marked with the package the JAR has them under, the others not marked.
            components = {(c.get('group'), c.get('name')): c for c in listed}
            if set(components) != sdk_runtime_allowlist() or len(components) != len(listed):
                raise SystemExit(f'{sbom_name}: components {sorted(components)}, not the allowlist '
                                 f'{sorted(sdk_runtime_allowlist())}')
            shaded = {(b['group'], b['artifact']): b for b in BUNDLED['keytend-kmip']}
            for key, component in components.items():
                marks = [p.get('value') for p in component.get('properties', []) if p.get('name') == SHADED_PROPERTY]
                expected = [shaded[key]['relocated']] if key in shaded else []
                if marks != expected or component.get('scope') != 'required':
                    raise SystemExit(f'{sbom_name}: {key[1]} is {component.get("scope")}, {SHADED_PROPERTY} '
                                     f'{marks}; expected required, {expected}')
                if key in shaded and component.get('version') != pom_property(shaded[key]['version_property']):
                    raise SystemExit(f'{sbom_name}: {key[1]} {component.get("version")} is not the bundled version')
        coordinates = {(c.get('group'), c.get('name'), c.get('version')) for c in listed}
        if any(name == TEST_ONLY[1] for _, name, _ in coordinates):
            raise SystemExit(f'{sbom_name}: lists {TEST_ONLY[1]}, which nothing needs at run time')
        if module != 'sdk' and ('dev.keytend', 'keytend-kmip', version) not in coordinates:
            raise SystemExit(f'{sbom_name}: does not list keytend-kmip {version}')
        if module in APPLICATIONS:
            third_party = sorted(f"{c.get('name')}-{c.get('version')}.jar" for c in listed
                                 if c.get('group') != 'dev.keytend')
            shipped = sorted(p.name for p in (ROOT / module / 'target' / 'lib').glob('*.jar')
                             if not p.name.startswith('keytend-kmip'))
            if third_party != shipped:
                raise SystemExit(f'{sbom_name}: lists {third_party}, but {module}/target/lib holds {shipped}')
        if (module, artifact) == TEST_ONLY:
            # It adds no library: exactly the SDK and the SDK's runtime dependencies it does not bundle.
            expected = {('dev.keytend', 'keytend-kmip')} | (sdk_runtime_allowlist() - {
                (b['group'], b['artifact']) for b in BUNDLED['keytend-kmip']})
            components = {(c.get('group'), c.get('name')) for c in listed}
            if components != expected or len(components) != len(listed):
                raise SystemExit(f'{sbom_name}: components {sorted(components)}, not the SDK and its '
                                 f'runtime dependencies {sorted(expected)}')
            beside[sbom_name] = content
            continue
        sbom_path = 'lib/' + sbom_name
        add(sbom_path, content)
        sboms.append(sbom_path)
    # The launcher, LICENSE, NOTICE, the README and the reports.
    entries[LAUNCHER[1]] = (source[LAUNCHER[0]][0], 0o100755 << 16)
    for notice in ['LICENSE', 'NOTICE']:
        entries[notice] = (source[notice][0], 0o100644 << 16)
    entries['README.md'] = (BINARY_README.replace('VERSION', version).encode(), 0o100644 << 16)
    for path, content in validation_entries(source, options.reports, commit).items():
        entries[path] = (content, 0o100644 << 16)
    # An -rc.N version is a pre-release; a release X.Y.Z is not, whatever its major version.
    prerelease = '-rc.' in version
    # How it was packaged: a release from a full run that passed (check_run), the release check's
    # own packaging before its last checks, or without reports. tools/publish-release.sh
    # --publish takes only a release.
    packaged = ('in release check' if options.in_release_check
                else 'release' if options.reports else 'without reports')
    metadata = dict(version=version, tag='v' + version, prerelease=prerelease, commit=commit,
                    source_date_epoch=epoch, java_release=17, source_zip=source_zip(version),
                    reports='validation/', packaged=packaged,
                    sboms=sboms, artifacts=artifacts)
    entries['release.json'] = ((json.dumps(metadata, indent=2) + '\n').encode(), 0o100644 << 16)
    # SHA256SUMS lists every other file: the artifacts, then the rest in path order.
    listed = [a['path'] for a in artifacts]
    listed += sorted(set(entries) - set(listed))
    sums = ''.join(hashlib.sha256(entries[path][0]).hexdigest() + '  ' + path + '\n'
                   for path in listed)
    entries['SHA256SUMS'] = (sums.encode(), 0o100644 << 16)
    outside = sorted(path for path in entries if path.split('/', 1)[0] not in BINARY_TOP)
    if outside:
        raise SystemExit(f'the binary ZIP would hold {outside[:5]}, outside {sorted(BINARY_TOP)}')
    output = ROOT / 'target/releases'
    output.mkdir(parents=True, exist_ok=True)
    destination = output / f'keytend-kmip-{version}.zip'
    write_zip(destination, prefix, entries, zip_time)
    write_zip(output / source_zip(version), f'keytend-kmip-{version}-src/', source, zip_time)
    checksum = hashlib.sha256(destination.read_bytes()).hexdigest()
    if options.central_bundle:
        sign_central_bundle(options.central_bundle, output / central_bundle_name(version), version, signer, zip_time)
    else:
        for suffix in ('', '.sha256', '.asc'):
            (output / (central_bundle_name(version) + suffix)).unlink(missing_ok=True)
    # Beside the ZIP: the test-only assets, each published file's .sha256, SHA256SUMS, signatures.
    published, signatures, signing_key = write_beside(output, version, destination, entries['SHA256SUMS'][0],
                                                      beside, signer, central=bool(options.central_bundle))
    if not signer:
        print('Not signed (--sign, --sign-key or KEYTEND_GPG_KEY): the release artifacts are UNSIGNED',
              file=sys.stderr)
    if not options.reports:
        print('No --reports: the binary ZIP holds no release check reports, and '
              'tools/publish-release.sh refuses it', file=sys.stderr)
    print(json.dumps({'zip': str(destination), 'sha256': checksum, 'commit': commit,
                      'version': version, 'entries': len(entries), 'artifacts': len(artifacts),
                      'source_zip': str(output / source_zip(version)),
                      'source_sha256': hashlib.sha256(
                          (output / source_zip(version)).read_bytes()).hexdigest(),
                      'source_entries': len(source),
                      'reports': str(options.reports) if options.reports else None,
                      'beside': [path.name for path in published[1:]],
                      'signed_by': signer.primary if signer else None, 'signing_key': signing_key,
                      'signatures': [str(signature) for signature in signatures]}, indent=2))


if __name__ == '__main__':
    main()
