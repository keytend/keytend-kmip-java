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

"""The release's reports: what the binary ZIP's validation/ directory holds.

The release check (tools/release-check.sh) writes the reports of one run to a directory, which
tools/package-release.py --reports packages as the binary ZIP's validation/. The source tree's
validation/recorded/ holds the evidence the release check cannot produce: each file is listed in
validation/recorded/index.json with the date it was recorded, the server it was taken on and why
the release does not produce it. The packaging copies it to the ZIP's validation/recorded/.

Live results against keytend-kmip-server are entries of live-server.json, one per scope and KMIP
version: the scope (a check and its settings), the version, the date, the server build, the image,
whether it was the pinned one, the JDK, the command, the result (PASS or FAIL) and its detail. A new
result replaces the entry of its scope and version; nothing is appended. The packaging merges the
run's entries over the recorded ones (validation/recorded/live-server.json), each keeping its
source ("release check" or "recorded").

    release_reports.py check                     validate validation/recorded/
    release_reports.py set FILE --scope S --kmip V [--kmip V ...] --date D --server S
        [--image ID] [--pinned yes|no] --jdk N --command C --result PASS|FAIL --detail TEXT
        [--source S]                             replace those entries in FILE
    release_reports.py probe FILE WORK [--scenarios S] [--env KMIP_X=V] [--server S --image ID
        --pinned yes|no --jdk N --date D]        the server probe's results (WORK/v*/probe.log)
    release_reports.py interop FILE LOG [--setup S] [--work DIR] [the same options]
                                                 the interop suite's results (its output)
    release_reports.py bench FILE WORK --scale N [the same options]
                                                 the benchmark's smoke run (WORK/live-v*/bench.log)
    release_reports.py cassandra FILE TRIAL... [the same options]
                                                 the Cassandra trunk dtest (each run-trial.sh OUT)
    release_reports.py merge RECORDED RUN OUT    the entries of RUN over those of RECORDED
    release_reports.py pinned RECORDED [--run RUN]
                                                 refuse what would ship of another server build
    release_reports.py complete FILE             refuse a live-server.json without the run's own
                                                 passing result of every live check the release
                                                 check runs (what tools/publish-release.sh requires)
    release_reports.py run DIR [--commit C] [--version V] [--in-release-check]
                                                 refuse a run directory's validation/ (DIR) that
                                                 cannot make a release (check_run)
    release_reports.py guard DIR                 refuse reports holding test output or local paths
    release_reports.py scrub SOURCE DEST --replace OLD=NEW [--replace OLD=NEW ...]
                                                 copy a report file or directory, local paths
                                                 named (gzip files too)

probe, interop, bench and cassandra print the entries they wrote, and exit 3 when one is FAIL.
"""
import argparse
import datetime
import getpass
import gzip
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
RECORDED = ROOT / 'validation' / 'recorded'
LIVE = 'live-server.json'
RESULTS = ('PASS', 'FAIL')
FIELDS = ('scope', 'kmip', 'date', 'server', 'image', 'pinned', 'jdk', 'command', 'result',
          'detail', 'source')
DATE = re.compile(r'\d{4}-\d{2}-\d{2}')
INDEX_FIELDS = ('path', 'what', 'server', 'recorded', 'why')
PIN = ROOT / 'tools' / 'kmip-server' / 'pinned-image.properties'
SERVER_ARGUMENT = '<the pinned Docker archive or image>'
# The live checks a release may ship as recorded, each with the command that records it again on
# the pinned image (docs/releasing.md, "Recorded results"). Every other live check is the release
# check's own.
RECORDED_SCOPES = {
    'cassandra-trunk-tde dtest':
        f'tools/record-live.sh cassandra-dtest --server {SERVER_ARGUMENT} '
        '--cassandra ../cassandra-trunk',
}
RELEASE_CHECK_COMMAND = f'tools/release-check.sh --server {SERVER_ARGUMENT}'
# The live checks the release check runs with --server, each with the KMIP versions it runs them at
# (tools/release-check.sh; the interop programs and versions of
# integration/keytend-kmip-server/run-interop.sh, which runs reversal, renewal and purpose from 2.0
# only). A release ships the run's own passing result of each (run_problems).
PROBE_VERSIONS = ('1.1', '1.2', '1.4', '2.1', '3.0')
INTEROP_VERSIONS = ('1.1', '1.2', '1.3', '1.4', '2.0', '2.1', '3.0')
FROM_2_0 = ('2.0', '2.1', '3.0')
RELEASE_CHECK_SCOPES = {
    'server-probe all': PROBE_VERSIONS,
    'server-probe all, KMIP_DESTROYED_NAME_REUSE=reserve': PROBE_VERSIONS,
    'server-probe all, KMIP_LEASE_STATES=active': PROBE_VERSIONS,
    'server-probe raw-leases,tls, KMIP_MAX_LEASE_SECONDS=0': ('1.4', '2.1', '3.0'),
    'interop configured suite': INTEROP_VERSIONS,
    'interop configured controls': INTEROP_VERSIONS,
    'interop configured reversal': FROM_2_0,
    'interop configured renewal': FROM_2_0,
    'interop configured purpose': FROM_2_0,
    'interop minimal suite': INTEROP_VERSIONS,
    'bench smoke': ('1.4', '2.1', '3.0'),
}
# The probe's full tls-issue-repeat runs in its "all" from KMIP 1.4 (tools/server-probe/README.md):
# each "all" entry at those versions must show it passed every check (run_problems), as many as
# the probe's source makes (full_repeat_passes).
REPEAT_VERSIONS = ('1.4', '2.1', '3.0')
REPEAT_COUNTS = re.compile(r'(?:^|; |, )tls-issue-repeat pass=(\d+) fail=(\d+) ')
PROBE_SOURCE = ROOT / 'tools' / 'server-probe' / 'ServerProbe.java'

# What a run must be to make a release (check_run). release-check.txt is the table of the checks
# before the packaging, summary.txt the whole run's; each row is "RESULT  CHECK DETAIL".
RELEASE_CHECK = 'release-check.txt'
SUMMARY = 'summary.txt'
RESULTS_OF_ROWS = ('PASS', 'FAIL', 'SKIP', 'UNPIN')
# The first release: the one release without an API baseline (tools/api-baseline.sh), so the only
# one, with its pre-releases, whose release check may record api-baseline as SKIP.
FIRST_RELEASE = '0.10.0'
# The rows of release-check.txt a release needs, each PASS (api-baseline SKIP under the
# first-release rule, and then no api-compat; otherwise api-compat PASS too).
REQUIRED_ROWS = ('test-jdk17', 'verify-jdk17', 'verify-jdk21', 'verify-jdk25',
                 'format-fixtures-jdk17', 'format-fixtures-jdk21', 'format-fixtures-jdk25',
                 'license-headers-jdk17', 'license-headers-jdk21', 'license-headers-jdk25',
                 'license_headers.py', 'api-baseline', 'live-run', 'live-pin', 'reports')
# The checks of what was packaged, which only summary.txt has.
PACKAGED_ROWS = ('distribution-a', 'distribution-b', 'central-bundle', 'reproducible',
                 'reproducible-javadoc', 'user-commands')
# The release check's arguments that leave out or weaken a check: a run with any cannot make a
# release.
REFUSED_ARGUMENTS = ('--skip-verify', '--skip-api', '--skip-repro', '--allow-dirty',
                     '--no-api-fail', '--server-unpinned')
# The release check's arguments a release needs: --integration runs the workflow suite and the
# catalog, whose reports (INTEGRATION_REPORTS) the compatibility tables rely on.
REQUIRED_ARGUMENTS = ('--integration',)
# The JDKs a release is verified on, each with its workflow and catalog reports.
RELEASE_JDKS = ('17', '21', '25')
# The reports --integration writes to validation/ (tools/summarize-validation.py,
# tools/summarize-catalog.py and their renderers), besides each run's own files, which their
# summary.json files name.
INTEGRATION_REPORTS = ('workflows/summary.json', 'workflows/overview.html', 'catalog/summary.json',
                       'catalog/cases.csv', 'catalog/overview.html', 'catalog/policy-coverage.html')
# A local path in a report: a home, temporary, mount, workspace or build directory, a file: URL, or
# a Windows drive path (the scrubbed reports name the run directory, the checkout and the home
# directory instead). Paths inside other URLs and the scrubbed names do not count, nor does the
# committed evidence (recorded/), whose paths are inside its containers.
LOCAL_PATH = re.compile(
    r'(?<![\w.~<>:/-])/(?:home|Users|tmp|var|private|root|mnt|media|run|opt|srv|data|scratch|'
    r'workspaces?|builds?|nix|Volumes|cygdrive|__w)/'
    r'|(?<![\w-])file:/'
    r'|(?<![\w-])[A-Za-z]:(?:\\{1,2}|/(?!/))[\w.$~ -]')
DEFAULT_RUN = '/tmp/keytend-kmip-release-check'


def key(entry):
    return entry['scope'], tuple(int(part) for part in entry['kmip'].split('.'))


def load(path):
    """The entries of a live-server.json; none when it does not exist."""
    if not Path(path).is_file():
        return []
    return parse(Path(path).read_text(encoding='utf-8'), path)


def parse(text, path):
    """The entries of a live-server.json's text (path names it in errors)."""
    try:
        data = json.loads(text)
    except ValueError as e:
        raise SystemExit(f'{path}: not JSON ({e})')
    entries = data.get('entries') if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise SystemExit(f'{path}: no "entries" list')
    for entry in entries:
        check_entry(path, entry)
    return entries


def check_entry(path, entry):
    missing = [field for field in FIELDS if field not in entry]
    if missing or set(entry) - set(FIELDS):
        raise SystemExit(f'{path}: an entry has fields {sorted(entry)}, not {list(FIELDS)}')
    if entry['result'] not in RESULTS:
        raise SystemExit(f'{path}: {entry["scope"]} {entry["kmip"]}: result {entry["result"]!r}')
    if not DATE.fullmatch(entry['date']):
        raise SystemExit(f'{path}: {entry["scope"]} {entry["kmip"]}: date {entry["date"]!r}')
    if not re.fullmatch(r'\d\.\d', entry['kmip']):
        raise SystemExit(f'{path}: {entry["scope"]}: KMIP version {entry["kmip"]!r}')


def dump(path, entries):
    """Writes the entries, one per scope and version, in that order: the same bytes for the same
    entries, so that a ZIP holding them stays reproducible."""
    by_key = {}
    for entry in entries:
        check_entry(path, entry)
        by_key[key(entry)] = {field: entry[field] for field in FIELDS}
    text = json.dumps({'entries': [by_key[k] for k in sorted(by_key)]}, indent=2) + '\n'
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(text, encoding='utf-8')


def replace(path, new):
    """Replaces the entries of each new entry's scope and version; keeps the others."""
    kept = {key(entry): entry for entry in load(path)}
    for entry in new:
        kept[key(entry)] = entry
    dump(path, kept.values())


def merge(recorded, run):
    """The run's entries over the recorded ones: each scope and version keeps its latest."""
    out = {key(entry): entry for entry in recorded}
    for entry in run:
        out[key(entry)] = entry
    return [out[k] for k in sorted(out)]


def read_pin(path=PIN):
    """The pinned keytend-kmip-server build: pinned-image.properties as a dict."""
    pin = {}
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        if line and not line.startswith('#') and '=' in line:
            name, _, value = line.partition('=')
            pin[name.strip()] = value.strip()
    for name in ('name', 'version', 'image_id'):
        if not pin.get(name):
            raise SystemExit(f'{path}: no {name}')
    return pin


def versions(entries):
    return ', '.join(e['kmip'] for e in sorted(entries, key=key))


def pin_problems(entries, pin, where):
    """Why the live entries that would ship (entries, after the merge; where, the file they come
    from) cannot: an entry that is not PASS, recorded ones included, an entry of another server
    build than the pin, or a recorded entry of a check the release check runs itself. Each problem
    says what to run; none when every entry may ship."""
    pinned = f'{pin["name"]} {pin["version"]} (image {pin["image_id"][:12]})'
    groups = {}
    for entry in entries:
        groups.setdefault((entry['source'], entry['scope']), []).append(entry)
    problems = []
    for (source, scope), group in sorted(groups.items()):
        failed = [e for e in group if e['result'] != 'PASS']
        if failed:
            command = RECORDED_SCOPES.get(scope, RELEASE_CHECK_COMMAND) if source == 'recorded' \
                else RELEASE_CHECK_COMMAND
            problems.append(f'{where}: {scope} (KMIP {versions(failed)}, {source}) is '
                            f'{" and ".join(sorted({e["result"] for e in failed}))}: a release '
                            f'ships passing results only. Run it again: {command}')
        if source == 'recorded' and scope not in RECORDED_SCOPES:
            problems.append(f'{where}: {scope} (KMIP {versions(group)}) is recorded, but the '
                            'release check runs it: remove it from validation/recorded/'
                            f'{LIVE} and run {RELEASE_CHECK_COMMAND}')
            continue
        stale = [e for e in group if e['image'] != pin['image_id'] or not e['pinned']]
        if not stale:
            continue
        builds = sorted({f'{e["server"]} (image {e["image"][:12] or "unknown"})' for e in stale})
        command = RECORDED_SCOPES[scope] if source == 'recorded' else RELEASE_CHECK_COMMAND
        problems.append(f'{where}: {scope} (KMIP {versions(stale)}) ran on '
                        f'{" and ".join(builds)}, not on the pinned {pinned}. '
                        f'Run it again on the pinned image: {command}'
                        + (', and commit validation/recorded/' + LIVE
                           if source == 'recorded' else ''))
    return problems


def run_problems(entries, pin, where):
    """Why the live entries that would ship (entries, after the merge; where, the file they come
    from) lack the release check's own run: each live check the release check runs
    (RELEASE_CHECK_SCOPES), at each KMIP version, must have an entry from this run ("release
    check"), PASS, on the pinned image. A run without --server leaves every one missing. None when
    the run is complete."""
    by_key = {(e['scope'], e['kmip']): e for e in entries}
    missing, failed, other, repeat = [], [], [], []
    for scope, kmip_versions in RELEASE_CHECK_SCOPES.items():
        for version in kmip_versions:
            entry = by_key.get((scope, version))
            if entry is None or entry['source'] != 'release check':
                missing.append(f'{scope} {version}')
            elif entry['result'] != 'PASS':
                failed.append(f'{scope} {version}')
            elif entry['image'] != pin['image_id'] or not entry['pinned']:
                other.append(f'{scope} {version}')
            elif scope.startswith('server-probe all') and version in REPEAT_VERSIONS:
                counts = REPEAT_COUNTS.search(entry['detail'])
                passes = full_repeat_passes()
                if not counts or counts.groups() != (str(passes), '0'):
                    repeat.append(f'{scope} {version} ('
                                  + (f'pass={counts.group(1)} fail={counts.group(2)}' if counts
                                     else 'not run') + f', not pass={passes} fail=0)')
    problems = []
    if missing:
        problems.append(f'{where}: {len(missing)} live results the release check runs are not '
                        f'this run\'s ({", ".join(missing[:4])}'
                        + (f' and {len(missing) - 4} more' if len(missing) > 4 else '')
                        + f'). Run {RELEASE_CHECK_COMMAND} and package its reports')
    if failed:
        problems.append(f'{where}: this run failed {", ".join(failed)}')
    if other:
        problems.append(f'{where}: {", ".join(other)} ran on another image than the pinned '
                        f'{pin["name"]} {pin["version"]}')
    if repeat:
        problems.append(f'{where}: {", ".join(repeat)} did not pass the full tls-issue-repeat')
    return problems


def full_repeat_passes(source=PROBE_SOURCE):
    """How many checks the probe's full tls-issue-repeat passes at a version: one per issue
    operation (IssueOp), way of stopping (StopMode) and check of each (repeatEach's check(step...)
    calls), read from the probe's source."""
    text = Path(source).read_text(encoding='utf-8')

    def constants(enum):
        body = re.search(r'\benum ' + enum + r' \{(.*?);', text, re.S)
        if not body:
            raise SystemExit(f'{source}: no enum {enum}')
        return len(re.findall(r'^\s*[A-Z][A-Z0-9_]*\(', body.group(1), re.M))
    each = re.search(r'static void repeatEach\((.*?)\n  \}\n', text, re.S)
    if not each:
        raise SystemExit(f'{source}: no repeatEach')
    checks = len(re.findall(r'\bcheck\(step\b', each.group(1)))
    passes = constants('IssueOp') * constants('StopMode') * checks
    if not passes:
        raise SystemExit(f'{source}: tls-issue-repeat makes no check')
    return passes


def check_pinned(entries, pin, where):
    problems = pin_problems(entries, pin, where)
    if problems:
        raise SystemExit('REFUSED: a release ships live results of the pinned server build only\n'
                         + '\n'.join('  ' + p for p in problems))


def check_recorded(directory=RECORDED):
    """validation/recorded/: index.json lists every other file there, each once, with its date
    and server; live-server.json holds recorded entries only, of the checks in RECORDED_SCOPES.
    Returns the index's entries."""
    index_path = directory / 'index.json'
    index = json.loads(index_path.read_text(encoding='utf-8'))
    listed = []
    for item in index.get('files', []):
        if tuple(item) != INDEX_FIELDS or not all(isinstance(item[f], str) and item[f]
                                                  for f in INDEX_FIELDS):
            raise SystemExit(f'{index_path}: an entry is not {list(INDEX_FIELDS)}: {item}')
        if not DATE.fullmatch(item['recorded']):
            raise SystemExit(f'{index_path}: {item["path"]}: recorded {item["recorded"]!r} '
                             'is not a date')
        listed.append(item['path'])
    present = sorted(p.relative_to(directory).as_posix() for p in directory.rglob('*')
                     if p.is_file() and p.name != 'index.json' and '__pycache__' not in p.parts)
    if sorted(listed) != present or len(set(listed)) != len(listed):
        raise SystemExit(f'{index_path}: lists {sorted(listed)}, but the directory holds {present}')
    for entry in load(directory / LIVE):
        if entry['source'] != 'recorded':
            raise SystemExit(f'{directory / LIVE}: {entry["scope"]} {entry["kmip"]} '
                             'is not recorded')
        if entry['scope'] not in RECORDED_SCOPES:
            raise SystemExit(f'{directory / LIVE}: {entry["scope"]} {entry["kmip"]}: the release '
                             f'check runs it; only {", ".join(RECORDED_SCOPES)} may be recorded')
    return index['files']


def rows(text):
    """The rows of a release check table (release-check.txt or summary.txt): each check's name (the
    first word of its CHECK column) to its results, in order."""
    out = {}
    for line in text.splitlines():
        m = re.match(r'^(' + '|'.join(RESULTS_OF_ROWS) + r')  (\S+)', line)
        if m:
            out.setdefault(m.group(2), []).append(m.group(1))
    return out


def release_of(version):
    """The release X.Y.Z a version X.Y.Z or X.Y.Z-rc.N is of."""
    return version.split('-', 1)[0]


def table_problems(table, where, version, required):
    """Why a table's rows cannot make a release: a required row missing, or any row not PASS
    (api-baseline may be SKIP for the first release and its pre-releases only)."""
    problems = []
    for name in required:
        if name not in table:
            problems.append(f'{where}: no {name} row: the release check did not run it')
    for name, results in table.items():
        for result in results:
            if result == 'PASS':
                continue
            if name == 'api-baseline' and result == 'SKIP' and release_of(version) == FIRST_RELEASE:
                continue
            why = ' (SKIP only for the first release, ' + FIRST_RELEASE + ', and its ' \
                'pre-releases)' if name == 'api-baseline' and result == 'SKIP' else ''
            problems.append(f'{where}: {name} is {result}{why}')
    if table.get('api-baseline') == ['PASS'] and table.get('api-compat') != ['PASS']:
        problems.append(f'{where}: api-baseline passed but api-compat did not')
    return problems


def release_check_problems(text, commit, version, where=RELEASE_CHECK):
    """Why a run's release-check.txt (text) cannot make the release of version at commit: another
    commit, a last line other than PASSED BEFORE PACKAGING, an argument that leaves out a check
    (REFUSED_ARGUMENTS) or one missing that a release needs (REQUIRED_ARGUMENTS), or a row missing
    or not passing (REQUIRED_ROWS, table_problems)."""
    problems = []
    named = re.findall(r'^commit ([0-9a-f]{40})$', text, re.M)
    if named != [commit]:
        problems.append(f'{where} is of commit {named}, not of {commit}')
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines or not lines[-1].startswith('PASSED BEFORE PACKAGING'):
        problems.append(f'{where} does not say the release checks before packaging passed: '
                        + (lines[-1] if lines else 'empty'))
    arguments = re.findall(r'^arguments(?: (.*))?$', text, re.M)
    if len(arguments) != 1:
        problems.append(f'{where} names no arguments line')
    else:
        given = (arguments[0] or '').split()
        refused = [a for a in REFUSED_ARGUMENTS if a in given]
        if refused:
            problems.append(f'{where}: the run left out or weakened checks ({" ".join(refused)}): '
                            'run the full release check')
        needed = [a for a in REQUIRED_ARGUMENTS if a not in given]
        if needed:
            problems.append(f'{where}: the run did not have {" ".join(needed)}: run the full '
                            'release check')
    return problems + table_problems(rows(text), where, version, REQUIRED_ROWS)


def summary_problems(text, commit, version, where=SUMMARY):
    """Why a run's summary.txt (text) cannot make the release: another commit, a last line other
    than RELEASE CHECK PASSED, or a check of what was packaged (PACKAGED_ROWS) missing or not
    passing."""
    problems = []
    if not re.search(r'^commit ' + re.escape(commit) + r'; ', text, re.M):
        problems.append(f'{where} is not of commit {commit}')
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines or not lines[-1].startswith('RELEASE CHECK PASSED'):
        problems.append(f'{where} does not say the release check passed: '
                        + (lines[-1] if lines else 'empty'))
    return problems + table_problems(rows(text), where, version, REQUIRED_ROWS + PACKAGED_ROWS)


def check_run(reports, commit, version, in_release_check=False, recorded=None):
    """Refuses a run that cannot make the release of version at commit (reports: the run
    directory's validation/): its release-check.txt (release_check_problems), its live results
    merged over the recorded ones (every live check this run, passing, on the pin: run_problems and
    pin_problems), its workflow and catalog reports (integration_problems), and its summary.txt
    beside validation/ (summary_problems). In a release check
    that is still running (in_release_check, which packages before its last checks), only the
    run's summary.txt must not exist yet: the run's results are checked when the release is
    packaged again and published."""
    reports = Path(reports)
    summary = reports.parent / SUMMARY
    if in_release_check:
        if summary.exists():
            raise SystemExit(f'REFUSED: {summary} exists: the release check that wrote '
                             f'{reports} has finished; package it without --in-release-check')
        return
    problems = []
    check = reports / RELEASE_CHECK
    if not check.is_file():
        problems.append(f'{reports} has no {RELEASE_CHECK}: not a release check\'s reports')
    else:
        problems += release_check_problems(check.read_text(encoding='utf-8'), commit, version,
                                           str(check))
    run_entries = load(reports / LIVE)
    live = merge(load(recorded if recorded is not None else RECORDED / LIVE), run_entries)
    pin = read_pin()
    problems += run_problems(live, pin, str(reports / LIVE))
    problems += pin_problems(live, pin, str(reports / LIVE))
    problems += integration_problems(reports_of(reports), str(reports))
    if not summary.is_file():
        problems.append(f'{reports.parent} has no {SUMMARY}: the release check did not finish')
    else:
        problems += summary_problems(summary.read_text(encoding='utf-8'), commit, version,
                                     str(summary))
    if problems:
        raise SystemExit('REFUSED: a release is made from a full release check run that passed '
                         '(docs/releasing.md, step 2)\n' + '\n'.join('  ' + p for p in problems))


def readable(name, content):
    """A report's text: a gzip file's content uncompressed; None when it is not UTF-8 text."""
    if name.endswith('.gz'):
        try:
            content = gzip.decompress(content)
        except (OSError, EOFError):
            return None
    try:
        return content.decode('utf-8')
    except UnicodeDecodeError:
        return None


def report_texts(name, content):
    """The texts of a report to check for local paths, or a problem string when it cannot be read:
    its text (a gzip file's uncompressed; bytes that are not UTF-8 read one character per byte, so
    nothing is skipped), and, for JSON, each string in it decoded (escaped slashes and backslashes,
    \\u escapes)."""
    if name.endswith('.gz'):
        try:
            content = gzip.decompress(content)
        except (OSError, EOFError) as e:
            return f'not a readable gzip file ({e}): a release ships only reports it can check'
    try:
        text = content.decode('utf-8')
    except UnicodeDecodeError:
        text = content.decode('latin-1')
    texts = [text]
    if re.search(r'\.json(?:\.gz)?$', name):
        try:
            data = json.loads(text)
        except ValueError:
            return 'not JSON: a release ships only reports it can check'
        strings = []

        def walk(value):
            if isinstance(value, str):
                strings.append(value)
            elif isinstance(value, dict):
                for k, v in value.items():
                    strings.append(k)
                    walk(v)
            elif isinstance(value, list):
                for v in value:
                    walk(v)
        walk(data)
        texts.append('\n'.join(strings))
    return texts


# An absolute local path in a report's text: from a / that does not continue a word, a relative
# path or a URL (LOCAL_PATH's rule), or from a Windows drive, up to a blank or a quote.
ABSOLUTE_PATH = re.compile(r'(?<![\w.~<>:/-])/[^\s"\'<>`]+'
                           r'|(?<![\w-])[A-Za-z]:(?:\\{1,2}|/(?!/))[^\s"\'<>`]+')


def user_found(text, user):
    """Whether text names the user where a user name identifies a machine's user: a segment of an
    absolute path (ABSOLUTE_PATH), ~USER, USER@HOST, or the value of a user, login or owner field.
    Not in prose, relative paths or URLs, where a user name such as root is an ordinary word
    ("Self-signed root validation")."""
    for path in ABSOLUTE_PATH.finditer(text):
        if user in re.split(r'[/\\]+', path.group()):
            return True
    u = re.escape(user)
    end = r'(?![\w.-])'
    return re.search(
        r'(?<![\w.-])~' + u + end
        + r'|(?<![\w.-])' + u + r'@[\w-]'
        + r'|(?i:\b(?:user(?:[._ -]?name)?|login|logname|owner|uid)\b["\']?\s*[:=]\s*["\']?)'
        + u + end, text) is not None


def report_problems(files, home=None, user=None):
    """Why reports (files: path in validation/ to content, without recorded/) cannot ship in a
    binary ZIP: Surefire or Failsafe output (a TEST-*.xml, a *-surefire-reports or
    *-failsafe-reports directory, or an XML test suite), a gzip file it cannot read, a JSON file
    that does not parse, or a local path: the home directory, the user name in a path or an
    identity field (user_found), the release check's default run directory, or any home,
    temporary, mount, workspace or build path, file: URL or Windows drive path (LOCAL_PATH). Gzip
    files are read uncompressed, bytes that are not UTF-8 one character per byte, and JSON both as
    text and as its decoded strings."""
    home = os.path.expanduser('~') if home is None else home
    user = getpass.getuser() if user is None else user
    problems = []
    for name, content in sorted(files.items()):
        parts = name.split('/')
        if re.fullmatch(r'TEST-.*\.xml', parts[-1]) or any(
                re.search(r'surefire|failsafe', part) for part in parts):
            problems.append(f'{name}: Surefire or Failsafe output, not a report')
            continue
        texts = report_texts(name, content)
        if isinstance(texts, str):
            problems.append(f'{name}: {texts}')
            continue
        if parts[-1].endswith('.xml') and '<testsuite' in texts[0]:
            problems.append(f'{name}: a JUnit test suite, not a report')
            continue
        found = []
        for text in texts:
            if home and home != '/' and home in text:
                found.append('the home directory')
            if user and len(user) > 1 and user_found(text, user):
                found.append(f'the user name {user}')
            if DEFAULT_RUN in text:
                found.append(DEFAULT_RUN)
            path = LOCAL_PATH.search(text)
            if path and not any(f.startswith('a local path') for f in found):
                found.append('a local path (' + text[path.start():path.start() + 40].split()[0]
                             + ')')
        if found:
            problems.append(f'{name}: {", ".join(dict.fromkeys(found))}')
    return problems


def integration_problems(files, where):
    """Why reports (files: path in validation/ to content) lack what --integration writes: the
    workflow suite's and the catalog's summaries and pages (INTEGRATION_REPORTS), a run on each of
    RELEASE_JDKS in each summary, and every run's file the summaries name (each workflow report,
    each catalog record file)."""
    problems = [f'{where}: no {path}: the release check ran without --integration or its '
                'reports did not pass' for path in INTEGRATION_REPORTS if path not in files]

    def summary(path):
        try:
            return json.loads(files[path])
        except (KeyError, ValueError):
            return None
    workflows = summary('workflows/summary.json')
    if isinstance(workflows, dict):
        rows = workflows.get('workflows') or []
        jdks = sorted({str(r.get('jdk')) for r in rows if isinstance(r, dict)})
        missing = [j for j in RELEASE_JDKS if j not in jdks]
        if missing:
            problems.append(f'{where}: workflows/summary.json has no run on JDK '
                            + ', '.join(missing))
        for r in rows:
            run = f'workflows/{r.get("server")}-{r.get("version")}-jdk{r.get("jdk")}.json'
            if run not in files:
                problems.append(f'{where}: no {run}, which workflows/summary.json names')
    elif 'workflows/summary.json' in files:
        problems.append(f'{where}: workflows/summary.json is not a summary')
    catalog = summary('catalog/summary.json')
    if isinstance(catalog, dict):
        tuples = catalog.get('tuples') or []
        controlled = catalog.get('controlled') or []
        for kind, items in (('tuples', tuples), ('controlled', controlled)):
            jdks = {str(t.get('jdk')) for t in items if isinstance(t, dict)}
            missing = [j for j in RELEASE_JDKS if j not in jdks]
            if missing:
                problems.append(f'{where}: catalog/summary.json has no {kind} on JDK '
                                + ', '.join(missing))
        for t in tuples + controlled:
            evidence = 'catalog/' + str(t.get('evidence'))
            if evidence not in files:
                problems.append(f'{where}: no {evidence}, which catalog/summary.json names')
    elif 'catalog/summary.json' in files:
        problems.append(f'{where}: catalog/summary.json is not a summary')
    return problems


def reports_of(directory):
    """The files of a reports directory, path to content, without recorded/."""
    directory = Path(directory)
    return {p.relative_to(directory).as_posix(): p.read_bytes()
            for p in sorted(directory.rglob('*'))
            if p.is_file() and not p.relative_to(directory).as_posix().startswith('recorded/')}


def check_reports(files, where):
    problems = report_problems(files)
    if problems:
        raise SystemExit(f'REFUSED: {where} holds what a release does not ship (test output or a '
                         'local path; tools/release-check.sh writes the reports without them)\n'
                         + '\n'.join('  ' + p for p in problems))


def scrub(source, dest, replacements):
    """Copies the report file or directory source to dest with each (old, new) of replacements
    made in order, in text files and in gzip files' text (recompressed with no time, so the bytes
    depend on the text only); other files are copied unchanged."""
    source, dest = Path(source), Path(dest)
    pairs = [(source, dest)] if source.is_file() else [
        (p, dest / p.relative_to(source)) for p in sorted(source.rglob('*')) if p.is_file()]
    for path, target in pairs:
        content = path.read_bytes()
        text = readable(path.name, content)
        if text is not None:
            for old, new in replacements:
                if old:
                    text = text.replace(old, new)
            content = text.encode('utf-8')
            if path.name.endswith('.gz'):
                content = gzip.compress(content, mtime=0)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)


def junit_from_log(log):
    """Each module's JUnit totals ([run, skipped] per surefire or failsafe run), in build order,
    from a sequential Maven log. Every line must report no failures and no errors."""
    totals, module = {}, None
    for line in log.splitlines():
        m = re.match(r'^\[INFO\] Building (.+?) [0-9][^ ]*\s+\[\d+/\d+\]$', line)
        if m:
            module = m.group(1)
            continue
        m = re.match(r'^\[(?:INFO|WARNING|ERROR)\] Tests run: (\d+), Failures: (\d+), '
                     r'Errors: (\d+), Skipped: (\d+)\s*$', line)
        if m:
            assert m.group(2) == m.group(3) == '0', f'{module}: {line}'
            totals.setdefault(module, []).append([int(m.group(1)), int(m.group(4))])
    return totals


def junit_from_reports(directory):
    """Each module's JUnit totals ([run, skipped] for its surefire, then its failsafe reports) from
    the release check's copies, DIRECTORY/MODULE-surefire-reports and MODULE-failsafe-reports. Every
    suite must report no failures and no errors."""
    import xml.etree.ElementTree as ET
    totals = {}
    for kind in ('surefire', 'failsafe'):
        for reports in sorted(Path(directory).glob(f'*-{kind}-reports')):
            module = reports.name[:-len(f'-{kind}-reports')]
            run = skipped = 0
            for path in sorted(reports.rglob('TEST-*.xml')):
                suite = ET.parse(path).getroot()
                failed = suite.get('failures', '0') != '0' or suite.get('errors', '0') != '0'
                assert not failed, f'{path}: failed'
                run += int(suite.get('tests', 0))
                skipped += int(suite.get('skipped', 0))
            totals.setdefault(module, []).append([run, skipped])
    return totals


def junit_runs(logs, reports, default_jdks=('17', '21', '25')):
    """The JUnit totals of each JDK's run, from --junit JDK=DIR (the release check's report copies)
    or --log JDK=PATH (a sequential build log, such as tools/verify-jdks.sh writes; by default
    .cache/integration-jdkN.log for 17, 21 and 25). Each log must say BUILD SUCCESS."""
    runs = {}
    for spec in reports or []:
        jdk, _, directory = spec.partition('=')
        runs[jdk] = junit_from_reports(directory)
    default = [] if reports else [f'{j}=.cache/integration-jdk{j}.log' for j in default_jdks]
    for spec in logs or default:
        jdk, _, path = spec.partition('=')
        text = (ROOT / path).read_text(encoding='utf-8', errors='replace')
        if 'BUILD SUCCESS' not in text:
            raise SystemExit(f'JDK {jdk}: the integration build did not succeed ({path})')
        runs[jdk] = junit_from_log(text)
    if not runs:
        raise SystemExit('no JDK runs: give --junit JDK=DIR or --log JDK=PATH')
    return dict(sorted(runs.items(), key=lambda item: int(item[0])))


def identity(options):
    return dict(date=options.date or datetime.date.today().isoformat(), server=options.server,
                image=options.image, pinned=options.pinned == 'yes', jdk=options.jdk,
                source=options.source)


def probe_entries(work, options):
    """One entry per version of the server probe's run in WORK (v<version>/probe.log): its
    SUMMARY line, and each scenario's counts in the detail."""
    entries = []
    for log in sorted(Path(work).glob('v*/probe.log')):
        version = log.parent.name[1:]
        text = log.read_text(encoding='utf-8', errors='replace')
        summary = re.search(r'^SUMMARY \[[^]]*\] pass=(\d+) fail=(\d+) info=(\d+) skip=(\d+)$',
                            text, re.M)
        scenarios, current = {}, None
        for line in text.splitlines():
            header = re.match(r'^---- \[[^]]*\] (\S+)$', line)
            if header:
                current = scenarios.setdefault(header.group(1),
                                               dict(PASS=0, FAIL=0, INFO=0, SKIP=0))
                continue
            kind = line.split(' ', 1)[0]
            if current is not None and kind in current:
                current[kind] += 1
        if summary:
            counts = 'pass=%s fail=%s info=%s skip=%s' % summary.groups()
            passed = summary.group(2) == '0'
        else:
            counts, passed = 'no SUMMARY line', False
        detail = counts + '; ' + ', '.join(
            f'{name} pass={c["PASS"]} fail={c["FAIL"]} info={c["INFO"]} skip={c["SKIP"]}'
            for name, c in scenarios.items())
        settings = ''.join(f', {e}' for e in options.env)
        env = ''.join(f'{e} ' for e in options.env)
        entries.append(dict(scope=f'server-probe {options.scenarios}{settings}', kmip=version,
                            command=f'{env}tools/server-probe/run.sh --scenarios '
                                    f'{options.scenarios} --versions {version}',
                            result='PASS' if passed else 'FAIL', detail=detail,
                            **identity(options)))
    if not entries:
        raise SystemExit(f'{work}: no v*/probe.log')
    return entries


# What the suite must refuse, and only that, with the minimal setup (a bare server: no trust
# anchor, no users file): the check's name to why (integration/keytend-kmip-server/README.md,
# "Limits"). Validate, at every version (the 1.x suite validates the server's chain, 2.0 and
# later an independent CA certificate) and, for the 3.0 draft's credentials, at 3.0.
VALIDATE_REFUSAL = 'Validate fails without a trust anchor'
MINIMAL_REFUSALS = {'Validate certificate': VALIDATE_REFUSAL,
                    'Validate independent CA certificate': VALIDATE_REFUSAL}
MINIMAL_REFUSALS_3_0 = {
    'Login and Logout ticket': 'Login',
    'CreateCredential password': 'Create Credential',
    'CreateUser': 'Create User',
    'CreateGroup and Obliterate': 'Create Group',
}


def minimal_refusals(version):
    validate = 'Validate certificate' if version.startswith('1.') else \
        'Validate independent CA certificate'
    expected = {validate: MINIMAL_REFUSALS[validate]}
    if version == '3.0':
        expected.update(MINIMAL_REFUSALS_3_0)
    return expected


def interop_entries(log, options):
    """One entry per program and version of run-interop.sh's output ("KMIP V PROGRAM exit=N",
    and the purpose program's "(N of M shapes agree)"). With the minimal setup, the suite passes
    when it fails exactly the checks it must (minimal_refusals), read from its output in WORK
    (WORK/suite/v<version>/out.log)."""
    entries = []
    pattern = re.compile(r'^KMIP (\d\.\d) (\w+) exit=(\d+)(?: \((.*)\))?$', re.M)
    for version, program, code, note in pattern.findall(Path(log).read_text(encoding='utf-8')):
        detail = f'exit {code}' + (f', {note}' if note else '')
        passed = code == '0'
        if options.setup == 'minimal':
            if not options.work:
                raise SystemExit('the minimal setup needs --work, the run\'s work directory')
            out = Path(options.work) / program / f'v{version}' / 'out.log'
            text = out.read_text(encoding='utf-8', errors='replace') if out.is_file() else ''
            failed = set(re.findall(r'^\S+ ' + re.escape(version) + r' FAIL (.+?): ', text, re.M))
            checks = len(re.findall(r'^\S+ ' + re.escape(version) + r' (?:PASS|FAIL) ', text,
                                    re.M))
            expected = minimal_refusals(version)
            passed = bool(text) and failed == set(expected)
            refused = [why for name, why in expected.items() if name in MINIMAL_REFUSALS]
            credentials = [why for name, why in expected.items() if name in MINIMAL_REFUSALS_3_0]
            if credentials:
                refused.append(', '.join(credentials[:-1]) + ' and ' + credentials[-1]
                               + ' are refused without the header credential')
            detail += f'; {checks - len(failed)} of {checks} checks passed'
            if passed:
                detail += '; only the expected refusals: ' + '; '.join(refused)
            else:
                unexpected = sorted(failed - set(expected))
                missing = sorted(set(expected) - failed)
                if unexpected:
                    detail += '; unexpected failures: ' + ', '.join(unexpected)
                if missing:
                    detail += '; expected refusals missing: ' + ', '.join(missing)
                if not text:
                    detail += f'; no output ({out})'
        entries.append(dict(scope=f'interop {options.setup} {program}', kmip=version,
                            command=f'integration/keytend-kmip-server/run-interop.sh --setup '
                                    f'{options.setup} --programs {program} --versions {version}',
                            result='PASS' if passed else 'FAIL', detail=detail,
                            **identity(options)))
    if not entries:
        raise SystemExit(f'{log}: no "KMIP V PROGRAM exit=N" line')
    return entries


def bench_entries(work, options):
    """One "bench smoke" entry per version of the benchmark's live run in WORK
    (live-v<version>/bench.log): it passed when the run printed its table of rows and no scenario
    failed. A smoke run measures nothing: its figures are not results."""
    entries = []
    for log in sorted(Path(work).glob('live-v*/bench.log')):
        version = log.parent.name[len('live-v'):]
        text = log.read_text(encoding='utf-8', errors='replace')
        scenarios, failed, current, table, rows = [], set(), None, False, 0
        for line in text.splitlines():
            heading = re.match(r'^## (\S+)   \(load ', line)
            if heading:
                current = heading.group(1)
                scenarios.append(current)
            elif line == f'## all rows (live, KMIP {version})':
                table = True
            elif line.startswith('SCENARIO FAILED: '):
                failed.add(current or '?')
            elif table and line.startswith('| ') and not line.startswith('| scenario |'):
                rows += 1
        failed = sorted(failed)
        passed = bool(table) and not failed and rows > 0
        detail = (f'{len(scenarios)} scenarios, {rows} rows at --scale {options.scale}; '
                  'a smoke run, its figures are not results')
        if failed:
            detail += '; failed: ' + ', '.join(failed)
        if not table:
            detail += '; the run did not finish (no table of rows)'
        entries.append(dict(scope='bench smoke', kmip=version,
                            command=f'tools/bench/run.sh --topologies live --versions {version} '
                                    f'--scale {options.scale}',
                            result='PASS' if passed else 'FAIL', detail=detail,
                            **identity(options)))
    if not entries:
        raise SystemExit(f'{work}: no live-v*/bench.log')
    return entries


def cassandra_entries(trials, options):
    """One "cassandra-trunk-tde dtest" entry per KMIP version of the Cassandra trunk runs, from
    each run-trial.sh output directory (PROVENANCE.txt and SUMMARY.txt): it passed when every
    suite of every run passed, the dtest included, each on the pinned image."""
    by_version, runs, passed = {}, [], True
    for trial in trials:
        provenance = (Path(trial) / 'PROVENANCE.txt').read_text(encoding='utf-8')
        summary = (Path(trial) / 'SUMMARY.txt').read_text(encoding='utf-8')
        server = re.search(r'^server_image=\S+ id=(\S+) (\S+) version=(.*?) kmip=(\S+) '
                           r'lease_states=(\S+)$', provenance, re.M)
        head = re.search(r'^cassandra=\S+ head=([0-9a-f]{7})', provenance, re.M)
        if not server or not head:
            raise SystemExit(f'{trial}/PROVENANCE.txt: no server_image or cassandra line')
        if server.group(1) != options.image or server.group(2) != 'pinned':
            raise SystemExit(f'{trial}: ran on image {server.group(1)} ({server.group(2)}), '
                             f'not {options.image}')
        # run-trial.sh without LEASE_STATES runs the server's default, active-deactivated.
        leases = 'active-deactivated' if server.group(5) == 'default' else server.group(5)
        suites = re.findall(r'^(\S+) exit=(\d+) (.*)$', summary, re.M)
        dtest = [s for s in suites if s[0].endswith('.KmipTdeRotationTest')]
        failed = [s[0].rsplit('.', 1)[-1] for s in suites if s[1] != '0']
        passed = passed and bool(dtest) and not failed and 'NOT-APPLIED' not in provenance
        runs.append(f'--lease-states {leases}: {len(suites) - len(dtest)} suites and '
                    f'the dtest ({dtest[0][2] if dtest else "not run"})'
                    + (f', failed {", ".join(failed)}' if failed else ''))
        for version in server.group(4).split(','):
            by_version.setdefault(version, []).append(leases)
        trunk = head.group(1)
    if not runs:
        raise SystemExit('no run-trial.sh output')
    patches = len(list((ROOT / 'integration/cassandra-trunk-tde/patches').glob('000*.patch')))
    entries = []
    for version, leases in sorted(by_version.items()):
        entries.append(dict(scope='cassandra-trunk-tde dtest', kmip=version,
                            command='integration/cassandra-trunk-tde/run-trial.sh, '
                                    f'KMIP {version}, under --lease-states '
                                    + ' and '.join(leases),
                            result='PASS' if passed and len(leases) == len(runs) else 'FAIL',
                            detail=f'Apache Cassandra trunk {trunk} with the {patches} patches; '
                                   'a KMS replica and its standby. ' + '; '.join(runs),
                            **identity(options)))
    return entries


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest='action', required=True)
    commands.add_parser('check')

    def run_options(sub):
        sub.add_argument('--server', required=True,
                         help='the server build, such as "keytend-kmip-server X.Y.Z"')
        sub.add_argument('--image', default='', help='the image ID')
        sub.add_argument('--pinned', choices=['yes', 'no'], default='yes')
        sub.add_argument('--jdk', required=True)
        sub.add_argument('--date', help='YYYY-MM-DD (default today)')
        sub.add_argument('--source', default='release check')

    one = commands.add_parser('set')
    one.add_argument('file', type=Path)
    one.add_argument('--scope', required=True)
    one.add_argument('--kmip', action='append', required=True)
    one.add_argument('--command', required=True)
    one.add_argument('--result', choices=RESULTS, required=True)
    one.add_argument('--detail', required=True)
    run_options(one)
    probe = commands.add_parser('probe')
    probe.add_argument('file', type=Path)
    probe.add_argument('work', type=Path)
    probe.add_argument('--scenarios', default='all')
    probe.add_argument('--env', action='append', default=[],
                       help='a KMIP_* setting of the server, such as KMIP_LEASE_STATES=active')
    run_options(probe)
    interop = commands.add_parser('interop')
    interop.add_argument('file', type=Path)
    interop.add_argument('log', type=Path)
    interop.add_argument('--setup', default='configured')
    interop.add_argument('--work', type=Path, help="the run's work directory (minimal setup)")
    run_options(interop)
    bench = commands.add_parser('bench')
    bench.add_argument('file', type=Path)
    bench.add_argument('work', type=Path)
    bench.add_argument('--scale', required=True)
    run_options(bench)
    cassandra = commands.add_parser('cassandra')
    cassandra.add_argument('file', type=Path)
    cassandra.add_argument('trials', type=Path, nargs='+')
    run_options(cassandra)
    pinned = commands.add_parser('pinned')
    pinned.add_argument('recorded', type=Path)
    pinned.add_argument('--run', type=Path)
    pinned.add_argument('--pin', type=Path, default=PIN)
    complete = commands.add_parser('complete')
    complete.add_argument('file', type=Path)
    complete.add_argument('--pin', type=Path, default=PIN)
    run = commands.add_parser('run')
    run.add_argument('reports', type=Path, help="the run directory's validation/")
    run.add_argument('--commit', help='default: HEAD')
    run.add_argument('--version', help="default: the POM's")
    run.add_argument('--in-release-check', action='store_true')
    run.add_argument('--recorded', type=Path, help='default: validation/recorded/' + LIVE)
    guard = commands.add_parser('guard')
    guard.add_argument('reports', type=Path)
    scrubbed = commands.add_parser('scrub')
    scrubbed.add_argument('source', type=Path)
    scrubbed.add_argument('dest', type=Path)
    scrubbed.add_argument('--replace', action='append', default=[], metavar='OLD=NEW')
    merged = commands.add_parser('merge')
    merged.add_argument('recorded', type=Path)
    merged.add_argument('run', type=Path)
    merged.add_argument('out', type=Path)
    options = parser.parse_args()
    if options.action == 'check':
        files = check_recorded()
        print(f'validation/recorded: {len(files)} files listed with their dates and servers; '
              f'{len(load(RECORDED / LIVE))} recorded live results')
    elif options.action in ('set', 'probe', 'interop', 'bench', 'cassandra'):
        if options.action == 'set':
            new = [dict(scope=options.scope, kmip=version, command=options.command,
                        result=options.result, detail=options.detail, **identity(options))
                   for version in options.kmip]
        elif options.action == 'probe':
            new = probe_entries(options.work, options)
        elif options.action == 'interop':
            new = interop_entries(options.log, options)
        elif options.action == 'bench':
            new = bench_entries(options.work, options)
        else:
            new = cassandra_entries(options.trials, options)
        replace(options.file, new)
        for entry in new:
            print(f'{entry["result"]} {entry["scope"]} {entry["kmip"]}: {entry["detail"]}')
        # 3: written, but a result is FAIL (an error exits 1 or 2 and writes nothing).
        if options.action != 'set' and any(e['result'] != 'PASS' for e in new):
            return 3
    elif options.action == 'pinned':
        entries = merge(load(options.recorded), load(options.run) if options.run else [])
        pin = read_pin(options.pin)
        check_pinned(entries, pin, LIVE)
        print(f'{LIVE}: {len(entries)} entries, every one of the pinned {pin["name"]} '
              f'{pin["version"]}')
    elif options.action == 'complete':
        problems = run_problems(load(options.file), read_pin(options.pin), LIVE)
        if problems:
            raise SystemExit('REFUSED: a release ships the live results of its own release check '
                             'run\n' + '\n'.join('  ' + p for p in problems))
        count = sum(len(v) for v in RELEASE_CHECK_SCOPES.values())
        print(f'{LIVE}: this run passed all {count} live results the release check runs')
    elif options.action == 'run':
        import subprocess
        import xml.etree.ElementTree as ET
        commit = options.commit or subprocess.run(
            ['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], capture_output=True, text=True,
            check=True).stdout.strip()
        version = options.version or ET.parse(ROOT / 'pom.xml').getroot().findtext(
            '{http://maven.apache.org/POM/4.0.0}version')
        check_run(options.reports, commit, version, options.in_release_check, options.recorded)
        print(f'{options.reports}: a full release check of {commit} that passed')
    elif options.action == 'guard':
        check_reports(reports_of(options.reports), str(options.reports))
        print(f'{options.reports}: no test output and no local path')
    elif options.action == 'scrub':
        replacements = [tuple(r.split('=', 1)) for r in options.replace]
        scrub(options.source, options.dest, replacements)
    else:
        dump(options.out, merge(load(options.recorded), load(options.run)))


if __name__ == '__main__':
    sys.exit(main())
