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

"""Validate and summarize the pairwise interoperability catalog's measured results.

Reads the catalog reports the integration build wrote (integration/reports/catalog: each live
tuple and the controlled peers, per JDK) and each JDK's JUnit totals, rejects any client failure,
and writes to the output directory summary.json, cases.csv (one row per
record) and results/ (each report, gzipped). The release check runs it after its -Pintegration
verify runs (tools/release-check.sh), into the run's validation/catalog/, which the binary ZIP
carries; render-catalog.py adds the HTML reports.

    summarize-catalog.py [--out DIR] [--reports DIR] [--junit JDK=DIR ... | --log JDK=PATH ...]
"""
import argparse
from collections import Counter
from pathlib import Path
import csv
import gzip
import hashlib
import json

from release_reports import ROOT, junit_runs

parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument('--out', type=Path, default=ROOT / 'target/validation/catalog')
parser.add_argument('--reports', type=Path, default=ROOT / 'integration/reports/catalog')
parser.add_argument('--junit', action='append', help="JDK=DIR: the release check's report copies")
parser.add_argument('--log', action='append', help='JDK=PATH: a sequential build log')
options = parser.parse_args()
DEST = options.out
RESULTS = DEST / 'results'
RESULTS.mkdir(parents=True, exist_ok=True)
catalog = json.loads((ROOT / 'integration/catalog/catalog.json').read_text())
cases = catalog['cases']
ids = [c['id'] for c in cases]
assert len(ids) == len(set(ids)) == catalog['test_count']
legacy = ['1.1', '1.2', '1.3', '1.4']
full = {'pykmip': legacy + ['2.0'], 'pqctoday': ['3.0'], 'krypton': ['1.4']}
states = ['PASS', 'FAIL_CLIENT', 'FAIL_SERVER', 'BLOCKED_ENV', 'UNSUPPORTED_SERVER',
          'NOT_APPLICABLE']
layers, reasons, hashes, rows, flat, controlled, tests = [], [], set(), [], [], [], {}
# Native policy adapters define the supporting fixture scope, not product-wide claims.
policy_targets = {
    'AUTH-01': {'pykmip'},
    'AUTH-02': {'pykmip'},
}
policy_runs = {case: [] for case in policy_targets}


def index(values, value):
    if value not in values:
        values.append(value)
    return values.index(value)


def archive(path):
    content = path.read_bytes()
    filename = path.name + '.gz'
    (RESULTS / filename).write_bytes(gzip.compress(content, mtime=0))
    return 'results/' + filename, hashlib.sha256(content).hexdigest()


def validate_records(records, expected_ids, filename):
    actual = [r['test_id'] for r in records]
    assert len(actual) == len(set(actual)), f'{filename}: duplicate cases'
    assert set(actual) == set(expected_ids), f'{filename}: case identity mismatch'
    for r in records:
        assert r['outcome'] in states and r['outcome'] != 'FAIL_CLIENT', f'{filename}: {r}'
        assert all(field in r for field in ['client_commit', 'client_worktree_sha256',
                   'configuration_hash', 'identity_role', 'namespace', 'seed', 'started_at',
                   'duration_ms', 'case_parameters', 'tls_version', 'evidence_refs', 'issue_id'])
        hashes.add(r['client_worktree_sha256'])


tests = junit_runs(options.log, options.junit)
expected_tuples = 0
for jdk in map(int, tests):
    for server, all_versions in full.items():
        versions = all_versions if jdk == 17 else [all_versions[-1]]
        if jdk == 21 and server == 'pykmip':
            versions = ['1.4']
        expected_tuples += len(versions)
        for version in versions:
            path = options.reports / f'{server}-{version}-jdk{jdk}.json'
            report = json.loads(path.read_text())
            records = report['records']
            validate_records(records, ids, path.name)
            for r in records:
                if r['test_id'] in policy_targets:
                    eligible = server in policy_targets[r['test_id']]
                    if eligible:
                        assert r['outcome'] in {'PASS', 'FAIL_SERVER'}, f'{path}: supported policy case did not execute'
                    policy_runs[r['test_id']].append(dict(
                        server=server, version=version, jdk=jdk, outcome=r['outcome'],
                        supporting_fixture=eligible,
                        scope='native policy configured' if eligible else 'outside configured policy fixture scope'))
            performance = next(r for r in records if r['test_id'] == 'JAVA-05')
            parameters = performance['case_parameters']
            latency = dict(outcome=performance['outcome'])
            if performance['outcome'] == 'PASS':
                assert parameters['samples'] == 100, f'{path}: latency sample count'
                assert parameters['p95_budget_ms'] == 1000 and parameters['p99_budget_ms'] == 2000, f'{path}: unapproved local budget'
                assert parameters['p95_get_us'] <= 1000000 and parameters['p99_get_us'] <= 2000000, f'{path}: Get exceeds approved latency budget'
                latency.update(samples=parameters['samples'],
                               p95_ms=parameters['p95_get_us'] / 1000,
                               p99_ms=parameters['p99_get_us'] / 1000,
                               p95_budget_ms=parameters['p95_budget_ms'],
                               p99_budget_ms=parameters['p99_budget_ms'])
            counts = Counter(r['outcome'] for r in records)
            packed = []
            for r in records:
                packed.append([ids.index(r['test_id']), states.index(r['outcome']),
                               index(reasons, r['reason']), index(layers, r['actual_layer']),
                               r['duration_ms']])
                flat.append(dict(jdk=jdk, server=server, version=version, test_id=r['test_id'],
                                 outcome=r['outcome'], layer=r['actual_layer'],
                                 duration_ms=r['duration_ms'], reason=r['reason']))
            evidence, sha256 = archive(path)
            rows.append(dict(jdk=jdk, server=server, version=version,
                             build=report['server_version'], outcomes=dict(counts),
                             qualification=report['qualification'], records=packed,
                             evidence=evidence, sha256=sha256,
                             get_latency=latency,
                             cleanup_remaining=len(report['cleanup']['remaining_run_owned_ids']),
                             demonstrated_by_layer=report['demonstrated_cases_by_layer']))
    path = options.reports / f'controlled-jdk{jdk}.json'
    report = json.loads(path.read_text())
    records = report['records']
    assert len(records) == 47
    validate_records(records, [r['test_id'] for r in records], path.name)
    assert all(r['outcome'] == 'PASS' for r in records)
    evidence, sha256 = archive(path)
    controlled.append(dict(jdk=jdk, passed=len(records), evidence=evidence, sha256=sha256,
                           cases=[r['test_id'] for r in records]))
assert len(rows) == expected_tuples and len(hashes) == 1, f'Matrix/source identity mismatch: {hashes}'
policy_coverage = []
for case, targets in policy_targets.items():
    runs = policy_runs[case]
    supporting = [r for r in runs if r['supporting_fixture']]
    assert {r['server'] for r in supporting} == targets
    assert len(supporting) == sum(t['server'] in targets for t in rows)
    policy_coverage.append(dict(
        test_id=case, coverage='COVERED', supporting_fixtures=sorted(targets),
        executed_tuples=len(supporting), outcomes=dict(Counter(r['outcome'] for r in supporting)),
        runs=runs))
summary = dict(catalog_sha256=hashlib.sha256((ROOT / 'integration/catalog/catalog.json').read_bytes()).hexdigest(),
               client_worktree_sha256=next(iter(hashes)),
               local_fixture_get_budget_ms=dict(p95=1000, p99=2000),
               policy_coverage=policy_coverage,
               policy_coverage_rule='A policy case is covered when executed on every configured supporting fixture and selected runtime/version tuple. Coverage is execution, not a server correctness pass. Other fixture gaps do not block aggregate SDK coverage and do not establish product-wide lack of support.',
               cases=[dict(id=c['id'], title=c['title'], family=c['family'], priority=c['priority']) for c in cases],
               states=states, layers=layers, reasons=reasons, tuples=rows, controlled=controlled,
               junit=tests,
               digest_scope='sha256 fields identify uncompressed JSON evidence bytes',
               blocked_reasons=[dict(reason=reason, count=count) for reason,count in Counter(r['reason'] for r in flat if r['outcome']=='BLOCKED_ENV').most_common()],
               scope='Measured pairwise catalog execution; blocked and unsupported required cases do not qualify a server')
(DEST / 'summary.json').write_text(json.dumps(summary, separators=(',', ':')) + '\n')
with (DEST / 'cases.csv').open('w', newline='') as stream:
    writer = csv.DictWriter(stream, fieldnames=list(flat[0]), lineterminator="\n")
    writer.writeheader()
    writer.writerows(flat)
print(f'Summarized {len(rows)} live tuples / {len(flat)} case records, plus {sum(c["passed"] for c in controlled)} controlled records')
for row in rows:
    print(row['jdk'], row['server'], row['version'], row['outcomes'], 'qualified=', row['qualification']['qualified'])
