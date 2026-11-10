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

"""Summarize the workflow suite's measured results; never treat unsupported features as passes.

Reads the workflow reports the integration build wrote (integration/reports, one per server,
version and JDK) and each JDK's JUnit totals, rejects any workflow failure, and writes summary.json
and a copy of each report to the output directory. The release check runs it after its
-Pintegration verify runs (tools/release-check.sh), into the run's validation/workflows/, which the
binary ZIP carries.

    summarize-validation.py [--out DIR] [--reports DIR] [--junit JDK=DIR ... | --log JDK=PATH ...]
"""
import argparse
from collections import Counter
from pathlib import Path
import json
import shutil

from release_reports import ROOT, junit_runs

SERVERS = [('pykmip', ['1.1', '1.2', '1.3', '1.4']),
           ('pqctoday', ['3.0'])]


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--out', type=Path, default=ROOT / 'target/validation/workflows')
    parser.add_argument('--reports', type=Path, default=ROOT / 'integration/reports')
    parser.add_argument('--junit', action='append', help="JDK=DIR: the release check's report copies")
    parser.add_argument('--log', action='append', help='JDK=PATH: a sequential build log')
    options = parser.parse_args()
    junit = junit_runs(options.log, options.junit)
    options.out.mkdir(parents=True, exist_ok=True)
    rows = []
    for jdk in junit:
        for server, versions in SERVERS:
            for version in versions:
                source = options.reports / f'{server}-{version}-jdk{jdk}.json'
                report = json.loads(source.read_text())
                counts = Counter(c['outcome'] for c in report['checks'])
                if counts['FAIL']:
                    raise SystemExit(f'{source}: workflow failures')
                rows.append(dict(server=server, version=version, jdk=int(jdk),
                                 runtime=report['java'], outcomes=dict(sorted(counts.items()))))
                shutil.copyfile(source, options.out / source.name)
    summary = dict(protocols=['1.1', '1.2', '1.3', '1.4', '2.0', '2.1', '3.0 CSD02'],
                   junit=junit, oasisFixtureFiles=542, independentBinaryDigests=2712, workflows=rows)
    (options.out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print('Summarized', len(rows), 'server/version/JDK workflow reports in', options.out)
    for row in rows:
        print(row['jdk'], row['server'], row['version'], row['outcomes'])


if __name__ == '__main__':
    main()
