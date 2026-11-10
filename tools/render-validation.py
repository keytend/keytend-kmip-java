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

"""Render the workflow suite's summary (summarize-validation.py) as a self-contained HTML report.

    render-validation.py [--dir DIR]    reads DIR/summary.json, writes DIR/overview.html
"""
import argparse
import json
from pathlib import Path

from license_headers import licensed_html

parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument('--dir', type=Path, default=Path(__file__).resolve().parents[1] / 'target/validation/workflows')
directory = parser.parse_args().dir
data = json.loads((directory / 'summary.json').read_text())
jdks = list(data['junit'])
tests = {jdk: sum(run for runs in modules.values() for run, _ in runs) for jdk, modules in data['junit'].items()}
html='''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>KMIP validation</title><style>
body{font-family:var(--font-sans,system-ui);color:var(--foreground,#18242b);line-height:1.45;margin:0}h2{font-size:21px;margin:0 0 10px}p{margin:8px 0 16px;color:var(--muted-foreground,#52606d)}.metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:18px 0}.metric{background:var(--muted,#f1f5f7);border-radius:var(--radius,8px);padding:16px}.metric b{display:block;font-size:24px}.metric small{color:var(--muted-foreground,#52606d)}label{font-weight:600}select{font:inherit;background:var(--card,#fff);color:inherit;border:1px solid var(--border,#ccd6dd);border-radius:6px;padding:6px 12px;margin-left:10px}table{width:100%;border-collapse:collapse;margin:16px 0;font-size:14px}th,td{text-align:left;padding:9px 5px;border-bottom:1px solid var(--border,#dce3e8)}th{color:var(--muted-foreground,#52606d);font-size:12px;font-weight:600}td:nth-child(n+3),th:nth-child(n+3){text-align:right}.ok{color:var(--success,#18794e);font-weight:650}.draft{font-size:11px;color:var(--warning,#987500)}.notes{background:var(--muted,#f1f5f7);padding:16px;border-radius:var(--radius,8px);font-size:13px}ul{padding-left:20px;margin:6px 0}.footer{font-size:12px;margin-top:12px}@media(max-width:480px){th,td{padding:9px 3px;font-size:12px}.metric{padding:12px}.metric b{font-size:21px}.metric small{font-size:11px}}
</style></head><body><h2>KMIP client validation</h2><p>Protocols 1.1–1.4, 2.0, 2.1 and 3.0 CSD02. The integration builds on JDK JDKS passed.</p><div class="metrics"><div class="metric"><b>66</b><small>operation codes exposed</small></div><div class="metric"><b>542</b><small>OASIS fixture files</small></div><div class="metric"><b>2,712</b><small>independent wire digests</small></div></div><label for="jdk">Runtime results</label><select id="jdk">OPTIONS</select><p class="footer">Tests run per JDK: TESTS.</p><table><thead><tr><th>Server</th><th>KMIP</th><th>Pass</th><th>Peer limits*</th><th>Failures</th></tr></thead><tbody id="rows"></tbody></table><div class="notes"><b>Measured coverage, with limits visible</b><ul><li>PyKMIP and PQCToday are open source.</li><li>*Peer limits combine unsupported features and identified server limitations. Version exclusions, callbacks and unexercised paths remain separate in the JSON reports.</li><li>3.0 is a pinned draft. PQCToday CA ownership limits issuance tests.</li><li>OASIS scenario replay is a separate audit with recorded mismatches; these passing builds do not certify complete server profiles.</li></ul></div><p class="footer">Full results: summary.json and the workflow reports beside this page. Reproduce with ./integration/run.sh and ./tools/verify-jdks.sh -Pintegration.</p><script>
const data=DATA;
function update(){const j=Number(document.querySelector('#jdk').value);document.querySelector('#rows').innerHTML=data.workflows.filter(r=>r.jdk===j).map(r=>`<tr><td>${r.server==='pqctoday'?'PQCToday':'PyKMIP'}</td><td>${r.version}${r.version==='3.0'?' <span class="draft">draft</span>':''}</td><td class="ok">${r.outcomes.PASS||0}</td><td>${(r.outcomes.UNSUPPORTED||0)+(r.outcomes.SERVER_LIMITATION||0)}</td><td>${r.outcomes.FAIL||0}</td></tr>`).join('')}
document.querySelector('#jdk').addEventListener('change',update);update();
</script></body></html>'''.replace(
    'JDKS', ', '.join(jdks)).replace('OPTIONS', ''.join(f'<option>{j}</option>' for j in jdks)).replace(
    'TESTS', '; '.join(f'JDK {j}: {n:,}' for j, n in tests.items())).replace('DATA', json.dumps(data))
(directory / 'overview.html').write_text(licensed_html(html))
