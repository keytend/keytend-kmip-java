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

"""Derive the Java runner's registry from the Keytend interoperability catalog."""
import hashlib
import json
from pathlib import Path
root = Path(__file__).resolve().parent.parent
source = root / 'integration/catalog/catalog.json'
data = json.loads(source.read_text())
cases = data['cases']
assert len(cases) == data['test_count']
assert len({case['id'] for case in cases}) == len(cases)
output = root / 'integration-tests/src/main/resources/dev/keytend/kmip/catalog'
output.mkdir(parents=True, exist_ok=True)
lines = []
for case in cases:
    columns = [case['id'], case['family'], case['title'], case['layer'],
               case['priority'], ','.join(case['server_ids'])]
    assert not any('\t' in cell or '\n' in cell for cell in columns)
    lines.append('\t'.join(columns))
(output / 'cases.tsv').write_text('\n'.join(lines) + '\n')
(output / 'source.sha256').write_text(hashlib.sha256(source.read_bytes()).hexdigest() + '\n')
print(f'Registered all {len(cases)} catalog case identities')
