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

set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
./mvnw -q -pl sdk -am -DskipTests package
java -cp sdk/target/classes tools/ExportCanonical.java
(cd tools/oracle && go run . ../../.cache/canonical.xml > ../../.cache/oracle-lines.txt)
python3 - <<'PY'
from pathlib import Path
import base64,hashlib
lines=Path('.cache/oracle-lines.txt').read_text().splitlines()
index=Path('.cache/canonical-index.tsv').read_text().splitlines()
assert len(lines)==len(index)
header='# Independently encoded by github.com/ovh/kmip-go v0.9.2; canonical numeric XML from original OASIS 1.x fixture files.\n'
Path('sdk/src/test/resources/oracle.tsv').write_text(header+'\n'.join(i+'\t'+hashlib.sha256(base64.b64decode(b)).hexdigest() for i,b in zip(index,lines))+'\n')
print('Generated',len(lines),'independent binary message digests')
PY
