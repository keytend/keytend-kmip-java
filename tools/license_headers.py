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

"""Apply or check Apache-2.0 headers on project-authored source documents.

Third-party Maven wrapper files and original OASIS fixtures retain their
original licensing. Generated JSON/TSV results and checksums are data, not code.
The build runs the same check without Python (sdk's LicenseHeadersTest, which
mirrors these rules: change both together).
"""
from pathlib import Path
import argparse

ROOT = Path(__file__).resolve().parents[1]
TEXT = '''Copyright 2026 Jeremiah Jordan

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.'''
JAVA = '/*\n' + '\n'.join(' * ' + line if line else ' *' for line in TEXT.splitlines()) + '\n */\n'
XML = '<!--\n' + TEXT + '\n-->\n'
HASH = '\n'.join('# ' + line if line else '#' for line in TEXT.splitlines()) + '\n'
SLASH = '\n'.join('// ' + line if line else '//' for line in TEXT.splitlines()) + '\n'


def licensed_html(value):
    if value.startswith(XML) or value.lower().startswith('<!doctype html>\n' + XML.lower()):
        return value
    if value.lower().startswith('<!doctype html>'):
        return value[:15] + '\n' + XML + value[15:]
    return XML + value


def source_files():
    for path in sorted(ROOT.rglob('*')):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT)
        if any(part in {'.git', '.cache', '.claude', 'target', '__pycache__'} for part in rel.parts):
            continue
        if str(rel).startswith(('sdk/src/test/resources/', 'integration/certs/', 'integration/reports/')):
            continue
        if path.name in {'LICENSE', 'NOTICE', 'mvnw', 'mvnw.cmd'}:
            continue
        if path.suffix in {'.java', '.py', '.sh', '.go', '.xml', '.yaml', '.yml', '.toml', '.md', '.html', '.svg', '.properties'} or path.name == 'Dockerfile' or path.name in {'go.mod', '.gitignore'}:
            yield path


def add_header(path, value):
    if path.suffix == '.html':
        return licensed_html(value)
    if path.suffix in {'.java', '.go'} or path.name == 'go.mod':
        header = JAVA if path.suffix == '.java' else SLASH
    elif path.suffix in {'.xml', '.svg', '.md'}:
        header = XML
    else:
        header = HASH
    if value.startswith('#!') or value.startswith('<?xml'):
        first, rest = value.split('\n', 1)
        if rest.startswith(header):
            return value
        return first + '\n' + header + '\n' + rest
    if value.startswith(header):
        return value
    return header + '\n' + value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    missing = []
    files = list(source_files())
    for path in files:
        value = path.read_text()
        updated = add_header(path, value)
        if updated != value:
            missing.append(str(path.relative_to(ROOT)))
            if not args.check:
                path.write_text(updated)
    if args.check and missing:
        raise SystemExit('Missing license headers:\n' + '\n'.join(missing))
    print(f'{len(files)} source documents checked; {len(missing)} headers ' + ('missing' if args.check else 'added'))


if __name__ == '__main__':
    main()
