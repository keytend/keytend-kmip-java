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
"""Check a Central bundle against a release's SHA256SUMS (docs/releasing.md, step 3).

    tools/central-bundle.py TREE SHA256SUMS

TREE is a checkout after `./mvnw -Pdistribution,central deploy -DskipUpload=true`, which wrote
TREE/target/central-publishing/central-bundle.zip. SHA256SUMS is the release's: the one
tools/package-release.py wrote, or the one the GitHub release publishes.

Every JAR of the bundle must be the one in its module's target/; every one SHA256SUMS lists must
have the SHA-256 it lists; and every JAR of the published modules that SHA256SUMS lists must be in
the bundle. So Central gets the bytes of the GitHub release (SECURITY.md). Exit 0 if all hold and
at least one JAR was compared, 1 otherwise. The last line printed sums it up.
"""
import glob
import hashlib
import os
import sys
import zipfile


def sha(content):
    return hashlib.sha256(content).hexdigest()


def main():
    if len(sys.argv) != 3:
        print(__doc__.strip().split('\n\n')[1], file=sys.stderr)
        return 2
    tree, sums = sys.argv[1], sys.argv[2]
    listed = {}
    for line in open(sums, encoding='utf-8'):
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
    print(f"{compared} of the bundle's {len(jars)} JARs are in SHA256SUMS, " + (
        'every one with its hash' if not failed else f'{len(failed)} failures'))
    return 1 if failed or not compared else 0


if __name__ == '__main__':
    sys.exit(main())
