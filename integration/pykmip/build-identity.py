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
"""The content identity of a PyKMIP server build, read inside its running container.

    python -I -c "$(cat build-identity.py)" [--list]

The tests run this in the container (KmsSamplesIT.identity); it is not part of the image. It
lists the Python version, the installed distributions and, for every file pip installed (under
/usr/local/lib*/python3.12/site-packages, without bytecode and dist-info metadata), its path and
SHA-256, one per line, sorted. It prints the SHA-256 of that list, or with --list the list itself
(integration/catalog/pykmip-files.txt records the diagnosed build's).

File times and the layers they produce differ on every build; the content does not, so a build of
the pinned Dockerfile on any machine has the same identity.
"""
import hashlib
import os
import sys

ROOTS = ('/usr/local/lib64/python3.12/site-packages', '/usr/local/lib/python3.12/site-packages')


def listing():
    files, dists = [], []
    for root in ROOTS:
        if not os.path.isdir(root):
            continue
        dists += [d[:-len('.dist-info')] for d in os.listdir(root) if d.endswith('.dist-info')]
        for directory, subdirectories, names in os.walk(root):
            subdirectories[:] = [d for d in subdirectories if d != '__pycache__' and not d.endswith('.dist-info')]
            for name in names:
                if name.endswith('.pyc'):
                    continue
                path = os.path.join(directory, name)
                with open(path, 'rb') as f:
                    files.append(f'{os.path.relpath(path, root)}  {hashlib.sha256(f.read()).hexdigest()}')
    lines = [f'python {sys.version.split()[0]}'] + [f'dist {d}' for d in sorted(dists)] + sorted(files)
    return ''.join(line + '\n' for line in lines)


if __name__ == '__main__':
    text = listing()
    sys.stdout.write(text if sys.argv[1:] == ['--list'] else hashlib.sha256(text.encode()).hexdigest() + '\n')
