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
"""Upload a Central bundle to the Central Portal and publish or drop it (docs/releasing.md, step 3).

    tools/central-upload.py BUNDLE --name NAME (--publish | --drop) [--timeout SECONDS]

BUNDLE is the central-bundle.zip that `./mvnw -Pdistribution,central deploy -DskipUpload=true`
wrote, after tools/central-bundle.py checked it. The bundle is uploaded as is, for the user to
publish (publishingType USER_MANAGED), and the Portal validates it. Once it is VALIDATED:

    --publish  publishes it, and waits until it is PUBLISHED. A version published on Maven
               Central can never be changed or removed. Only a release X.Y.Z is published: a
               bundle with another version (a pre-release X.Y.Z-rc.N) is refused before upload.
    --drop     drops it: nothing is published. This tries the Portal's validation (signatures,
               POMs, sources and Javadoc JARs) without releasing anything.

The Portal user token comes from CENTRAL_TOKEN_USERNAME and CENTRAL_TOKEN_PASSWORD, or else from
the server "central" of ~/.m2/settings.xml. It is sent only to the Portal. KEYTEND_CENTRAL_URL
names another Portal (the tests' stub). Exit 0 when the deployment ends as asked, 1 if the Portal
refuses it (its errors are printed) or it is not done within --timeout seconds (default 3600).
"""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET
import zipfile

PORTAL = os.environ.get('KEYTEND_CENTRAL_URL') or 'https://central.sonatype.com'
POLL_SECONDS = float(os.environ.get('KEYTEND_CENTRAL_POLL_SECONDS') or 10)


def versions(bundle):
    """The versions of the bundle's POMs: each is at group/artifact/version/artifact-version.pom."""
    with zipfile.ZipFile(bundle) as z:
        return {n.split('/')[-2] for n in z.namelist() if n.endswith('.pom') and n.count('/') >= 3}


def token():
    user, password = os.environ.get('CENTRAL_TOKEN_USERNAME'), os.environ.get('CENTRAL_TOKEN_PASSWORD')
    if not (user and password):
        settings = Path.home() / '.m2' / 'settings.xml'
        if settings.is_file():
            root = ET.parse(settings).getroot()
            ns = {'s': root.tag[1:].split('}')[0]} if root.tag.startswith('{') else {}
            p = 's:' if ns else ''
            for server in root.iterfind(f'{p}servers/{p}server', ns):
                if server.findtext(f'{p}id', namespaces=ns) == 'central':
                    user = server.findtext(f'{p}username', namespaces=ns)
                    password = server.findtext(f'{p}password', namespaces=ns)
    if not (user and password):
        raise SystemExit('REFUSED: no Portal user token: set CENTRAL_TOKEN_USERNAME and CENTRAL_TOKEN_PASSWORD, '
                         'or the server "central" in ~/.m2/settings.xml')
    return base64.b64encode(f'{user}:{password}'.encode()).decode()


def call(method, path, auth, body=None, content_type=None):
    request = urllib.request.Request(PORTAL + path, data=body, method=method,
                                     headers={'Authorization': 'Bearer ' + auth})
    if content_type:
        request.add_header('Content-Type', content_type)
    try:
        with urllib.request.urlopen(request, timeout=300) as response:
            return response.status, response.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', 'replace')
    except (urllib.error.URLError, OSError) as e:
        raise SystemExit(f'FAILED: {method} {PORTAL}{path.split("?")[0]}: {e}')


def upload(bundle, name, auth):
    boundary = uuid.uuid4().hex
    body = b''.join([
        f'--{boundary}\r\n'.encode(),
        f'Content-Disposition: form-data; name="bundle"; filename="{bundle.name}"\r\n'.encode(),
        b'Content-Type: application/octet-stream\r\n\r\n',
        bundle.read_bytes(),
        f'\r\n--{boundary}--\r\n'.encode(),
    ])
    query = urllib.parse.urlencode({'name': name, 'publishingType': 'USER_MANAGED'})
    status, text = call('POST', '/api/v1/publisher/upload?' + query, auth, body,
                        f'multipart/form-data; boundary={boundary}')
    deployment = text.strip()
    if status not in (200, 201) or not re.fullmatch(r'[0-9A-Za-z-]+', deployment):
        raise SystemExit(f'FAILED: the upload was refused (HTTP {status}): {text.strip()}')
    return deployment


def state(deployment, auth):
    status, text = call('POST', '/api/v1/publisher/status?' + urllib.parse.urlencode({'id': deployment}), auth)
    if status != 200:
        raise SystemExit(f'FAILED: no status of deployment {deployment} (HTTP {status}): {text.strip()}')
    return json.loads(text)


def wait(deployment, auth, until, deadline):
    last = None
    while True:
        current = state(deployment, auth)
        now = current.get('deploymentState')
        if now != last:
            print(f'deployment {deployment}: {now}', flush=True)
            last = now
        if now == 'FAILED':
            print(json.dumps(current.get('errors'), indent=2), file=sys.stderr)
            raise SystemExit(f'FAILED: the Portal refused deployment {deployment}')
        if now in until:
            return current
        if time.monotonic() > deadline:
            raise SystemExit(f'FAILED: deployment {deployment} is still {now} after the timeout')
        time.sleep(POLL_SECONDS)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('bundle', type=Path)
    parser.add_argument('--name', required=True, help='the deployment name the Portal shows')
    then = parser.add_mutually_exclusive_group(required=True)
    then.add_argument('--publish', action='store_true', help='publish the validated deployment')
    then.add_argument('--drop', action='store_true', help='drop the validated deployment')
    parser.add_argument('--timeout', type=float, default=3600)
    options = parser.parse_args()
    if not options.bundle.is_file():
        raise SystemExit(f'REFUSED: no bundle {options.bundle}')
    found = versions(options.bundle)
    if not found:
        raise SystemExit(f'REFUSED: {options.bundle} holds no POM')
    if options.publish and not all(re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', v) for v in found):
        raise SystemExit(f'REFUSED: only a release X.Y.Z goes to Maven Central, and the bundle is of '
                         f'{", ".join(sorted(found))} (--drop validates it without publishing)')
    auth = token()
    deadline = time.monotonic() + options.timeout
    deployment = upload(options.bundle, options.name, auth)
    print(f'uploaded {options.bundle.name} as deployment {deployment} ({options.name})', flush=True)
    validated = wait(deployment, auth, {'VALIDATED'}, deadline)
    if options.drop:
        status, text = call('DELETE', f'/api/v1/publisher/deployment/{deployment}', auth)
        if status not in (200, 204):
            raise SystemExit(f'FAILED: deployment {deployment} was not dropped (HTTP {status}): {text.strip()}')
        print(f'dropped deployment {deployment}: validated, nothing published')
        return 0
    status, text = call('POST', f'/api/v1/publisher/deployment/{deployment}', auth)
    if status not in (200, 204):
        raise SystemExit(f'FAILED: deployment {deployment} was not published (HTTP {status}): {text.strip()}')
    published = wait(deployment, auth, {'PUBLISHED'}, deadline)
    for purl in published.get('purls') or validated.get('purls') or []:
        print('published', purl)
    return 0


if __name__ == '__main__':
    sys.exit(main())
