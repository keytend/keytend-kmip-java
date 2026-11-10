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

"""Fetch original, unmodified OASIS vectors and SHA-256 provenance manifest.
Requires beautifulsoup4; ordinary SDK builds use the checked-in fixtures offline.
"""
from pathlib import Path
import concurrent.futures, hashlib, json, urllib.request
from bs4 import BeautifulSoup
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'sdk/src/test/resources/oasis'
urls={}
for v in range(1,5):
 for kind in ['mandatory','optional']:
  u=f'https://docs.oasis-open.org/kmip/profiles/v1.{v}/os/test-cases/kmip-v1.{v}/{kind}/'
  try:
   s=BeautifulSoup(urllib.request.urlopen(u).read(),'html.parser')
   for a in s.find_all('a'):
    f=a.get('href','')
    if f.endswith('.xml') and '/' not in f: urls[f'1.{v}/{kind}/{f}']=u+f
  except Exception as e: print(u,e)
u='https://docs.oasis-open.org/kmip/testcases/v1.4/cn01/test-cases/kmip-v1.4/'
s=BeautifulSoup(urllib.request.urlopen(u).read(),'html.parser')
for a in s.find_all('a'):
 f=a.get('href','')
 if f.endswith('.xml') and '/' not in f:urls['1.4/testcases/'+f]=u+f

def fetch(it):
 name,url=it; p=OUT/name; p.parent.mkdir(parents=True,exist_ok=True)
 if not p.exists():p.write_bytes(urllib.request.urlopen(url).read())
 return {'file':name,'url':url,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex: entries=list(ex.map(fetch,urls.items()))
(OUT/'manifest.json').write_text(json.dumps(entries,indent=2)+'\n')
print('Fetched',len(entries),'original OASIS files')
# Modern profiles ship their authoritative test cases in ZIP archives.
import zipfile,io
for version,stage in [('2.0','os'),('2.1','os'),('3.0','csd02')]:
    url=f'https://docs.oasis-open.org/kmip/kmip-profiles/v{version}/{stage}/kmip-profiles-v{version}-{stage}.zip'
    try: archive=zipfile.ZipFile(io.BytesIO(urllib.request.urlopen(url).read()))
    except Exception as e: print(url,e);continue
    for name in archive.namelist():
        if not name.endswith('.xml') or 'test-cases/' not in name:continue
        # Some bundles contain copies of old versions; retain their archive paths.
        relative=f'{version}/archive/{name}'
        p=OUT/relative;p.parent.mkdir(parents=True,exist_ok=True);data=archive.read(name);p.write_bytes(data)
        entries.append({'file':relative,'url':url+'#'+name,'sha256':hashlib.sha256(data).hexdigest()})
(OUT/'manifest.json').write_text(json.dumps(entries,indent=2)+'\n')
print('Total original OASIS files:',len(entries))
