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

"""Generate versioned registries from OASIS normative tables (3.0 pinned to CSD02).
Run with Python 3 + beautifulsoup4 + lxml. See NOTICE for OASIS attribution.
"""
from pathlib import Path
from license_headers import JAVA
from collections import OrderedDict
import json,re,urllib.request
from bs4 import BeautifulSoup
ROOT=Path(__file__).resolve().parents[1];CACHE=ROOT/'.cache/research';CACHE.mkdir(parents=True,exist_ok=True)
OUT=ROOT/'sdk/src/main/java/dev/keytend/kmip/model';RES=ROOT/'sdk/src/main/resources/dev/keytend/kmip'
VERSIONS=['1.1','1.2','1.3','1.4','2.0','2.1','3.0']
URLS={v:(f'https://docs.oasis-open.org/kmip/spec/v{v}/os/kmip-spec-v{v}-os.html' if v.startswith('1.') else f'https://docs.oasis-open.org/kmip/kmip-spec/v{v}/os/kmip-spec-v{v}-os.html') for v in VERSIONS}
URLS['3.0']='https://docs.oasis-open.org/kmip/kmip-spec/v3.0/csd02/kmip-spec-v3.0-csd02.html'
def clean(s):return ' '.join(re.sub(r'<!\[.*?\]>','',s).split())
def compact(s):
 s=s.replace('(', ' ').replace(')', ' ');s=re.sub(r'[^A-Za-z0-9_\s]([A-Za-z][a-z])',r' \1',s);s=re.sub(r'[^A-Za-z0-9_\s]','_',s)
 words=s.split()
 if not words:return ''
 words[0]=re.sub(r'^(\d+)(.*)$',r'\2\1',words[0]);return ''.join(w[0].upper()+w[1:] for w in words if w)
def norm(s):return re.sub('[^a-z0-9]','',s.lower())
def ident(s):
 s=re.sub(r'([a-z0-9])([A-Z])',r'\1_\2',s);s=re.sub(r'[^A-Za-z0-9]+','_',s).strip('_').upper();return 'N_'+s if s[0].isdigit() else s
def rows(t):return [[clean(c.get_text(' ',strip=True)) for c in r.find_all(['td','th'],recursive=False)] for r in t.find_all('tr')]
def group_name(s):
 s=re.sub(r' Enumerations?$','',s)
 aliases={'Batch Error Continuation Option':'Batch Error Continuation','Key Wrap Encoding Option':'Encoding Option','Destroy Action':'Destroy Action Type','Profile Name':'Profile Name Type'}
 return compact(aliases.get(s,s))
POLYMORPHIC={'KeyMaterial':'If the Key Format Type in the Key Block is','CredentialValue':'If the Credential Type in the Credential is'}
tags=OrderedDict();tagfirst={};tagversions={};groups=OrderedDict();enumfirst={};enumreserved={};enumaliases=[];schemas={};orders={};available={}
for v in VERSIONS:
 code=int(v.replace('.',''));p=CACHE/f'spec-{v}.html'
 if not p.exists():p.write_bytes(urllib.request.urlopen(URLS[v]).read())
 soup=BeautifulSoup(p.read_bytes(),'lxml'); tables=soup.find_all('table');localtags={}
 for table in tables:
  rs=rows(table)
  if any(len(r)>1 and r[0]=='Activation Date' and r[1]=='420001' for r in rs[:8]):
   for r in rs:
    if len(r)>1 and re.match(r'^(?:0x)?42[0-9A-Fa-f]{4}(?:$| \()',r[1]) and r[0] not in ['Reserved','(Reserved)']:
     value=int(r[1].removeprefix('0x')[:6],16);localtags[compact(r[0])]=value;tags.setdefault(value,r[0]);tagfirst.setdefault(value,code);tagversions.setdefault(value,set()).add(code)
 for table in tables:
  rs=rows(table)
  if len(rs)>2 and rs[1]==['Name','Value']:
   name=rs[0][0]
   if not v.startswith('1.'):
    h=table.find_previous(['h2','h3','h4']);heading=clean(h.get_text(' ',strip=True)) if h else ''
    m=re.match(r'^(?:11|12)\.\d+ (.+)$',heading)
    if m:name=m[1]
   group=group_name(name)
   if group=='Tag':continue
   for r in rs[2:]:
    if len(r)>1 and re.match(r'^(?:0x)?[0-9A-Fa-f]{8}(?:$| )',r[1]):
     value=int(r[1].removeprefix('0x')[:8],16);groups.setdefault(group,OrderedDict()).setdefault(value,r[0]);enumfirst.setdefault((group,value),code);
     if compact(r[0])=='Reserved':enumreserved.setdefault((group,value),set()).add(code)
     enumaliases.append((group,compact(r[0]),value,code))
 current=None;localops=set();vschema={}
 # Spec prose and tables differ in capitalization (Timestamp vs TimeStamp, HAsh vs Hash).
 localnorm={norm(k):k for k in localtags};opnames={norm(compact(n)):compact(n) for n in groups['Operation'].values()}
 def local(name):return localnorm.get(norm(compact(name.split(', see')[0])))
 for el in soup.find_all(['h2','h3','table']):
  if el.name!='table':
   txt=clean(el.get_text(' ',strip=True))
   pattern=r'^[45]\.\d+ (.+)$' if v.startswith('1.') else r'^6\.[12]\.\d+ (.+)$'
   m=re.match(pattern,txt)
   if m:
    current=compact(m[1]);current=opnames.get(norm(current),current);localops.add(current)
   elif re.match(r'^(?:[789]|10)\.',txt):current=None
  else:
   rs=rows(el)
   if current and rs and rs[0] and norm(rs[0][0]) in ['requestpayload','responsepayload','messagepayload']:
    direction='response' if norm(rs[0][0])=='responsepayload' else 'request';vschema.setdefault(current,{})[direction]=[{'field':r[0].split(', see')[0].strip(),'requirement':r[1]} for r in rs[2:] if len(r)>1]
   if len(rs)>3 and rs[0] in [['Request Header'],['Response Header'],['Request Batch Item'],['Response Batch Item']]:
    parent=compact(rs[2][0]);orders[f'{code}:{parent}']=[local(r[0]) for r in rs[3:] if local(r[0])]
   if len(rs)>2 and rs[0][:2] in [['Object','Encoding'],['Item','Encoding']] and len(rs[1])>1 and rs[1][1].startswith('Structure'):
    parent=local(rs[1][0]);fields=[local(r[0]) for r in rs[2:] if len(r)>1]
    # Key Material and Credential Value have one table per Key Format Type / Credential Type.
    # Their orders are recorded per variant (PARENT@Variant) rather than merged into one list.
    variant=None
    if parent in POLYMORPHIC:
     prose=el.find_previous(lambda t:t.name=='p' and POLYMORPHIC[parent] in clean(t.get_text(' ',strip=True)))
     m=re.search(POLYMORPHIC[parent]+r' *([A-Za-z0-9 ]+?) *,',clean(prose.get_text(' ',strip=True))) if prose else None
     if m:variant=compact(m[1])
    if parent and variant:orders[f'{code}:{parent}@{variant}']=[f for f in fields if f]
    elif parent and parent not in POLYMORPHIC:
     prior=orders.setdefault(f'{code}:{parent}',[])
     for field in fields:
      if field and field not in prior:prior.append(field)
 for op,spec in vschema.items():orders[f'{code}:RequestPayload:{op}']=[local(f['field']) for f in spec.get('request',[]) if local(f['field'])]
 schemas[v]=vschema;available[v]=sorted(localops)
 print(v,len(localtags),'tags,',len(localops),'operation sections')
header=JAVA+'// Generated by tools/generate_registry.py from OASIS KMIP. See NOTICE.\npackage dev.keytend.kmip.model;\n\n'
lines=[header,'import java.util.*;\n','/** All standard tags through KMIP 3.0 CSD02, including older deprecated tags.\n *\n * @since 0.10.0\n */','public enum Tag {']
seen=set()
for value,name in tags.items():
 const=ident(name)
 if const in seen:raise ValueError('Duplicate tag name '+const)
 # Bit i is set when VERSIONS[i] defines the tag; 2.0 and 3.0 turned several tags into Reserved.
 mask=sum(1<<i for i,v in enumerate(VERSIONS) if int(v.replace('.','')) in tagversions[value])
 seen.add(const);lines.append(f'    {const}(0x{value:06X}, "{compact(name)}", {tagfirst[value]}, 0b{mask:07b}),')
lines[-1]=lines[-1][:-1]+';'
lines+=['    private final int code; private final String wireName; private final int since; private final int versions;','    Tag(int code,String wireName,int since,int versions) { this.code=code;this.wireName=wireName;this.since=since;this.versions=versions; }','    public int code() { return code; }','    public String wireName() { return wireName; }','    public ProtocolVersion since() { return ProtocolVersion.fromCode(since); }','    /** Whether the version\'s tag table defines this tag (false where it became Reserved). */','    @SuppressWarnings("EnumOrdinal") // bit i of versions is ProtocolVersion\'s i-th constant','    public boolean definedIn(ProtocolVersion version) { return (versions & (1 << version.ordinal())) != 0; }','    private static final Map<Integer,Tag> BY_CODE=new HashMap<>();','    private static final Map<String,Tag> BY_NAME=new HashMap<>();','    static { for(Tag t:values()) { BY_CODE.put(t.code,t);BY_NAME.put(normalize(t.wireName),t); } }','    public static Optional<Tag> fromCode(int code) { return Optional.ofNullable(BY_CODE.get(code)); }','    public static Tag fromName(String name) { Tag t=BY_NAME.get(normalize(name));if(t==null)throw new IllegalArgumentException("Unknown KMIP tag: "+name);return t; }','    public static String normalize(String text) { return text.replaceAll("[^A-Za-z0-9]", "").toLowerCase(Locale.ROOT); }','}']
(OUT/'Tag.java').write_text('\n'.join(lines)+'\n')
lines=[header,'/** Standard wire enumerations and masks, including PQC algorithms from KMIP 3.0 CSD02.\n *\n * @since 0.10.0\n */','public final class Enums {','    private Enums() {}']
for group,entries in groups.items():
 if group=='Operation':continue
 lines.append(f'    public enum {group} implements WireEnum {{');seen=set()
 for value,name in entries.items():
  const=ident(name)
  if const in seen:const+='_'+str(value)
  # Bit i is set when VERSIONS[i] lists the value as Reserved (for example Export in 2.0).
  reserved=sum(1<<i for i,v in enumerate(VERSIONS) if int(v.replace('.','')) in enumreserved.get((group,value),()))
  seen.add(const);lines.append(f'        {const}(0x{value:08X}, {json.dumps(compact(name))}, {enumfirst[group,value]}'+(f', 0b{reserved:07b}' if reserved else '')+'),')
 lines[-1]=lines[-1][:-1]+';'
 lines+=['        private final int code;private final String wireName;private final int since;private final int reserved;',f'        {group}(int code,String wireName,int since) {{ this(code,wireName,since,0); }}',f'        {group}(int code,String wireName,int since,int reserved) {{ this.code=code;this.wireName=wireName;this.since=since;this.reserved=reserved; }}','        @Override public int code() { return code; }','        @Override public String wireName() { return wireName; }','        @Override public ProtocolVersion since() { return ProtocolVersion.fromCode(since); }','        /** Defined from {@link #since()} on, except in versions whose table lists the value as Reserved. */','        @Override @SuppressWarnings("EnumOrdinal") // bit i of reserved is ProtocolVersion\'s i-th constant','        public boolean definedIn(ProtocolVersion version) { return version.atLeast(since()) && (reserved & (1 << version.ordinal())) == 0; }',f'        /** The constant for a wire code; empty for vendor, future or invalid codes. */',f'        public static java.util.Optional<{group}> fromCode(int code) {{ return WireEnums.fromCode({group}.class, code); }}','    }']
lines+=['}'];(OUT/'Enums.java').write_text('\n'.join(lines)+'\n')
lines=[header,'import java.util.Arrays;\n','/** Every operation code through KMIP 3.0 CSD02.\n *\n * @since 0.10.0\n */','public enum Operation implements WireEnum {']
for value,name in groups['Operation'].items():lines.append(f'    {ident(name)}(0x{value:02X}, "{compact(name)}", {enumfirst["Operation",value]}),')
lines[-1]=lines[-1][:-1]+';'
lines+=['    private final int code;private final String wireName;private final int since;','    Operation(int code,String wireName,int since) { this.code=code;this.wireName=wireName;this.since=since; }','    @Override public int code() { return code; }','    @Override public String wireName() { return wireName; }','    @Override public ProtocolVersion since() { return ProtocolVersion.fromCode(since); }','    public void requireVersion(ProtocolVersion v) { if(!v.atLeast(since()))throw new IllegalArgumentException(wireName+" requires KMIP "+since()); }','    public boolean serverToClient() { return this==NOTIFY || this==PUT; }','    public static Operation fromCode(int code) { return Arrays.stream(values()).filter(o -> o.code==code).findFirst().orElseThrow(() -> new IllegalArgumentException("Unknown operation: "+code)); }','}'];(OUT/'Operation.java').write_text('\n'.join(lines)+'\n')
(RES/'enumerations.tsv').write_text('\n'.join(f'{g}\t{n}\t{value}\t{enumfirst[g,value]}' for g,n,value,v in dict.fromkeys(enumaliases))+'\n')
(RES/'order.tsv').write_text('\n'.join(k+'\t'+'\t'.join(fields) for k,fields in orders.items())+'\n')
reg={'sources':URLS,'tags':{compact(name):value for value,name in tags.items()},'enumerations':{g:{n:v for v,n in e.items()} for g,e in groups.items()},'schemas':schemas,'operationSections':available}
(RES/'registry.json').write_text(json.dumps(reg,indent=2)+'\n')
# Public operation entry points, generated alongside the wire registries.
lines=[JAVA+'// Generated by tools/generate_registry.py from OASIS KMIP. See NOTICE.\npackage dev.keytend.kmip.client;','','import dev.keytend.kmip.model.*;','import static dev.keytend.kmip.model.Tag.*;','import static dev.keytend.kmip.model.Ttlv.*;','','/** Named entry points for every operation through KMIP 3.0 CSD02.\n *\n * @since 0.10.0\n */','public final class Requests {','    private Requests() {}']
for value,name in groups['Operation'].items():
 words=re.sub('[^A-Za-z0-9 ]','',name).split();method=words[0].lower()+''.join(w.title() if w.isupper() else w[0].upper()+w[1:] for w in words[1:])
 method={'Re-key':'reKey','Re-certify':'reCertify','Re-key Key Pair':'reKeyKeyPair','Re-Provision':'reProvision','Notify':'notifyRequest','Import':'importObject','PKCS#11':'pkcs11'}.get(name,method)
 lines.append(f'    public static Request.Builder {method}() {{ return Request.operation(Operation.{ident(name)}); }}')
lines+=['    /** Requires at least one usage: an empty mask would create a key that permits nothing. */','    public static Request createSymmetricKey(Enums.CryptographicAlgorithm algorithm,int bits,Enums.CryptographicUsageMask... usage) { if(usage.length==0)throw new IllegalArgumentException("At least one cryptographic usage is required");return create().add(enumeration(OBJECT_TYPE,Enums.ObjectType.SYMMETRIC_KEY)).template(Attributes.algorithm(algorithm),Attributes.length(bits),Attributes.usage(usage)).build(); }','    public static Request registerObject(Ttlv object,Ttlv... attributes) { return register().add(enumeration(OBJECT_TYPE,ManagedObjects.objectType(object)),Attributes.template(attributes),object).build(); }','    /** Revocation Message is optional; a null message is omitted. */','    public static Request revoke(String id,Enums.RevocationReasonCode reason,String message) { java.util.Objects.requireNonNull(id,"id");java.util.Objects.requireNonNull(reason,"reason");Ttlv code=enumeration(REVOCATION_REASON_CODE,reason);return revoke().uniqueIdentifier(id).add(message==null?structure(REVOCATION_REASON,code):structure(REVOCATION_REASON,code,text(REVOCATION_MESSAGE,message))).build(); }','}']
(ROOT/'sdk/src/main/java/dev/keytend/kmip/client/Requests.java').write_text('\n'.join(lines)+'\n')
print('TOTAL',len(tags),'tags,',len(groups),'enum groups,',len(groups['Operation']),'operations')

# Runtime operation descriptions; conditional requirements are kept verbatim, not flattened to booleans.
meta=[]
for version,operations in schemas.items():
 for operation,directions in operations.items():
  for direction,fields in directions.items():
   for field in fields:meta.append(str(int(version.replace('.','')))+'\t'+operation+'\t'+direction+'\t'+field['field']+'\t'+field['requirement'])
(RES/'payloads.tsv').write_text('\n'.join(meta)+'\n')
