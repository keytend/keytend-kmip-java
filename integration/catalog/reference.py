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

"""Independent minimal binary KMIP probe. No Java SDK/codec dependency; synthetic keys only."""
import argparse, hashlib, json, socket, ssl, struct
T={n:0x420000+v for n,v in dict(RequestMessage=0x78,RequestHeader=0x77,ProtocolVersion=0x69,ProtocolVersionMajor=0x6a,ProtocolVersionMinor=0x6b,BatchCount=0x0d,BatchItem=0x0f,Operation=0x5c,RequestPayload=0x79,ObjectType=0x57,TemplateAttribute=0x91,Attribute=0x08,AttributeName=0x0a,AttributeValue=0x0b,Attributes=0x125,CryptographicAlgorithm=0x28,CryptographicLength=0x2a,CryptographicUsageMask=0x2c,SymmetricKey=0x8f,KeyBlock=0x40,KeyFormatType=0x42,KeyValue=0x45,KeyMaterial=0x43,UniqueIdentifier=0x94,ResponsePayload=0x7c,ResultStatus=0x7f,ResultReason=0x7e,TimeStamp=0x92).items()}
def item(tag,kind,value):
 if isinstance(tag,str): tag=T[tag]
 if kind==1: value=b''.join(value)
 elif kind in (2,5): value=struct.pack('>I',value&0xffffffff)
 elif kind in (7,12,13,14): value=value.encode('utf-8')
 return tag.to_bytes(3,'big')+bytes([kind])+struct.pack('>I',len(value))+value+b'\0'*((-len(value))%8)
def parse(data,offset=0):
 tag=int.from_bytes(data[offset:offset+3],'big'); kind=data[offset+3]; size=int.from_bytes(data[offset+4:offset+8],'big'); start=offset+8; end=start+size
 if end>len(data): raise ValueError('Truncated response')
 value=data[start:end]
 if kind==1:
  value=[]; p=start
  while p<end: n,p=parse(data,p); value.append(n)
 elif kind in (2,5):value=int.from_bytes(value,'big')
 elif kind in (7,12,13,14):value=value.decode('utf-8')
 return (tag,kind,value),end+(-size)%8
def find(node,name):
 for c in node[2] if node[1]==1 else []:
  if c[0]==T[name]:return c
 raise ValueError('Missing '+name)
def exact(s,n):
 b=b''
 while len(b)<n:
  p=s.recv(n-len(b))
  if not p:raise EOFError('Truncated response')
  b+=p
 return b
def exchange(a,op,fields):
 major,minor=map(int,a.version.split('.')); h=[item('ProtocolVersion',1,[item('ProtocolVersionMajor',2,major),item('ProtocolVersionMinor',2,minor)])]
 if major!=3:h.append(item('BatchCount',2,1))
 request=item('RequestMessage',1,[item('RequestHeader',1,h),item('BatchItem',1,[item('Operation',5,op),item('RequestPayload',1,fields)])])
 ctx=ssl.create_default_context(cafile=a.certs+'/ca.pem');ctx.minimum_version=ssl.TLSVersion.TLSv1_2;ctx.load_cert_chain(a.certs+'/client.pem',a.certs+'/client-key.pem')
 with socket.create_connection((a.host,a.port),timeout=5) as raw:
  with ctx.wrap_socket(raw,server_hostname=a.host) as s:
   s.sendall(request); header=exact(s,8); size=int.from_bytes(header[4:],'big')
   if size>1024*1024:raise ValueError('Oversize response')
   root,_=parse(header+exact(s,(size+7)//8*8)); batch=find(root,'BatchItem');status=find(batch,'ResultStatus')[2]
   if status!=0: raise RuntimeError('KMIP failure status='+str(status)+' reason='+str(find(batch,'ResultReason')[2]))
   return find(batch,'ResponsePayload'),s.version()
def main():
 p=argparse.ArgumentParser();p.add_argument('action',choices=['register','get']);p.add_argument('host');p.add_argument('port',type=int);p.add_argument('certs');p.add_argument('version');p.add_argument('--uid');a=p.parse_args();major=int(a.version.split('.')[0]);known=bytes(range(32))
 if a.action=='register':
  attrs=[item('CryptographicAlgorithm',5,3),item('CryptographicLength',2,256),item('CryptographicUsageMask',2,12)]
  if major==1:
   attrs=item('TemplateAttribute',1,[item('Attribute',1,[item('AttributeName',7,name),item('AttributeValue',5 if name=='Cryptographic Algorithm' else 2,value)]) for name,value in [('Cryptographic Algorithm',3),('Cryptographic Length',256),('Cryptographic Usage Mask',12)]])
  else:attrs=item('Attributes',1,attrs)
  payload,tls=exchange(a,3,[item('ObjectType',5,2),attrs,item('SymmetricKey',1,[item('KeyBlock',1,[item('KeyFormatType',5,1),item('KeyValue',1,[item('KeyMaterial',8,known)]),item('CryptographicAlgorithm',5,3),item('CryptographicLength',2,256)])])]);uid=find(payload,'UniqueIdentifier')[2]
 else:uid=a.uid
 payload,tls=exchange(a,10,[item('UniqueIdentifier',13 if major==3 else 7,uid)])
 block=find(find(payload,'SymmetricKey'),'KeyBlock');material=find(find(block,'KeyValue'),'KeyMaterial')[2]
 print(json.dumps(dict(uid=find(payload,'UniqueIdentifier')[2],bits=find(block,'CryptographicLength')[2],algorithm=find(block,'CryptographicAlgorithm')[2],sha256=hashlib.sha256(material).hexdigest(),tls=tls)))
if __name__=='__main__':main()
