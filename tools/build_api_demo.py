"""Compile our GlobalItem mod against real local PC tModLoader, and an own mobile shim."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile
from apk_format import sha256
from build_companion import run

ROOT=Path(__file__).resolve().parents[1]

def encoded_string(value):
    raw=value.encode('utf-8'); count=len(raw); prefix=bytearray()
    while count>=128: prefix.append((count&127)|128);count >>= 7
    prefix.append(count)
    return bytes(prefix)+raw

def make_tmod(path,dll):
    info=b''.join(encoded_string(value) for value in ('version','1.0.0','buildVersion','2026.8.3.0','displayName','Own PC GlobalItem Demo',''))
    entries=[('Info',info),('PcGlobalItemDemo.dll',dll)]
    table=encoded_string('PcGlobalItemDemo')+encoded_string('1.0.0')+struct.pack('<i',len(entries))
    for name,data in entries: table+=encoded_string(name)+struct.pack('<ii',len(data),len(data))
    payload=table+b''.join(data for _,data in entries)
    path.write_bytes(b'TMOD'+encoded_string('2026.8.3.0')+hashlib.sha1(payload).digest()+bytes(256)+struct.pack('<i',len(payload))+payload)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--lab',type=Path,required=True)
    p.add_argument('--tml',type=Path,default=Path('C:/Program Files (x86)/Steam/steamapps/common/tModLoader/tModLoader.dll'))
    p.add_argument('--dotnet',type=Path,default=Path('C:/Program Files/dotnet'))
    args=p.parse_args()
    lab=args.lab.resolve()/'api-demo'
    if lab.is_relative_to(ROOT): raise ValueError('Keep compiled DLLs outside source repository')
    lab.mkdir(parents=True,exist_ok=True)
    bundle=lab/'bundle';bundle.mkdir(exist_ok=True)
    csc=args.dotnet/'sdk/8.0.425/Roslyn/bincore/csc.dll'
    refs=sorted((args.dotnet/'packs/Microsoft.NETCore.App.Ref/8.0.31/ref/net8.0').glob('*.dll'))
    if not refs or not args.tml.is_file(): raise ValueError('Local PC tModLoader and .NET8 reference assemblies required')
    def compile(name,source,extra):
        output=bundle/name
        response=lab/(name+'.rsp')
        lines=['-nologo','-target:library','-nostdlib+','-deterministic+','-langversion:12',f'-out:"{output}"']
        lines += [f'-r:"{ref}"' for ref in [*refs,*extra]]
        lines += [f'"{ROOT/source}"']
        response.write_text('\n'.join(lines),encoding='utf-8')
        run([args.dotnet/'dotnet.exe',csc,'@'+str(response)])
        return output
    pc=compile('PcGlobalItemDemo.dll','managed/pc-demo/PcGlobalItemDemo.cs',[args.tml])
    shim=compile('tModLoader.dll','managed/compat/MinimalTmlApi.cs',[])
    host=compile('TerrariaMobile.ManagedDemo.dll','managed/api-host/ManagedGlobalItemHost.cs',[shim])
    tmod=bundle/'PcGlobalItemDemo.tmod';make_tmod(tmod,pc.read_bytes())
    contract={'mode':'global-item','name':'PC API Test Sword','damage_add':19,'handler_count':1,
              'checks':[[3507,5,24],[1,5,5],[3507,7,26]],'tmod_sha256':sha256(tmod),'mod_dll_sha256':sha256(pc)}
    (bundle/'demo-contract.json').write_text(json.dumps(contract,indent=2)+'\n',encoding='utf-8')
    # The Android package receives the .tmod; Java extracts only its own DLL.
    files=[host,shim,tmod,bundle/'demo-contract.json']
    report={'status':'built-unverified','bundle':str(bundle),'pc_mod_dll':str(pc),
            'pc_reference_assembly':str(args.tml),'pc_reference_sha256':sha256(args.tml),
            'own_api_shim':True,'game_code_bundled':False,'arbitrary_tmod_supported':False,
            'files':{file.name:sha256(file) for file in files},'contract':contract}
    (ROOT/'reports/api-demo-build.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2))

if __name__=='__main__': main()
