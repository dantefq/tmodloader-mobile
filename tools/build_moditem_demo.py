"""Build one own PC ModItem and a separately written mobile API adapter."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from apk_format import sha256
from build_companion import run
from build_api_demo import encoded_string

ROOT = Path(__file__).resolve().parents[1]

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--lab', type=Path, required=True)
    p.add_argument('--tml', type=Path, default=Path('C:/Program Files (x86)/Steam/steamapps/common/tModLoader/tModLoader.dll'))
    p.add_argument('--dotnet', type=Path, default=Path('C:/Program Files/dotnet'))
    args = p.parse_args()
    lab = args.lab.resolve()/'moditem-demo'
    if lab.is_relative_to(ROOT): raise ValueError('Keep binaries outside source repository')
    bundle = lab/'bundle'; bundle.mkdir(parents=True, exist_ok=True)
    refs = sorted((args.dotnet/'packs/Microsoft.NETCore.App.Ref/8.0.31/ref/net8.0').glob('*.dll'))
    if not refs or not args.tml.is_file(): raise ValueError('Local .NET8 and PC tModLoader required')
    def compile(name, source, extra):
        output = bundle/name; response = lab/(name+'.rsp')
        lines = ['-nologo','-target:library','-nostdlib+','-deterministic+','-langversion:12',f'-out:"{output}"']
        lines += [f'-r:"{path}"' for path in [*refs,*extra]]
        lines += [f'"{ROOT/source}"']
        response.write_text('\n'.join(lines), encoding='utf-8')
        run([args.dotnet/'dotnet.exe',args.dotnet/'sdk/8.0.425/Roslyn/bincore/csc.dll','@'+str(response)])
        return output
    pc = compile('PcModItemDemo.dll','managed/pc-demo/PcModItemDemo.cs',[args.tml])
    shim = compile('tModLoader.dll','managed/compat/MinimalModItemApi.cs',[])
    host = compile('TerrariaMobile.ManagedDemo.dll','managed/api-host/ManagedModItemHost.cs',[shim])
    info = b''.join(encoded_string(value) for value in ('version','1.0.0','buildVersion','2026.8.3.0','displayName','Own PC ModItem Demo',''))
    entries = [('Info',info),('PcModItemDemo.dll',pc.read_bytes())]
    payload = encoded_string('PcModItemDemo')+encoded_string('1.0.0')+struct.pack('<i',2)
    for name,data in entries: payload += encoded_string(name)+struct.pack('<ii',len(data),len(data))
    payload += b''.join(data for _,data in entries)
    tmod = bundle/'PcModItemDemo.tmod'
    tmod.write_bytes(b'TMOD'+encoded_string('2026.8.3.0')+hashlib.sha1(payload).digest()+bytes(256)+struct.pack('<i',len(payload))+payload)
    contract = {'mode':'mod-item','name':'PC ModItem Test Blade','name_test_id':6196,'content_id':6196,'template_id':3507,
                'handler_count':1,'checks':[[6196,5,37],[3507,5,5],[6196,7,37]],
                'tmod_sha256':sha256(tmod),'mod_dll_sha256':sha256(pc)}
    (bundle/'demo-contract.json').write_text(json.dumps(contract,indent=2)+'\n',encoding='utf-8')
    report = {'status':'built-unverified','bundle':str(bundle),'pc_reference_assembly':str(args.tml),
              'pc_reference_sha256':sha256(args.tml),'own_api_shim':True,'game_code_bundled':False,'arbitrary_tmod_supported':False,
              'files':{path.name:sha256(path) for path in (host,shim,tmod,bundle/'demo-contract.json')},'contract':contract}
    (ROOT/'reports/moditem-demo-build.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2))

if __name__ == '__main__': main()
