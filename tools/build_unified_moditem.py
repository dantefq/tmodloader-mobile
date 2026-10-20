"""Build the merged API around our unchanged PC demo; leave legacy bundles intact."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
from apk_format import sha256
from build_companion import run
from inspect_mod_api import assembly_bytes
from managed_api_sources import API_SOURCES, HOST_SUPPORT_SOURCES

ROOT = Path(__file__).resolve().parents[1]
REVISION = 'managed-foundation-v1'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--lab', type=Path, required=True)
    p.add_argument('--dotnet', type=Path, default=Path('C:/Program Files/dotnet'))
    args = p.parse_args()
    lab = args.lab.resolve()/'unified-moditem-demo'
    if lab.is_relative_to(ROOT): raise ValueError('Keep DLLs outside source repository')
    bundle = lab/'bundle'; bundle.mkdir(parents=True, exist_ok=True)
    original = json.loads((ROOT/'reports/moditem-demo-build.json').read_text('utf-8-sig'))
    tmod = Path(original['bundle'])/'PcModItemDemo.tmod'
    if sha256(tmod) != original['files'][tmod.name]: raise ValueError('Original own demo changed')
    data, header = assembly_bytes(tmod, 'PcModItemDemo.dll')
    contract = dict(original['contract'])
    if header['mod'] != 'PcModItemDemo' or hashlib.sha256(data).hexdigest() != contract['mod_dll_sha256']:
        raise ValueError('Expected the exact previously PC-compiled own demo')
    shutil.copyfile(tmod, bundle/tmod.name)
    refs = sorted((args.dotnet/'packs/Microsoft.NETCore.App.Ref/8.0.31/ref/net8.0').glob('*.dll'))
    csc = args.dotnet/'sdk/8.0.425/Roslyn/bincore/csc.dll'
    if not refs or not csc.is_file(): raise ValueError('Pinned .NET SDK 8.0.425 / refs 8.0.31 required')
    def compile(name, sources, extra=()):
        out = bundle/name; rsp = lab/(name+'.rsp')
        lines = ['-nologo','-target:library','-nostdlib+','-deterministic+','-langversion:12',f'-out:"{out}"']
        lines += [f'-r:"{r}"' for r in [*refs,*extra]]
        lines += [f'"{ROOT/s}"' for s in sources]
        rsp.write_text('\n'.join(lines), encoding='utf-8')
        run([args.dotnet/'dotnet.exe',csc,'@'+str(rsp)])
        return out
    shim = compile('tModLoader.dll', API_SOURCES)
    host = compile('TerrariaMobile.ManagedDemo.dll',
                   ['managed/unified-host/ManagedModItemHost.cs', *HOST_SUPPORT_SOURCES], [shim])
    contract.update(api_revision=REVISION, foundation_check_count=8)
    contract_file = bundle/'demo-contract.json'
    contract_file.write_text(json.dumps(contract, indent=2)+'\n', encoding='utf-8')
    report = {'status':'built-runtime-unverified','bundle':str(bundle),'api_revision':REVISION,
              'own_api_shim':True,'game_code_bundled':False,'arbitrary_tmod_supported':False,
              'pc_mod_dll_recompiled':False,'original_pc_mod_sha256':hashlib.sha256(data).hexdigest(),
              'contract':contract,'files':{f.name:sha256(f) for f in (host,shim,bundle/tmod.name,contract_file)}}
    (ROOT/'reports/unified-moditem-demo-build.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2))


if __name__ == '__main__': main()
