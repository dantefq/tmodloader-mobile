"""Build an own adapter around one hash-pinned local third-party mod DLL."""
import argparse
import io
import json
from pathlib import Path
import shutil

from apk_format import sha256
from build_companion import run
from inspect_mod_api import assembly_bytes, metadata
from check_mod_signatures import compare
from inspect_workshop import string
from managed_api_sources import API_SOURCES, HOST_SUPPORT_SOURCES

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--lab', type=Path, required=True)
    p.add_argument('--tmod', type=Path, default=Path('C:/Program Files (x86)/Steam/steamapps/workshop/content/1281930/3014137690/2025.1/ChangeSleepTime.tmod'))
    p.add_argument('--dotnet', type=Path, default=Path('C:/Program Files/dotnet'))
    p.add_argument('--unified', action='store_true', help='Use the common item/time API and registry; preserve the historical minimal bundle')
    args = p.parse_args()
    stem = 'unified-sleep' if args.unified else 'sleep'
    lab = args.lab.resolve() / (stem+'-demo')
    if lab.is_relative_to(ROOT): raise ValueError('Keep third-party DLL and outputs outside repository')
    bundle = lab / 'bundle'; bundle.mkdir(parents=True, exist_ok=True)
    data, header = assembly_bytes(args.tmod, 'ChangeSleepTime.dll')
    meta = metadata(data)
    if header['mod'] != 'ChangeSleepTime' or header['version'] != '2025.3.6.1' or meta['type_definition_count'] != 4:
        raise ValueError('Only the audited local mod version is supported')
    if {r['name'] for r in meta['assembly_references']} != {'System.Runtime', 'tModLoader'}:
        raise ValueError('Unexpected assembly dependencies')
    expected = json.loads((ROOT / 'reports/small-mod-candidates.json').read_text())
    pinned = next(row for row in expected['candidates'] if row['mod'] == 'ChangeSleepTime')
    import hashlib
    if hashlib.sha256(data).hexdigest() != pinned['assembly_sha256']: raise ValueError('Audited DLL changed')
    info, _ = assembly_bytes(args.tmod, 'Info')
    stream = io.BytesIO(info); tags = []
    while stream.tell() < len(info): tags.append(string(stream))
    if any(tag in tags for tag in ('modReferences', 'weakReferences', 'dllReferences')):
        raise ValueError('Mod dependency declarations require separate review')
    refs = sorted((args.dotnet / 'packs/Microsoft.NETCore.App.Ref/8.0.31/ref/net8.0').glob('*.dll'))
    if not refs: raise ValueError('.NET8 reference assemblies missing')
    csc = args.dotnet / 'sdk/8.0.425/Roslyn/bincore/csc.dll'
    def compile(name, sources, extra, exe=False):
        target = bundle / name
        rsp = lab / (name + '.rsp')
        lines = ['-nologo', '-target:'+('exe' if exe else 'library'), '-nostdlib+', '-deterministic+', '-langversion:12', f'-out:"{target}"']
        if args.unified: lines += ['-define:TMAL_COMBINED_CONTENT']
        lines += [f'-r:"{r}"' for r in [*refs, *extra]]
        lines += [f'"{ROOT / source}"' for source in sources]
        rsp.write_text('\n'.join(lines), encoding='utf-8')
        run([args.dotnet / 'dotnet.exe', csc, '@' + str(rsp)])
        return target
    shim = compile('tModLoader.dll', API_SOURCES if args.unified else ['managed/compat/MinimalTimeApi.cs'], [])
    preflight = compare(data, shim.read_bytes())
    if (preflight['missing_types'] or preflight['counts'] != {'exact-signature': 13}
            or preflight['override_counts'] != {'exact-override': 2}):
        raise ValueError('Audited sleep API signature/override contract differs: ' +
                         json.dumps(preflight, sort_keys=True))
    # Write the pinned user-owned DLL only after the static API preflight.
    dll = bundle / 'ChangeSleepTime.dll'; dll.write_bytes(data)
    host = compile('TerrariaMobile.ManagedDemo.dll',
        ['managed/unified-host/ManagedTimeHost.cs','managed/unified-host/ManagedModItemHost.cs',*HOST_SUPPORT_SOURCES] if args.unified else ['managed/time-host/ManagedTimeHost.cs'], [shim])
    contract = {'mode': 'time-rate', 'mod': header['mod'], 'version': header['version'],
                'mod_dll_sha256': sha256(dll), 'tmod_sha256': sha256(args.tmod), 'handler_count': 1,
                'self_test_cases': 10, 'default_multiplier': 5, 'general_tmod_support': False}
    host_checks = None
    if args.unified:
        contract.update(api_revision='managed-foundation-v2', lifecycle_check_count=7, content_check_count=14)
        original=json.loads((ROOT/'reports/moditem-demo-build.json').read_text('utf-8-sig'))
        pc_tmod=Path(original['bundle'])/'PcModItemDemo.tmod'
        if sha256(pc_tmod)!=original['files']['PcModItemDemo.tmod']:
            raise ValueError('Previously PC-compiled own ModItem container changed')
        item_data,_=assembly_bytes(pc_tmod,'PcModItemDemo.dll')
        if hashlib.sha256(item_data).hexdigest()!=original['contract']['mod_dll_sha256']:
            raise ValueError('Original PC ModItem DLL changed')
        # Test binaries remain private and are excluded from the four-file APK bundle.
        (bundle/'PcModItemDemo.dll').write_bytes(item_data)
        shutil.copyfile(pc_tmod,bundle/'PcModItemDemo.tmod')
        contract['item_contract']=original['contract']
        runner=compile('UnifiedTimeChecks.dll',['managed/tests/OriginalTimeItemChecks.cs'],[shim,host],True)
        runner.with_suffix('.runtimeconfig.json').write_text(json.dumps({'runtimeOptions':{
            'tfm':'net8.0','framework':{'name':'Microsoft.NETCore.App','version':'8.0.31'}}}),encoding='utf-8')
        result=run([args.dotnet/'dotnet.exe',runner])
        host_checks=json.loads(result)
        if host_checks['status']!='passed' or host_checks['original_sleep_cases']!=10 or host_checks['lifecycle_checks']!=7:
            raise ValueError('Original-DLL unified host checks failed')
    contract_file = bundle / 'demo-contract.json'
    contract_file.write_text(json.dumps(contract, indent=2) + '\n', encoding='utf-8')
    files=[host,shim,dll,contract_file]
    if args.unified: files.append(bundle/'PcModItemDemo.tmod')
    report = {'status': 'built-runtime-unverified', 'bundle': str(bundle),
              'source_tmod': str(args.tmod), 'source_tmod_sha256': sha256(args.tmod),
              'mod_dll_recompiled_or_patched': False, 'own_api_shim': True, 'game_code_bundled': False,
              'contains_user_owned_third_party_mod': True, 'private_lab_only': True,
              'declared_external_mod_dependencies': [], 'files': {f.name: sha256(f) for f in files},
              'static_signature_preflight': preflight,
              'api_revision': contract.get('api_revision'), 'host_checks':host_checks,
              'contract': contract}
    (ROOT / 'reports'/(stem+'-demo-build.json')).write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    (lab/'bundle-build.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k:report[k] for k in ('status','bundle','files','api_revision','host_checks')},indent=2))


if __name__ == '__main__': main()
