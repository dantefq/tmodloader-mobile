"""Pin the own demo bundle; never package the user's PC game assembly."""
import json
from pathlib import Path
import shutil
from apk_format import sha256

ROOT=Path(__file__).resolve().parents[1]
NAMES={'TerrariaMobile.ManagedDemo.dll','tModLoader.dll','PcGlobalItemDemo.tmod','demo-contract.json'}

def copy_bundle(bundle,target):
    contract=json.loads((bundle/'demo-contract.json').read_text(encoding='utf-8'))
    moditem=contract.get('mode')=='mod-item'
    time_rate=contract.get('mode')=='time-rate'
    respawn=contract.get('mode')=='respawn-snapshot'
    revision=contract.get('api_revision')
    unified_time=revision=='managed-foundation-v2' and time_rate
    if revision is not None and not (revision=='managed-foundation-v1' and moditem) and not unified_time:
        raise ValueError('Unknown experimental API revision')
    stem='respawn' if respawn else 'unified-sleep' if unified_time else 'unified-moditem' if revision else 'sleep' if time_rate else 'moditem' if moditem else 'api'
    report=json.loads((ROOT/'reports'/f'{stem}-demo-build.json').read_text(encoding='utf-8'))
    names=(NAMES-{'PcGlobalItemDemo.tmod'})|{'PcModItemDemo.tmod'} if moditem else NAMES
    if time_rate: names=(NAMES-{'PcGlobalItemDemo.tmod'})|{'ChangeSleepTime.dll'}
    if unified_time: names.add('PcModItemDemo.tmod')
    if respawn:
        names={'TerrariaMobile.ManagedDemo.dll','tModLoader.dll','TerrariaHooks.dll','ShorterRespawn.dll',
               'demo-contract.json','FNA.dll','ReLogic.dll','log4net.dll','Newtonsoft.Json.dll',
               'Mono.Cecil.dll','MonoMod.Utils.dll','MonoMod.Backports.dll','MonoMod.ILHelpers.dll'}
        if contract.get('live_game_supported') is not False or contract.get('mod_dll_sha256')!='aeaf65ac9b0699950ebbd033f42891c298f807fa07d665da67c77adf2d4b5e9a':
            raise ValueError('Only the audited isolated respawn bundle is supported')
    if set(report['files'])!=names or not report['own_api_shim'] or report['game_code_bundled']:
        raise ValueError('Expected the independently written demo bundle')
    for name,digest in report['files'].items():
        source=bundle/name
        if sha256(source)!=digest: raise ValueError('Own bundle checksum differs: '+name)
        shutil.copyfile(source,target/name)
    return report
