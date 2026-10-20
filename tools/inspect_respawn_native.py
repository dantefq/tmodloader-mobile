"""Read a bounded native UpdateDead span; retain game disassembly privately."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--serial', required=True)
    p.add_argument('--lab', type=Path, required=True)
    args = p.parse_args()
    if args.lab.resolve().is_relative_to(ROOT):
        raise ValueError('Keep game disassembly private')
    evidence = json.loads((ROOT / 'reports/android-respawn-method-metadata.json').read_text())
    entries = {m['name']: m for m in evidence['player_methods']}
    start = int(entries['UpdateDead']['native_module_offset'], 16)
    end = int(entries['Spawn']['native_module_offset'], 16)
    if not 0 < end - start <= 4096:
        raise ValueError('Expected bounded method-neighbor span')
    adb = Path.home() / 'AppData/Local/Android/Sdk/platform-tools/adb.exe'
    pid = subprocess.check_output([str(adb), '-s', args.serial, 'shell', 'pidof',
                                   'com.and.games505.TerrariaPaid'], timeout=25).decode().strip()
    if not pid.isdigit() or int(pid) != evidence['pid']:
        raise ValueError('Refresh metadata for the current game process')
    subprocess.run([str(adb), '-s', args.serial, 'forward', 'tcp:27043', 'tcp:27042'], check=True, timeout=25)
    sys.path.insert(0, str(ROOT / '.tools/frida-deps'))
    import frida
    session = frida.get_device_manager().add_remote_device('127.0.0.1:27043').attach(int(pid))
    try:
        script = session.create_script('''rpc.exports.inspect=function(start,end){
            const module=Process.getModuleByName('libil2cpp.so'),rows=[];
            for(let offset=start;offset<end;offset+=4){
                const p=module.base.add(offset),instruction=Instruction.parse(p);
                if(instruction.size!==4)throw Error('Expected ARM64 instruction');
                rows.push({offset:'0x'+offset.toString(16),text:instruction.toString()});
            }
            return {pid:Process.id,architecture:Process.arch,rows};
        };''')
        script.load()
        result = script.exports_sync.inspect(start, end)
        script.unload()
    finally:
        session.detach()
    args.lab.mkdir(parents=True, exist_ok=True)
    private = args.lab / 'mobile-update-dead-private-disassembly.json'
    raw = (json.dumps(result, indent=2) + '\n').encode()
    private.write_bytes(raw)
    report = {'status': 'read-only-bounded-native-span', 'pid': int(pid), 'start': hex(start), 'end': hex(end),
              'size': end - start, 'private_evidence': str(private), 'sha256': hashlib.sha256(raw).hexdigest(),
              'span_basis': 'UpdateDead start to the following Spawn entrypoint; precise function boundary not independently proved',
              'game_state_modified': False, 'native_clamp_semantics_verified': False}
    (ROOT / 'reports/android-respawn-native-inspection.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))
    hits = [i for i, row in enumerate(result['rows']) if any(x in row['text'] for x in ('0xe10', '#3600', '#0x5fc'))]
    for i in hits:
        print(json.dumps(result['rows'][max(0, i-5):i+8]))


if __name__ == '__main__':
    main()
