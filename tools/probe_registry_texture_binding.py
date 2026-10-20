"""Keep an own C# registry alive through a pinned texture's native icon probe.

Only the original texture is read, as data. No original mod DLL is loaded.
Outputs, copied resources and build products must stay in a new private lab.
"""
import argparse
import hashlib
import json
from pathlib import Path
import queue
import subprocess
import sys
import threading

from managed_api_sources import API_SOURCES, HOST_SUPPORT_SOURCES
from registry_texture_binding import read_binding

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tmod', required=True, type=Path)
    parser.add_argument('--lab', required=True, type=Path)
    parser.add_argument('--dotnet', type=Path, default=Path('C:/Program Files/dotnet'))
    parser.add_argument('--serial')
    parser.add_argument('--host-only', action='store_true')
    parser.add_argument('--previous-binding', type=Path, help='Previous completed fixture plan for a native stale-generation rejection control')
    args = parser.parse_args()
    previous_plan = None; previous_packet = None
    if args.previous_binding:
        previous_plan, previous_packet, _, _ = read_binding(args.previous_binding)
    lab = args.lab.resolve()
    if lab.is_relative_to(ROOT) or lab.exists() or (not args.host_only and not args.serial):
        raise ValueError('New private lab and explicit device or --host-only required')
    lab.mkdir(parents=True)
    build = lab / 'build'; build.mkdir()
    dotnet = args.dotnet / 'dotnet.exe'
    csc = args.dotnet / 'sdk/8.0.425/Roslyn/bincore/csc.dll'
    refs = sorted((args.dotnet / 'packs/Microsoft.NETCore.App.Ref/8.0.31/ref/net8.0').glob('*.dll'))
    if not csc.is_file() or not refs:
        raise ValueError('Pinned SDK 8.0.425 and references 8.0.31 required')

    def compile(name, sources, extra=(), executable=False):
        output = build / name
        response = build / (name + '.rsp')
        lines = ['-nologo', '-nostdlib+', '-deterministic+', '-langversion:12',
                 '-target:' + ('exe' if executable else 'library'), '-out:"' + str(output) + '"']
        lines += ['-r:"' + str(ref) + '"' for ref in [*refs, *extra]]
        lines += ['"' + str(ROOT / source) + '"' for source in sources]
        response.write_text('\n'.join(lines), encoding='utf-8')
        result = subprocess.run([str(dotnet), str(csc), '@' + str(response)], capture_output=True, timeout=60)
        (build / (name + '.compiler.txt')).write_bytes(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError('Own registry host compilation failed; private compiler output retained')
        return output

    shim = compile('tModLoader.dll', API_SOURCES)
    sources = [*HOST_SUPPORT_SOURCES, 'managed/tools/TextureBindingHost.cs']
    # The common shim deliberately exposes its internal host API only to this
    # existing friend-assembly identity. Keep that boundary unchanged.
    executable = compile('TerrariaMobile.ManagedDemo.dll', sources, [shim], True)
    executable.with_suffix('.runtimeconfig.json').write_text(json.dumps({'runtimeOptions': {
        'tfm': 'net8.0', 'framework': {'name': 'Microsoft.NETCore.App', 'version': '8.0.31'}}}), encoding='utf-8')
    fixture = lab / 'fixture'
    transcript = []
    replies = queue.Queue()
    with (lab / 'host-stderr.txt').open('w', encoding='utf-8') as stderr:
        host = subprocess.Popen([str(dotnet), str(executable), str(args.tmod.resolve()), str(fixture)],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr, text=True, bufsize=1)

        def read_stdout():
            for line in host.stdout:
                replies.put(line)
            replies.put(None)

        threading.Thread(target=read_stdout, daemon=True).start()

        def reply(command=None):
            if command is not None:
                host.stdin.write(command + '\n'); host.stdin.flush()
            line = replies.get(timeout=15)
            if line is None or len(line) > 8192:
                raise RuntimeError('Registry host stopped or returned an invalid response; private stderr retained')
            data = json.loads(line); transcript.append({'command': command, 'response': data})
            (lab / 'host-transcript.json').write_text(json.dumps(transcript, indent=2), encoding='utf-8')
            return data

        try:
            ready = reply()
            if (ready.get('status') != 'ready' or ready.get('original_mod_code_executed') is not False or
                    ready.get('common_texture_bridge') is not True):
                raise RuntimeError('Own registry host scope differs')
            plan, packet, _, _ = read_binding(fixture / 'texture-binding-plan.json')
            digest = hashlib.sha256(packet).hexdigest()
            if ready['generation'] != plan['generation'] or ready['packet_sha256'] != digest or ready['transfer_id'] != plan['transferId']:
                raise RuntimeError('Host binding export differs from independent wire reader')
            if previous_plan is not None:
                if previous_plan['generation'] == plan['generation']:
                    raise RuntimeError('Registry generations unexpectedly match')
                for key in ('asset', 'itemType', 'item', 'archiveSha256', 'pngSha256', 'width', 'height'):
                    if previous_plan[key] != plan[key]:
                        raise RuntimeError('Stale-generation control must keep item/resource identity identical')
            before = reply('validate')
            if before.get('status') != 'active' or before.get('generation') != plan['generation'] or before.get('packet_sha256') != digest:
                raise RuntimeError('Registry binding was stale before native execution')
            blocked = reply('unload-while-active')
            if blocked.get('status') != 'unload-blocked' or blocked.get('pending_transfers') != 1:
                raise RuntimeError('Outstanding transfer did not block registry unload')
            native = None
            if not args.host_only:
                from probe_device_texture_upload import main as native_probe
                previous = sys.argv
                sys.argv = ['probe_device_texture_upload.py', '--serial', args.serial, '--lab', str(lab / 'native'),
                            '--registry-binding', str(fixture / 'texture-binding-plan.json'), '--verify-xna-wrapper',
                            '--verify-native-asset', '--verify-private-slot', '--verify-menu-overlay', '--verify-item-icon']
                if args.previous_binding:
                    sys.argv += ['--stale-registry-packet', str(args.previous_binding.resolve().parent / 'texture-binding.png.tmit')]
                try:
                    native_probe()
                finally:
                    sys.argv = previous
                native = json.loads((lab / 'native/texture-upload-result.json').read_text(encoding='utf-8'))
                if (native['phase'] != 'complete' or not native.get('content_tables_restored') or not native.get('destroy_observed') or
                        native.get('texture_transfer_id') != plan['transferId']):
                    raise RuntimeError('Native teardown must finish before registry unload')
            after = reply('validate')
            if after != before:
                raise RuntimeError('Registry generation/binding changed while native scope was active')
            completed = reply('complete ' + plan['transferId'])
            if completed.get('status') != 'teardown-acknowledged' or completed.get('pending_transfers') != 0:
                raise RuntimeError('Native teardown acknowledgement was not accepted')
            unloaded = reply('unload')
            if unloaded.get('status') != 'unloaded' or not unloaded.get('stale_binding_rejected') or unloaded.get('image_cache_resident_bytes') != 0:
                raise RuntimeError('Registry unload did not invalidate its binding')
            result = {'format': 'registry-native-texture-probe-v1', 'host_registry_generation_stable': True,
                      'host_registry_active_during_native': native is not None,
                      'packet_independently_verified': True, 'original_mod_code_executed': False,
                      'original_archive_sha256': ready['original_archive_sha256'], 'source_image_sha256': ready['original_image_sha256'],
                      'resource_archive_is_own_private_fixture': True, 'generation': plan['generation'], 'packet_sha256': digest,
                      'common_texture_bridge_verified': True,
                      'native_executed': native is not None, 'native_tables_restored': native.get('content_tables_restored') if native else None,
                      'stale_binding_rejected_after_unload': True, 'inventory_item_rendered': False,
                      'unload_blocked_while_transfer_pending': True, 'teardown_acknowledgement_matched': True,
                      'previous_generation_rejected_natively': native is not None and previous_plan is not None,
                      'source_sha256': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in [*API_SOURCES, *sources]}}
            (lab / 'registry-native-result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
            print(json.dumps({'live_host_registry_verified': True, 'native_executed': native is not None,
                              'native_teardown_before_registry_unload': native is not None,
                              'stale_binding_rejected_after_unload': True, 'original_mod_code_executed': False}))
        finally:
            if host.poll() is None:
                try:
                    host.stdin.write('quit\n'); host.stdin.flush(); host.wait(timeout=3)
                except (BrokenPipeError, subprocess.TimeoutExpired):
                    host.kill(); host.wait(timeout=3)
            host.stdin.close(); host.stdout.close()


if __name__ == '__main__':
    main()
