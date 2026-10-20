"""Temporary Unity PNG upload/readback/destruction probe on the pinned ARM64 build.

Invokes graphics methods on the main thread. Optional item-icon mode temporarily
publishes copied content tables. No restart, menu navigation, inventory or save
writes. Raw evidence is private.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import struct
import subprocess
import sys
import time
import zlib

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_LIBRARY = '9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
PACKAGE = 'com.and.games505.TerrariaPaid'


def encode_fixture(width, height, rgba):
    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))
    rows = b''.join(b'\0' + rgba[y*width*4:(y+1)*width*4] for y in range(height))
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0)) +
            chunk(b'IDAT', zlib.compress(rows)) + chunk(b'IEND', b''))


def fixture_png():
    return encode_fixture(2, 2, bytes([255, 0, 255, 255]) * 4)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--serial', required=True)
    p.add_argument('--lab', required=True, type=Path)
    p.add_argument('--port', type=int, default=27043)
    p.add_argument('--original-packet', type=Path, help='Private, pinned HelicopterParts probe packet; default is a synthetic 2x2 texture')
    p.add_argument('--registry-binding', type=Path, help='Own live-registry fixture plan; still restricted to the pinned original texture')
    p.add_argument('--own-bridge-export', type=Path, help='Fixed lab export only; caller must keep its Android registry alive')
    p.add_argument('--pinned-bridge-resource', type=Path, help='Private pinned original raw reference; requires --own-bridge-export')
    p.add_argument('--stale-registry-packet', type=Path, help='Optional previous generation packet rejection control, never submitted for graphics')
    p.add_argument('--calibrate-uv', action='store_true', help='Own 4x4 coordinate-gradient diagnostic, not original content')
    p.add_argument('--verify-xna-wrapper', action='store_true', help='Also create a temporary mobile XNA wrapper and verify its dimensions/reference')
    p.add_argument('--verify-native-asset', action='store_true', help='Also verify a standalone Asset wrapper, without installing any table entry')
    p.add_argument('--verify-private-slot', action='store_true', help='Install and restore the Asset in an unpublished one-element array using managed Array methods')
    p.add_argument('--verify-menu-overlay', action='store_true', help='Briefly draw the temporary texture in the active menu SpriteBatch and capture a private screenshot')
    p.add_argument('--verify-item-icon', action='store_true', help='Publish/restores copied item tables and draw an isolated lab item through ItemSlot.DrawItemIcon; requires original packet and overlay')
    p.add_argument('--adb', type=Path, default=Path.home() / 'AppData/Local/Android/Sdk/platform-tools/adb.exe')
    args = p.parse_args()
    if args.pinned_bridge_resource and not args.own_bridge_export:
        raise ValueError('Pinned reference requires the explicit lab bridge export')
    lab = args.lab.resolve()
    if lab.is_relative_to(ROOT) or not 1 <= args.port <= 65535:
        raise ValueError('Private lab and loopback port required')
    lab.mkdir(parents=True, exist_ok=True)
    def adb(*words):
        r = subprocess.run([str(args.adb), '-s', args.serial, *words], capture_output=True, timeout=25)
        if r.returncode:
            (lab / 'adb-error.txt').write_bytes(r.stdout + r.stderr)
            raise RuntimeError('ADB command failed; private details saved')
        return r.stdout.decode('utf-8', 'replace').strip()
    if adb('get-state') != 'device':
        raise RuntimeError('Authorized USB target required')
    pid = adb('shell', 'pidof', PACKAGE)
    if not pid.isdigit():
        raise RuntimeError('One existing game process required; no restart performed')
    sys.path.insert(0, str(ROOT / '.tools/frida-deps'))
    import frida
    session = frida.get_device_manager().add_remote_device('127.0.0.1:' + str(args.port)).attach(int(pid))
    script = None
    messages = []
    try:
        source = ((ROOT / 'runtime/texture-packet.js').read_text(encoding='utf-8') + '\n' +
                  (ROOT / 'runtime/texture-slot-lease.js').read_text(encoding='utf-8') + '\n' +
                  (ROOT / 'runtime/content-table-lease.js').read_text(encoding='utf-8') + '\n' +
                  (ROOT / 'runtime/native-content-table-scope.js').read_text(encoding='utf-8') + '\n' +
                  (ROOT / 'runtime/item-icon-preview.js').read_text(encoding='utf-8') + '\n' +
                  (ROOT / 'runtime/texture-menu-overlay.js').read_text(encoding='utf-8') + '\n' +
                  (ROOT / 'runtime/texture-upload-probe.js').read_text(encoding='utf-8'))
        script = session.create_script(source)
        script.on('message', lambda message, data: messages.append(message))
        script.load()
        info = script.exports_sync.moduleinfo()
        path = info['library_path']
        if info['architecture'] != 'arm64' or info['pointer_size'] != 8 or not path.startswith('/') or not path.endswith('/libil2cpp.so') or '!' in path:
            raise RuntimeError('Direct native ARM64 library identity required')
        command = 'sha256sum ' + shlex.quote(path)
        digest = adb('shell', 'su', '-c', shlex.quote(command)).split()[0]
        if digest != EXPECTED_LIBRARY:
            raise RuntimeError('Pinned library hash differs; GPU probe not started')
        if sum(bool(v) for v in (args.original_packet, args.registry_binding, args.own_bridge_export, args.calibrate_uv)) > 1:
            raise ValueError('Select one original packet, registry fixture or coordinate calibration')
        png = fixture_png(); width = height = 2; sample = [1, 0, 1, 1]; kind = 'synthetic-magenta'; uv = [0.5, 0.5]; extra = []
        if args.calibrate_uv:
            width = height = 4
            rgba = bytes(channel for y in range(4) for x in range(4) for channel in (x*85, y*85, 0, 255))
            png = encode_fixture(width, height, rgba); sample = [2/3, 1/3, 0, 1]; kind = 'own-coordinate-gradient'
        registry_plan = None; registry_packet = None
        if args.original_packet or args.registry_binding or args.own_bridge_export:
            from probe_sots_item_defaults import verify_png, verify_texture_packet, IMAGE_SHA, TMOD_SHA
            if args.own_bridge_export:
                from texture_bridge_fixture import read_export
                from texture_lab_profiles import OWN, PINNED
                registry_plan, registry_packet, png, raw = read_export(args.own_bridge_export,
                    PINNED if args.pinned_bridge_resource else OWN, args.pinned_bridge_resource)
            elif args.registry_binding:
                from registry_texture_binding import read_binding
                registry_plan, registry_packet, png, raw = read_binding(args.registry_binding)
            else:
                raw = args.original_packet.with_name('original-item.rawimg').read_bytes()
            if not args.own_bridge_export and hashlib.sha256(raw).hexdigest() != IMAGE_SHA:
                raise ValueError('Pinned original raw image differs')
            version, width, height = struct.unpack_from('<iii', raw)
            if version != 1 or not 1 <= width <= 256 or not 1 <= height <= 256:
                raise ValueError('Original image dimensions outside diagnostic scope')
            if args.original_packet:
                png = args.original_packet.with_name('original-item.png').read_bytes()
                verify_png(png, width, height, raw[12:])
                verify_texture_packet(args.original_packet.read_bytes(), 'SOTS/Items/HelicopterParts.rawimg', TMOD_SHA, png, width, height)
            # The separate 4x4 device calibration establishes u*width, v*height
            # pixel-space sampling with PNG top rows mapped to Unity's top rows.
            checks = []; seen = set()
            coordinates = [(width//2, height//2)] + [(x, y) for y in range(height) for x in range(width)]
            for x, y in coordinates:
                pixel = tuple(raw[12+(y*width+x)*4:16+(y*width+x)*4])
                if pixel in seen: continue
                seen.add(pixel)
                checks.append({'uv': [x/width, (height-1-y)/height], 'rgba': [v/255 for v in pixel]})
                if len(checks) == 8: break
            uv = checks[0]['uv']; sample = checks[0]['rgba']; extra = checks[1:]
            kind = ('pinned-original-android-registry' if args.pinned_bridge_resource else 'own-2x2-android-registry') if args.own_bridge_export else 'pinned-SOTS-HelicopterParts'
        (lab / 'diagnostic.png').write_bytes(png)
        if args.verify_native_asset and not args.verify_xna_wrapper:
            raise ValueError('Native Asset check requires --verify-xna-wrapper')
        if args.verify_private_slot and not args.verify_native_asset:
            raise ValueError('Private slot check requires --verify-native-asset')
        if args.verify_menu_overlay and not args.verify_private_slot:
            raise ValueError('Menu overlay requires --verify-private-slot')
        if args.verify_item_icon and (not args.verify_menu_overlay or not (args.original_packet or args.registry_binding or args.own_bridge_export)):
            raise ValueError('Item icon requires overlay and a pinned original/registry packet')
        if (args.registry_binding or args.own_bridge_export) and not args.verify_item_icon:
            raise ValueError('Live registry fixture requires the isolated item-icon scope')
        if args.stale_registry_packet and not args.registry_binding:
            raise ValueError('Stale registry control requires a current registry binding')
        packet_controls = []
        if args.original_packet or args.registry_binding or args.own_bridge_export:
            packet_bytes = list(registry_packet if (args.registry_binding or args.own_bridge_export) else args.original_packet.read_bytes())
            plan = registry_plan if (args.registry_binding or args.own_bridge_export) else dict(asset='SOTS/Items/HelicopterParts.rawimg', generation='13fb5666-8cf1-4941-acf8-8d54eff30d10',
                                                                  archiveSha256=TMOD_SHA, pngSha256=hashlib.sha256(png).hexdigest())
            # The plan is independent of the incoming packet: either the pinned
            # old fixture or the own live-registry host's exported binding.
            controls = [('generation', '00000001-0000-0000-0000-000000000000'),
                        ('archiveSha256', '00'*32), ('asset', 'Own/Other.rawimg')]
            if args.registry_binding or args.own_bridge_export:
                controls += [('transferId', '00000000-0000-0000-0000-000000000000'), ('itemType', 6197)]
            for field, value in controls:
                try:
                    script.exports_sync.checkpacket(packet_bytes, {**plan, field: value})
                except frida.core.RPCException:
                    packet_controls.append(field)
                else:
                    raise RuntimeError('Native receiver accepted a mismatched packet identity')
            damaged = packet_bytes.copy(); damaged[-1] ^= 1
            try:
                script.exports_sync.checkpacket(damaged, plan)
            except frida.core.RPCException:
                packet_controls.append('corrupted_payload')
            else:
                raise RuntimeError('Native receiver accepted a damaged payload')
            if args.stale_registry_packet:
                if args.stale_registry_packet.resolve().is_relative_to(ROOT) or args.stale_registry_packet.stat().st_size > 65536 + 613:
                    raise ValueError('Private bounded previous packet required')
                stale = list(args.stale_registry_packet.read_bytes())
                try:
                    script.exports_sync.checkpacket(stale, plan)
                except frida.core.RPCException:
                    packet_controls.append('previous_registry_generation')
                else:
                    raise RuntimeError('Native receiver accepted the previous registry generation')
            if script.exports_sync.status()['phase'] != 'idle':
                raise RuntimeError('Packet rejection reached graphics setup')
            script.exports_sync.beginpacket(packet_bytes, plan, sample, uv, extra, args.verify_xna_wrapper,
                                            args.verify_native_asset, args.verify_private_slot, args.verify_menu_overlay, args.verify_item_icon)
        else:
            script.exports_sync.begin(list(png), width, height, sample, uv, extra, args.verify_xna_wrapper,
                                      args.verify_native_asset, args.verify_private_slot, args.verify_menu_overlay, False, None)
        deadline = time.monotonic() + 45
        screenshot_taken = False; screenshot_attempted = False; capture_error = None
        while True:
            report = script.exports_sync.status()
            if args.verify_menu_overlay and not screenshot_attempted and report.get('menu_overlay_draw_calls', 0) >= 3 and report['phase'] == 'private-slot-held':
                screenshot_attempted = True
                try:
                    activity = adb('shell', 'dumpsys', 'activity', 'activities')
                    resumed = [line for line in activity.splitlines() if 'mResumedActivity' in line or 'topResumedActivity' in line]
                    if not resumed or not all(PACKAGE + '/' in line for line in resumed):
                        raise RuntimeError('Game is not foreground; no screen captured')
                    capture = subprocess.run([str(args.adb), '-s', args.serial, 'exec-out', 'screencap', '-p'],
                                             capture_output=True, timeout=20, check=True)
                    if not capture.stdout.startswith(b'\x89PNG\r\n\x1a\n'):
                        raise RuntimeError('Invalid private game screenshot')
                    (lab / ('item-icon.png' if args.verify_item_icon else 'menu-overlay.png')).write_bytes(capture.stdout)
                    screenshot_taken = True
                except Exception as error:
                    # Still wait for normal game-thread teardown before detaching.
                    capture_error = str(error)
            if report['phase'] in ('complete', 'failed', 'cleanup-failed') or time.monotonic() >= deadline:
                break
            time.sleep(0.2)
        report.update(library_sha256=digest, script_sha256=hashlib.sha256(source.encode()).hexdigest(),
                      fixture_sha256=hashlib.sha256(png).hexdigest(), serial=args.serial, pid=int(pid),
                      fixture_kind=kind, expected_center_rgba=sample, inventory_item_rendered=False,
                      sample_uv=uv, additional_reference_samples=extra,
                      rejected_packet_controls=packet_controls,
                      menu_overlay_screenshot_captured=screenshot_taken, menu_overlay_visually_reviewed=False,
                      screenshot_error=capture_error,
                      scope=('Temporary copied-table publication and isolated item icon; no inventory/world/save writes' if args.verify_item_icon else
                             'Temporary texture/private Asset array/optional short menu overlay; no game content-table install or saves'))
        (lab / 'texture-upload-result.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
        (lab / 'frida-messages.json').write_text(json.dumps(messages, indent=2), encoding='utf-8')
        if report['phase'] != 'complete' or not all(report[k] for k in ('menu_only_verified', 'png_loaded', 'dimensions_verified', 'color_verified', 'destroy_requested', 'destroy_observed', 'hook_detached')):
            raise RuntimeError('GPU probe incomplete; inspect private result before further tests')
        if args.verify_xna_wrapper and not all(report.get(k) for k in ('xna_wrapper_created', 'xna_dimensions_verified', 'xna_texture_reference_verified')):
            raise RuntimeError('Mobile XNA wrapper verification incomplete')
        if args.verify_native_asset and not all(report.get(k) for k in ('asset_loaded_verified', 'asset_value_verified', 'asset_disposal_verified')):
            raise RuntimeError('Native Asset verification incomplete')
        if args.verify_private_slot and (not all(report.get(k) for k in ('private_slot_install_verified', 'private_slot_restore_verified')) or
                                         report.get('private_slot_frames_verified', 0) < 2):
            raise RuntimeError('Private Asset slot lease verification incomplete')
        expected_controls = 4 + (2 if (args.registry_binding or args.own_bridge_export) else 0) + (1 if args.stale_registry_packet else 0)
        if (args.original_packet or args.registry_binding or args.own_bridge_export) and (not report.get('texture_packet_verified') or len(packet_controls) != expected_controls):
            raise RuntimeError('Native packet receiver verification incomplete')
        if args.verify_menu_overlay and (not screenshot_taken or not report.get('menu_overlay_submission_verified') or
                                        not report.get('menu_overlay_hook_detached')):
            raise RuntimeError('Menu overlay submission/capture/cleanup incomplete')
        if args.verify_item_icon and (report.get('content_tables_installed') != 129 or not report.get('content_tables_restored') or
                                     report.get('item_icon_type') != 6196 or report.get('item_icon_calls', 0) < 3 or
                                     report.get('item_icon_queued_texture_matches', 0) < report.get('item_icon_calls', 0) or
                                     not report.get('item_icon_queue_transition_verified') or not report.get('item_icon_roots_released')):
            raise RuntimeError('Item icon/table scope verification incomplete')
        if adb('shell', 'pidof', PACKAGE) != pid:
            raise RuntimeError('Game process changed during probe')
        print(json.dumps({'unity_texture_load_verified': True, 'dimensions': [width, height],
                          'sample_rgba': report['sample_rgba'], 'destruction_observed': True,
                          'color_checks': len(report['samples']),
                          'xna_wrapper_verified': bool(report.get('xna_dimensions_verified') and report.get('xna_texture_reference_verified')),
                          'native_asset_verified': bool(report.get('asset_loaded_verified') and report.get('asset_disposal_verified')),
                          'private_slot_lease_verified': bool(report.get('private_slot_install_verified') and report.get('private_slot_restore_verified')),
                          'private_slot_frames_verified': report.get('private_slot_frames_verified', 0),
                          'texture_packet_verified': bool(report.get('texture_packet_verified')),
                          'rejected_packet_controls': len(packet_controls),
                          'menu_overlay_submitted': bool(report.get('menu_overlay_submission_verified')),
                          'menu_overlay_screenshot_captured': screenshot_taken,
                          'content_tables_changed': report['content_tables_changed'],
                          'content_tables_restored': bool(report.get('content_tables_restored')),
                          'isolated_item_icon_verified': bool(args.verify_item_icon and report.get('item_icon_queued_texture_matches')),
                          'inventory_item_rendered': False, 'saves_accessed': False}))
    finally:
        try:
            if script is not None:
                from device_texture_teardown import teardown
                final = teardown(script)
                (lab / 'teardown-result.json').write_text(json.dumps(final, indent=2), encoding='utf-8')
        finally:
            session.detach()


if __name__ == '__main__':
    main()
