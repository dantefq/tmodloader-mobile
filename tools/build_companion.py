"""Build a same-certificate Android instrumentation companion, without changing Terraria."""
import argparse
import json
import lzma
from pathlib import Path
import re
import shutil
import subprocess
import zipfile
from apk_format import sha256

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = '1f8e2ba7ddabaee961a1b2552d44bc0c281c9b5122480642b018779bcbf2fe8e'


def run(command):
    result = subprocess.run(list(map(str, command)), capture_output=True, text=True,
                            encoding='utf-8', errors='replace', timeout=120)
    if result.returncode:
        raise RuntimeError(result.stdout + '\n' + result.stderr)
    return result.stdout


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for option in ('sdk', 'jdk', 'lab', 'source', 'gadget', 'key', 'cert'):
        p.add_argument('--'+option, type=Path, required=True)
    p.add_argument('--managed-runtime',type=Path)
    p.add_argument('--managed-assembly',type=Path)
    p.add_argument('--managed-bundle',type=Path)
    p.add_argument('--variant',choices=('standard','emulator-check','api-demo','content-recon','moditem-demo','unified-moditem-demo','sleep-demo','unified-sleep-demo','combined-demo','respawn-demo'),default='standard')
    args = p.parse_args()
    if args.managed_bundle and args.managed_assembly: raise ValueError('Choose one managed demo source')
    managed=bool(args.managed_runtime and (args.managed_assembly or args.managed_bundle))
    if bool(args.managed_runtime)!=bool(args.managed_assembly or args.managed_bundle): raise ValueError('Supply managed runtime and one own demo source')
    combined=args.variant=='combined-demo'
    respawn=args.variant=='respawn-demo'
    unified=args.variant=='unified-moditem-demo'
    unified_time=args.variant in ('unified-sleep-demo','combined-demo')
    sleep=args.variant in ('sleep-demo','unified-sleep-demo','combined-demo')
    crypto=unified or unified_time or respawn
    moditem=args.variant in ('moditem-demo','unified-moditem-demo','combined-demo')
    if bool(args.managed_bundle)!=(args.variant in ('api-demo','moditem-demo','unified-moditem-demo','sleep-demo','unified-sleep-demo','combined-demo','respawn-demo')): raise ValueError('Use an API demo variant for the own API bundle')
    if args.managed_bundle:
        contract=json.loads((args.managed_bundle/'demo-contract.json').read_text())
        mode=contract['mode']
        if mode!=('respawn-snapshot' if respawn else 'time-rate' if sleep else 'mod-item' if moditem else 'global-item'): raise ValueError('Bundle mode does not match companion variant')
        revision='managed-foundation-v2' if unified_time else 'managed-foundation-v1' if unified else None
        if contract.get('api_revision')!=revision: raise ValueError('API revision does not match companion variant')
    if sha256(args.source) != EXPECTED:
        raise ValueError('Reinvestigate changed target APK first')
    sdk = args.sdk/'build-tools/36.0.0'
    jar = args.sdk/'platforms/android-35/android.jar'
    java = args.jdk/'bin/java.exe'
    signer = sdk/'lib/apksigner.jar'
    def cert(apk):
        lines = run([java, '-jar', signer, 'verify', '--print-certs', apk])
        matches = re.findall(r'Signer #\d+ certificate SHA-256 digest: ([0-9a-f]{64})', lines)
        if len(matches) != 1: raise ValueError('Expected one verified signer')
        return matches[0]
    target_cert = cert(args.source)
    # This route is only for this user's existing publicly development-signed repack.
    if target_cert != 'a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc':
        raise ValueError('No matching development certificate for this target')
    info = json.loads((ROOT/'reports/dependencies.json').read_text(encoding='utf-8-sig'))
    if 'sha256:'+sha256(args.gadget) != info['digest']: raise ValueError('Gadget checksum differs')
    lab = args.lab.resolve()/('respawn-companion' if respawn else 'combined-companion' if combined else 'unified-sleep-companion' if unified_time else 'unified-moditem-companion' if unified else 'sleep-companion' if sleep else 'moditem-companion' if moditem else 'content-recon' if args.variant=='content-recon' else 'api-companion' if args.variant=='api-demo' else 'companion-emulator-check' if args.variant=='emulator-check' else 'companion-managed' if managed else 'companion')
    if lab.is_relative_to(ROOT): raise ValueError('Native dependency output must stay outside source repo')
    lab.mkdir(parents=True, exist_ok=True)
    classes, dex, assets = [lab/name for name in ('classes', 'dex', 'assets')]
    for folder in (classes, dex, assets/'tmloader'): folder.mkdir(parents=True, exist_ok=True)
    assets.joinpath('tmloader/CopperSwordDemo.json').write_bytes((ROOT/'mods/CopperSwordDemo.json').read_bytes())
    natives={}; java_dependencies=[]
    if managed:
        dependency=json.loads((ROOT/'reports/mono-runtime-dependency.json').read_text())
        if sha256(args.managed_runtime)!=dependency['sha256']: raise ValueError('Mono package checksum differs')
        if args.managed_assembly:
            probe=json.loads((ROOT/'reports/managed-probe-build.json').read_text())
            if sha256(args.managed_assembly)!=probe['own_assembly_sha256']: raise ValueError('Use the verified own probe assembly')
        else:
            stem='respawn' if respawn else 'unified-sleep' if unified_time else 'unified-moditem' if unified else 'sleep' if sleep else 'moditem' if moditem else 'api'
            probe=json.loads((ROOT/'reports'/('shorter-respawn-android-validation.json' if respawn else f'{stem}-probe-validation.json')).read_text())
            build=json.loads((ROOT/'reports'/f'{stem}-demo-build.json').read_text())
            if respawn:
                probe_build=json.loads((ROOT/'reports/respawn-probe-build.json').read_text())
                if (probe['status']!='verified-original-respawn-callbacks-on-android-snapshots'
                    or probe['managed_files_sha256']!=build['files']
                    or probe['installed_apk_sha256']!=probe_build['sha256']
                    or probe_build['sha256']!=sha256(Path(probe_build['apk']))
                    or probe['result']['callbacks'].get('live_snapshot_checks')!=8
                    or len(probe['result'].get('nativeJsonAfterGc',[]))!=4
                    or probe['result'].get('nativeJsonGcBytes')!=16777216):
                    raise ValueError('Verify identical original respawn DLL and native JSON bridge on Android first')
            elif sleep:
                if probe['status']!='original-local-mod-executed-in-isolated-android-probe' or not probe['device_dll_hash_matched'] or probe['files']!=build['files'] or probe['mod_dll_sha256']!=build['files']['ChangeSleepTime.dll'] or probe['probe_apk_sha256']!=sha256(Path(json.loads((ROOT/'reports'/f'{stem}-probe-build.json').read_text())['apk'])):
                    raise ValueError('Verify identical audited mod in isolated probe first')
            elif probe['status']!='verified' or probe['files']!=build['files']: raise ValueError('Verify identical own API bundle in isolated probe first')
            if unified:
                probe_build=json.loads((ROOT/'reports/unified-moditem-probe-build.json').read_text())
                if (not probe['device_bundle_hashes_matched'] or not probe['installed_probe_apk_hash_matched']
                    or probe['result']['foundationChecks']!=8 or probe['api_revision']!='managed-foundation-v1'
                    or probe['probe_apk_sha256']!=sha256(Path(probe_build['apk']))):
                    raise ValueError('Verify identical unified API and probe APK on Android first')
            if unified_time:
                probe_build=json.loads((ROOT/'reports/unified-sleep-probe-build.json').read_text())
                if (not probe['device_bundle_hashes_matched'] or not probe['installed_probe_apk_hash_matched']
                    or probe['lifecycleChecks']!=7 or probe['contentChecks']!=14 or probe['api_revision']!='managed-foundation-v2'):
                    raise ValueError('Verify unified time lifecycle and content on Android first')
        target=assets/'managed';target.mkdir(exist_ok=True)
        with zipfile.ZipFile(args.managed_runtime) as archive:
            for name in archive.namelist():
                if name.startswith('runtimes/android-arm64/') and name.endswith('.dll'):
                    (target/Path(name).name).write_bytes(archive.read(name))
                if name.startswith('runtimes/android-arm64/native/') and name.endswith('.so'):
                    natives[Path(name).name]=archive.read(name)
            for name in ('LICENSE.TXT','THIRD-PARTY-NOTICES.TXT'):
                (target/name).write_bytes(archive.read(name))
            if crypto:
                crypto_jar=lab/'libSystem.Security.Cryptography.Native.Android.jar'
                crypto_jar.write_bytes(archive.read('runtimes/android-arm64/native/'+crypto_jar.name))
                if sha256(crypto_jar)!=probe_build['cryptography_java_jar_sha256']: raise ValueError('Crypto Java dependency differs from probe')
                java_dependencies.append(crypto_jar)
        if args.managed_bundle:
            from api_bundle import copy_bundle
            copy_bundle(args.managed_bundle,target)
        else: shutil.copyfile(args.managed_assembly,target/'TerrariaMobile.ManagedDemo.dll')
    sources = sorted((ROOT/'android/instrumentation').rglob('*.java'))+sorted((ROOT/'android/shared').rglob('*.java'))
    run([args.jdk/'bin/javac.exe', '--release', '8', '-encoding', 'UTF-8', '-cp', jar, '-d', classes, *sources])
    run([java, '-cp', sdk/'lib/d8.jar', 'com.android.tools.r8.D8', '--lib', jar, '--min-api', '23', '--output', dex, *sorted(classes.rglob('*.class')), *java_dependencies])
    unsigned, aligned, output = [lab/name for name in ('unsigned.apk', 'aligned.apk', 'Terraria-Mobile-Mods-Managed-Companion.apk' if managed else 'Terraria-Mobile-Mods-Companion.apk')]
    run([sdk/'aapt.exe', 'package', '-f', '-M', ROOT/'android/instrumentation/AndroidManifest.xml', '-I', jar, '-A', assets, '-F', unsigned])
    with zipfile.ZipFile(unsigned, 'a') as apk:
        apk.writestr('classes.dex', (dex/'classes.dex').read_bytes())
        apk.writestr('lib/arm64-v8a/libfridagadget.so', lzma.decompress(args.gadget.read_bytes()), compress_type=zipfile.ZIP_STORED)
        apk.writestr('lib/arm64-v8a/libfridagadget.config.so', json.dumps({'interaction': {'type': 'script', 'path': 'libtmloader.js.so', 'on_change': 'ignore'}, 'runtime': 'qjs'}), compress_type=zipfile.ZIP_STORED)
        script=(ROOT/'runtime/managed-host.js').read_bytes()+b'\n'+(ROOT/'runtime/loader.js').read_bytes() if managed else (ROOT/'runtime/loader.js').read_bytes()
        if sleep: script=b'\n'.join((ROOT/name).read_bytes() for name in ('runtime/managed-time-host.js','runtime/sleep-scene.js','runtime/time-loader.js'))
        if moditem: script=b'globalThis.TMALContentDelayUntil=Date.now()+15000;\n'+script
        if args.variant=='content-recon': script+=b'\n'+(ROOT/'runtime/content-recon.js').read_bytes()
        if moditem: script+=b'\n'+(ROOT/'runtime/save-trace.js').read_bytes()+b'\n'+(ROOT/'runtime/content-sidecar.js').read_bytes()+b'\n'+(ROOT/'runtime/moditem-content.js').read_bytes()
        script+=b'\n'+(ROOT/'runtime/lab-protection.js').read_bytes()
        if combined:
            from companion_script import combined_script
            script=combined_script(ROOT)
        if respawn:
            script=b'\n'.join((ROOT/'runtime'/name).read_bytes() for name in (
                'mono-runtime.js','managed-respawn-host.js','respawn-clamp-lease.js','respawn-loader.js','lab-protection.js'))
        apk.writestr('lib/arm64-v8a/libtmloader.js.so', script, compress_type=zipfile.ZIP_STORED)
        for name,data in natives.items(): apk.writestr('lib/arm64-v8a/'+name,data,compress_type=zipfile.ZIP_STORED)
    run([sdk/'zipalign.exe', '-P', '16', '-f', '4', unsigned, aligned])
    run([java, '-jar', signer, 'sign', '--key', args.key, '--cert', args.cert, '--out', output, aligned])
    if cert(output) != target_cert: raise ValueError('Companion signature differs from target')
    run([sdk/'zipalign.exe', '-c', '-P', '16', '4', output])
    if sha256(args.source) != EXPECTED: raise ValueError('Target changed unexpectedly')
    report = {'status': 'built-runtime-unverified', 'apk': str(output), 'output_sha256': sha256(output),
              'target_apk_unchanged': True, 'target_apk_sha256': EXPECTED,
              'signature_verified': True, 'matching_target_certificate': target_cert,
              'game_protection_code_modified': False, 'in_game_verified': False, 'pc_tmod_supported': False}
    report['managed_runtime_included']=managed
    if managed: report['own_assembly_sha256']=sha256(assets/'managed/TerrariaMobile.ManagedDemo.dll')
    if args.managed_bundle: report['own_api_bundle_files']=build['files']
    report['variant']=args.variant
    if unified: report['api_revision']='managed-foundation-v1';report['cryptography_java_jar_sha256']=sha256(crypto_jar)
    if unified_time: report['api_revision']='managed-foundation-v2';report['cryptography_java_jar_sha256']=sha256(crypto_jar);report['native_item_bridge_included']=False
    if combined:
        report['native_item_bridge_included']=True
        report['shared_mono_bootstrap_included']=True
    if respawn:
        report['cryptography_java_jar_sha256']=sha256(crypto_jar)
        report['experimental_respawn_bridge_included']=True
        report['snapshot_api_isolated_from_item_time_api']=True
        report['contains_user_owned_third_party_mod']=True
        report['private_lab_only']=True
    if sleep: report['contains_user_owned_third_party_mod']=True;report['private_lab_only']=True
    # Preserve the manifest beside each private build when the rolling report
    # in the checkout is replaced by a later build.
    (lab/'companion-build.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    (ROOT/'reports'/('respawn-companion-build.json' if respawn else 'combined-companion-build.json' if combined else 'unified-sleep-companion-build.json' if unified_time else 'unified-moditem-companion-build.json' if unified else 'sleep-companion-build.json' if sleep else 'moditem-companion-build.json' if moditem else 'content-recon-build.json' if args.variant=='content-recon' else 'api-companion-build.json' if args.variant=='api-demo' else 'emulator-companion-build.json' if args.variant=='emulator-check' else 'managed-companion-build.json' if managed else 'companion-build-report.json')).write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__': main()
