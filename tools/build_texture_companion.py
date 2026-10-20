"""Package the exact own Android-tested texture runtime in a separate companion.

No original mod DLL, game implementation or Gadget is bundled. External authorized
ADB/loopback Frida controls the laboratory. Existing companion variants remain
untouched. The target must match the already researched development-signed APK.
"""
import argparse
import json
from pathlib import Path
import re
import zipfile

from build_companion import run, EXPECTED
from build_texture_bridge_probe import sha

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('sdk', 'jdk', 'lab', 'key', 'cert', 'source', 'probe-build', 'probe-validation'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    lab = args.lab.resolve(); probe = args.probe_build.resolve()
    if lab.exists() or lab.is_relative_to(ROOT) or probe.is_relative_to(ROOT) or args.probe_validation.resolve().is_relative_to(ROOT):
        raise ValueError('New private build and private validated probe inputs required')
    if sha(args.source) != EXPECTED: raise ValueError('Pinned target APK differs')
    build = json.loads((probe / 'build.json').read_text('utf-8'))
    evidence = json.loads(args.probe_validation.read_text('utf-8'))
    apk = probe / 'Texture-Bridge-Probe.apk'
    if (sha(apk) != build['apk_sha256'] or evidence.get('apk_sha256') != build['apk_sha256'] or
            evidence.get('status') != 'verified-android-registry-to-native-game-lab' or
            evidence.get('own_managed_files_matched') is not True or evidence.get('game_health_verified') is not True):
        raise ValueError('Exact own Android-tested probe/managed files required')
    for name, digest in build['source_sha256'].items():
        if sha(ROOT / name) != digest: raise ValueError('Probe source changed since Android test: ' + name)
    if set(build['files']) != {'TerrariaMobile.ManagedDemo.dll', 'tModLoader.dll'}:
        raise ValueError('Unexpected managed fixture files')
    lab.mkdir(parents=True)
    sdk = args.sdk / 'build-tools/36.0.0'; android = args.sdk / 'platforms/android-35/android.jar'
    java = args.jdk / 'bin/java.exe'; signer = sdk / 'lib/apksigner.jar'
    def certificate(path):
        matches = re.findall(r'Signer #\d+ certificate SHA-256 digest: ([0-9a-f]{64})',
                             run([java, '-jar', signer, 'verify', '--print-certs', path]))
        if len(matches) != 1: raise ValueError('One verified signing certificate required')
        return matches[0]
    target_cert = certificate(args.source)
    if target_cert != 'a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc':
        raise ValueError('Only the researched development-signed target is supported')
    assets = lab / 'assets/managed'; assets.mkdir(parents=True)
    natives = {}
    with zipfile.ZipFile(apk) as archive:
        for name in archive.namelist():
            if name.startswith('assets/managed/') and not name.endswith('/'):
                part = Path(name).name
                if not re.fullmatch('[A-Za-z0-9_.-]+', part): raise ValueError('Unexpected runtime filename')
                (assets / part).write_bytes(archive.read(name))
            if name.startswith('lib/arm64-v8a/') and name.endswith('.so'):
                natives[Path(name).name] = archive.read(name)
    for name, digest in build['files'].items():
        if sha(assets / name) != digest: raise ValueError('Copied own managed file differs')
    crypto = probe / 'libSystem.Security.Cryptography.Native.Android.jar'
    if sha(crypto) != build['cryptography_java_jar_sha256']: raise ValueError('Pinned crypto Java helper differs')
    classes = lab / 'classes'; classes.mkdir(); dex = lab / 'dex'; dex.mkdir()
    sources = sorted((ROOT / 'android/texture-companion').rglob('*.java'))
    run([args.jdk / 'bin/javac.exe', '--release', '8', '-encoding', 'UTF-8', '-cp', android, '-d', classes, *sources])
    run([java, '-cp', sdk / 'lib/d8.jar', 'com.android.tools.r8.D8', '--lib', android, '--min-api', '23',
         '--output', dex, *sorted(classes.rglob('*.class')), crypto])
    unsigned = lab / 'unsigned.apk'; aligned = lab / 'aligned.apk'; output = lab / 'Texture-Bridge-Companion.apk'
    run([sdk / 'aapt.exe', 'package', '-f', '-M', ROOT / 'android/texture-companion/AndroidManifest.xml', '-I', android,
         '-A', lab / 'assets', '-F', unsigned])
    with zipfile.ZipFile(unsigned, 'a') as archive:
        archive.writestr('classes.dex', (dex / 'classes.dex').read_bytes())
        for name, data in natives.items(): archive.writestr('lib/arm64-v8a/' + name, data, compress_type=zipfile.ZIP_STORED)
    run([sdk / 'zipalign.exe', '-P', '16', '-f', '4', unsigned, aligned])
    run([java, '-jar', signer, 'sign', '--key', args.key, '--cert', args.cert, '--out', output, aligned])
    if certificate(output) != target_cert: raise ValueError('Companion and target signing certificates differ')
    run([sdk / 'zipalign.exe', '-c', '-P', '16', '4', output])
    if sha(args.source) != EXPECTED: raise ValueError('Target unexpectedly changed')
    report = {'format': 'tmal-texture-companion-build-v1', 'status': 'built-in-process-unverified',
              'apk_sha256': sha(output), 'target_apk_sha256': EXPECTED, 'signing_certificate_sha256': target_cert,
              'managed_files': build['files'], 'probe_apk_sha256': build['apk_sha256'],
              'probe_script_sha256': build['script_sha256'], 'game_apk_modified': False,
              'bootstrap_order': 'mono-before-unity',
              'resource_profile': build.get('resource_profile', 'own-2x2'), 'resource_files': build.get('resource_files', {}),
              'original_texture_data_bundled': bool(build.get('resource_files')),
              'fixture_scope': 'Fixed lab image profile only; not inventory/gameplay or original mod execution',
              'source_sha256': {p.relative_to(ROOT).as_posix(): sha(p) for p in
                  [ROOT / 'android/texture-companion/AndroidManifest.xml', *sources]}}
    (lab / 'build.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({'status': report['status'], 'apk_sha256': report['apk_sha256'], 'matching_target_certificate': True,
                      'exact_android_tested_managed_files': True, 'game_apk_modified': False}))


if __name__ == '__main__': main()
