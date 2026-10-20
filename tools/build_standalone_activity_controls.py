"""Build private inert DEX / Activity controls; no loader and no device access."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

from apk_format import replace_activity, sha256
from build_standalone_controls import ROOT, SOURCE_SHA, payloads, run, signer, signing_entry

ACTIVITY = 'tm.loader.ControlActivity'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'lab', 'sdk', 'jdk', 'key', 'cert'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    source, lab = args.source.resolve(), args.lab.resolve()
    if lab == ROOT or lab.is_relative_to(ROOT) or source.is_relative_to(lab):
        raise ValueError('Use a private lab separate from source/repository')
    if lab.exists():
        raise ValueError('Refusing to overwrite prior evidence')
    if sha256(source) != SOURCE_SHA:
        raise ValueError('Unexpected source APK')
    sdk = args.sdk / 'build-tools/36.0.0'
    java = args.jdk / 'bin/java.exe'
    javac = args.jdk / 'bin/javac.exe'
    android_jar = args.sdk / 'platforms/android-35/android.jar'
    prefix = [java, '-jar', sdk / 'lib/apksigner.jar']
    certificate = signer(run(prefix + ['verify', '--print-certs', source]))
    baseline = payloads(source)
    if 'classes2.dex' in baseline:
        raise ValueError('Source already contains secondary DEX')
    for name in ('stubs', 'classes', 'dex'):
        (lab / name).mkdir(parents=True)
    run([javac, '--release', '8', '-cp', android_jar, '-d', lab / 'stubs',
         ROOT / 'android/stubs/com/unity3d/player/UnityPlayerActivity.java'])
    import os
    run([javac, '--release', '8', '-cp', str(android_jar) + os.pathsep + str(lab / 'stubs'),
         '-d', lab / 'classes', ROOT / 'android/control/tm/loader/ControlActivity.java'])
    run([java, '-cp', sdk / 'lib/d8.jar', 'com.android.tools.r8.D8', '--lib', android_jar,
         '--classpath', lab / 'stubs', '--min-api', '23', '--output', lab / 'dex',
         lab / 'classes/tm/loader/ControlActivity.class'])
    dex = (lab / 'dex/classes.dex').read_bytes()
    controls = []
    for variant in ('repacked-only', 'dex-only', 'activity-only'):
        staging, aligned, output = [lab / (variant + suffix) for suffix in ('-input.apk', '-aligned.apk', '.apk')]
        manifest = None
        with zipfile.ZipFile(source) as original, zipfile.ZipFile(staging, 'w') as target:
            for item in original.infolist():
                if signing_entry(item.filename):
                    continue
                content = original.read(item)
                if variant == 'activity-only' and item.filename == 'AndroidManifest.xml':
                    manifest = content = replace_activity(content, ACTIVITY)
                target.writestr(item, content)
            if variant != 'repacked-only':
                target.writestr('classes2.dex', dex, compress_type=zipfile.ZIP_STORED)
        run([sdk / 'zipalign.exe', '-P', '16', '-f', '4', staging, aligned])
        run(prefix + ['sign', '--key', args.key, '--cert', args.cert, '--out', output, aligned])
        verification = run(prefix + ['verify', '--verbose', '--print-certs', output])
        if signer(verification) != certificate:
            raise ValueError('Certificate differs')
        expected = dict(baseline)
        if variant != 'repacked-only':
            expected['classes2.dex'] = hashlib.sha256(dex).hexdigest()
        if manifest is not None:
            expected['AndroidManifest.xml'] = hashlib.sha256(manifest).hexdigest()
        if payloads(output) != expected:
            raise ValueError('Unexpected original payload change')
        run([sdk / 'zipalign.exe', '-c', '-P', '16', '4', output])
        badging = run([sdk / 'aapt.exe', 'dump', 'badging', output])
        launcher = ACTIVITY if variant == 'activity-only' else 'com.unity3d.player.UnityPlayerActivity'
        if "launchable-activity: name='" + launcher + "'" not in badging:
            raise ValueError('Unexpected launcher')
        (lab / (variant + '-signature.txt')).write_text(verification, encoding='utf-8')
        controls.append({'variant': variant, 'apk': str(output), 'sha256': sha256(output),
                         'launcher': launcher, 'original_dex_and_native_libraries_unchanged': True,
                         'signature_verified': True, 'zipalign_16k_verified': True,
                         'changed_original_payloads': ['AndroidManifest.xml'] if manifest is not None else [],
                         'added_non_signing_members': [] if variant == 'repacked-only' else ['classes2.dex'],
                         'contains_loader': False, 'runtime_tested': False})
    if sha256(source) != SOURCE_SHA:
        raise ValueError('Source changed during build')
    report = {'status': 'built-offline-verified-runtime-unverified', 'source_sha256': SOURCE_SHA,
              'signer_sha256': certificate, 'control_dex_sha256': hashlib.sha256(dex).hexdigest(),
              'control_source_sha256': sha256(ROOT / 'android/control/tm/loader/ControlActivity.java'),
              'phone_accessed': False, 'controls': controls,
              'limitations': 'Controls only; original code unchanged. Alignment/recompression also differs from original.'}
    text = json.dumps(report, ensure_ascii=False, indent=2) + '\n'
    (lab / 'controls-build.json').write_text(text, encoding='utf-8')
    (ROOT / 'reports/standalone-activity-controls-build.json').write_text(text, encoding='utf-8')
    print(text)


if __name__ == '__main__':
    main()
