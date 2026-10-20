"""Build private offline diagnostic APKs; never install or contact a device.

Controls contain no loader. They distinguish re-signing from adding an inert
archive member when future, separately scheduled runtime tests are possible.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import zipfile

from apk_format import sha256

ROOT = Path(__file__).resolve().parents[1]
SOURCE_SHA = '1f8e2ba7ddabaee961a1b2552d44bc0c281c9b5122480642b018779bcbf2fe8e'
MARKER = 'assets/tmloader-diagnostic-marker.txt'
MARKER_BYTES = b'Inert archive control. No loader or executable code.\n'


def run(command):
    result = subprocess.run(list(map(str, command)), capture_output=True,
                            text=True, encoding='utf-8', errors='replace', timeout=120)
    if result.returncode:
        raise RuntimeError('Diagnostic build command failed:\n' + result.stdout + result.stderr)
    return result.stdout + result.stderr


def signer(text):
    matches = re.findall(r'Signer #\d+ certificate SHA-256 digest: ([0-9a-f]{64})', text)
    if len(matches) != 1:
        raise ValueError('Expected one verified signer')
    return matches[0]


def signing_entry(name):
    upper = name.upper()
    return upper.startswith('META-INF/') and (
        upper.endswith(('.SF', '.RSA', '.DSA', '.EC')) or upper == 'META-INF/MANIFEST.MF')


def payloads(path):
    result = {}
    with zipfile.ZipFile(path) as archive:
        if len(archive.namelist()) != len(set(archive.namelist())):
            raise ValueError('Duplicate archive members')
        for item in archive.infolist():
            if signing_entry(item.filename):
                continue
            digest = hashlib.sha256()
            with archive.open(item) as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(chunk)
            result[item.filename] = digest.hexdigest()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'lab', 'java', 'apksigner', 'key', 'cert'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    source, lab = args.source.resolve(), args.lab.resolve()
    if lab == ROOT or lab.is_relative_to(ROOT):
        raise ValueError('Derived APKs must stay outside the source repository')
    if source == lab or source.is_relative_to(lab):
        raise ValueError('Use a new diagnostic directory separate from the source')
    if lab.exists():
        raise ValueError('Use a new directory; refusing to overwrite prior evidence')
    if sha256(source) != SOURCE_SHA:
        raise ValueError('Unexpected source APK hash')
    prefix = [args.java, '-jar', args.apksigner]
    source_cert = signer(run(prefix + ['verify', '--verbose', '--print-certs', source]))
    baseline = payloads(source)
    if MARKER in baseline:
        raise ValueError('Diagnostic marker already exists')
    lab.mkdir(parents=True)
    controls = []
    for variant in ('resign-only', 'inert-marker'):
        staging = lab / (variant + '-input.apk')
        output = lab / (variant + '.apk')
        shutil.copyfile(source, staging)
        if variant == 'inert-marker':
            with zipfile.ZipFile(staging, 'a') as archive:
                archive.writestr(MARKER, MARKER_BYTES, compress_type=zipfile.ZIP_STORED)
        run(prefix + ['sign', '--key', args.key, '--cert', args.cert, '--out', output, staging])
        verification = run(prefix + ['verify', '--verbose', '--print-certs', output])
        if signer(verification) != source_cert:
            raise ValueError('Signer does not match source')
        expected = dict(baseline)
        if variant == 'inert-marker':
            expected[MARKER] = hashlib.sha256(MARKER_BYTES).hexdigest()
        if payloads(output) != expected:
            raise ValueError('Unexpected payload change in ' + variant)
        (lab / (variant + '-signature.txt')).write_text(verification, encoding='utf-8')
        controls.append({'variant': variant, 'apk': str(output), 'sha256': sha256(output),
                         'source_payloads_preserved': len(baseline),
                         'added_non_signing_members': [MARKER] if variant == 'inert-marker' else [],
                         'signer_matches_source': True, 'signature_verified': True,
                         'contains_loader': False, 'runtime_tested': False})
    if sha256(source) != SOURCE_SHA:
        raise ValueError('Source changed during build')
    report = {'status': 'built-offline-verified-runtime-unverified',
              'source_sha256': SOURCE_SHA, 'signer_sha256': source_cert,
              'phone_accessed': False, 'game_or_protection_code_modified': False,
              'controls': controls,
              'limitations': 'Diagnostic controls only; no mods, no autonomous loader, no runtime verdict.'}
    text = json.dumps(report, ensure_ascii=False, indent=2) + '\n'
    (lab / 'controls-build.json').write_text(text, encoding='utf-8')
    (ROOT / 'reports/standalone-controls-build.json').write_text(text, encoding='utf-8')
    print(text)


if __name__ == '__main__':
    main()
