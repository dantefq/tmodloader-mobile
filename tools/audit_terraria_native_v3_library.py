"""Run the pinned, independent V3 audit for one completed native queue."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

LAB = Path(r'C:\Temp\terraria-re-20261012')
LIBRARIES = ('libGNS_Wrapper.so', 'libexternal_wrapper.so', 'libc++_shared.so',
             'libpairipcore.so', 'libpdaprotect.so', 'libunity.so')
PRODUCER_SHA = '2abbe851f83a5bcde7864dda26652cdb7083d10634fea796bf9506e375cea3a0'
AUDITOR_SHA = '90d8b5371f848e67c1b628fb3fc3c5485553aff21bf8bb4ea384881056f9ed7f'

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('library', choices=LIBRARIES)
    args = parser.parse_args()
    slug = args.library.removesuffix('.so').replace('+', 'p')
    manifest = LAB/'other-native-range-v3-manifests-20261019'/(args.library+'.manifest.json')
    records = json.loads((manifest.parent/'summary.json').read_text())
    record, = [r for r in records if r['library'] == args.library]
    assert hashlib.sha256(manifest.read_bytes()).hexdigest() == record['manifest_sha256']
    frozen = LAB/'other-native-exporter-v3-sources-20261019'
    auditor = frozen/'tools/apk-native-v3/audit_apk_native_range_export_v3.py'
    assert hashlib.sha256(auditor.read_bytes()).hexdigest() == AUDITOR_SHA
    output = LAB/f'other-native-range-c-{slug}-sample-v3-20261019'
    audit = LAB/f'other-native-{slug}-final-v3-audit-20261019.json'
    assert not audit.exists(), 'Preserve prior audit; fresh destination required'
    data = json.loads(manifest.read_text())
    command = [sys.executable, str(auditor), '--elf', data['binary_path'],
               '--manifest', str(manifest), '--manifest-sha256', record['manifest_sha256'],
               '--producer', str(frozen/'ApkNativeRangeExport.java'),
               '--producer-sha256', PRODUCER_SHA,
               '--engine', str(LAB/'ghidra-guard-range-20261019/Ghidra/Features/Decompiler/os/win_x86_64/decompile.exe'),
               '--output-dir', str(output), '--audit-output', str(audit)]
    result = subprocess.run(command, capture_output=True, text=True, encoding='utf8')
    (LAB/f'other-native-{slug}-final-v3-audit-20261019.stdout.log').write_text(result.stdout, encoding='utf8')
    (LAB/f'other-native-{slug}-final-v3-audit-20261019.stderr.log').write_text(result.stderr, encoding='utf8')
    if result.returncode:
        raise RuntimeError(result.stderr[-4000:])
    verified = json.loads(audit.read_text())
    keys = ('integrity_passed', 'all_rows_attempted', 'attempted_rows', 'not_attempted_rows',
            'status_counts', 'C_text_rows_without_detected_truncation_markers',
            'C_text_rows_with_retained_pcode_outside_extent',
            'conditional_export_rows_without_detected_truncation_and_with_retained_scope_inside',
            'unjournaled_artifacts', 'import_restoration_record_present')
    print(json.dumps(dict(library=args.library, audit=str(audit),
                          **{k: verified.get(k) for k in keys})))
    assert verified['all_rows_attempted'], 'Partial audit preserved; queue needs continuation'

if __name__ == '__main__':
    main()
