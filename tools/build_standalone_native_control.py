"""Private DT_NEEDED bootstrap diagnostic; no DEX or manifest modifications."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import zipfile

from apk_format import sha256
from build_standalone_controls import ROOT, SOURCE_SHA, payloads, run, signer, signing_entry


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'lab', 'sdk', 'jdk', 'key', 'cert', 'python-libs'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    source, lab = args.source.resolve(), args.lab.resolve()
    if lab == ROOT or lab.is_relative_to(ROOT) or source.is_relative_to(lab) or lab.exists():
        raise ValueError('Use a new private lab separate from source/repository')
    if sha256(source) != SOURCE_SHA:
        raise ValueError('Unexpected source APK')
    sys.path.insert(0, str(args.python_libs.resolve()))
    import lief
    from elftools.elf.elffile import ELFFile
    from io import BytesIO
    lab.mkdir(parents=True)
    os.environ['ZIG_GLOBAL_CACHE_DIR'] = str(lab / 'zig-global-cache')
    os.environ['ZIG_LOCAL_CACHE_DIR'] = str(lab / 'zig-local-cache')
    zig = args.python_libs / 'ziglang/zig.exe'
    stub = lab / 'log-link-stub.c'
    stub.write_text('int __android_log_write(int p,const char*t,const char*s){return 0;}\n', encoding='utf-8')
    common = [zig, 'cc', '-target', 'aarch64-linux-android', '-fPIC', '-shared', '-nostdlib',
              '-Wl,-z,max-page-size=16384', '-Wl,--build-id=sha1']
    run(common + [stub, '-Wl,-soname,liblog.so', '-o', lab / 'liblog.so'])
    own = lab / 'libtmbootstrapcontrol.so'
    run(common + [ROOT / 'android/native/standalone-control.c', '-L' + str(lab), '-llog',
                  '-Wl,-soname,libtmbootstrapcontrol.so', '-o', own])
    member = 'lib/arm64-v8a/libmain.so'
    with zipfile.ZipFile(source) as archive:
        original = archive.read(member)
    binary = lief.ELF.parse(list(original))
    if binary is None or binary.has_library(own.name):
        raise ValueError('Unexpected original ELF')
    binary.add_library(own.name)
    if not binary.relocate_phdr_table(lief.ELF.Binary.PHDR_RELOC.SEGMENT_GAP):
        raise ValueError('Cannot place program headers in existing mapped gap')
    patched = lab / 'libmain-with-bootstrap.so'
    binary.write(str(patched))
    modified = patched.read_bytes()
    before, after = ELFFile(BytesIO(original)), ELFFile(BytesIO(modified))
    phoff = after.header['e_phoff']
    phsize = after.header['e_phnum'] * after.header['e_phentsize']
    loads = [segment for segment in after.iter_segments() if segment['p_type'] == 'PT_LOAD']
    zero_load = next(segment for segment in loads if segment['p_offset'] == 0)
    loaded_phdr = zero_load['p_vaddr'] + phoff
    if not any(segment['p_vaddr'] <= loaded_phdr and
               loaded_phdr + phsize <= segment['p_vaddr'] + segment['p_filesz'] for segment in loads):
        raise ValueError('Android loaded program headers are not covered by PT_LOAD')
    executable_sections = []
    for section in before.iter_sections():
        if section['sh_flags'] & 4 and section['sh_size']:
            target = after.get_section_by_name(section.name)
            if target is None or target['sh_addr'] != section['sh_addr'] or target.data() != section.data():
                raise ValueError('Original executable section changed: ' + section.name)
            executable_sections.append(section.name)
    needed = [tag.needed for tag in after.get_section_by_name('.dynamic').iter_tags()
              if tag.entry.d_tag == 'DT_NEEDED']
    if needed.count(own.name) != 1:
        raise ValueError('Bootstrap dependency missing or duplicated')
    baseline = payloads(source)
    sdk = args.sdk / 'build-tools/36.0.0'
    prefix = [args.jdk / 'bin/java.exe', '-jar', sdk / 'lib/apksigner.jar']
    certificate = signer(run(prefix + ['verify', '--print-certs', source]))
    staging, aligned, output = [lab / name for name in ('input.apk', 'aligned.apk', 'native-bootstrap-control.apk')]
    with zipfile.ZipFile(source) as archive, zipfile.ZipFile(staging, 'w') as target:
        for item in archive.infolist():
            if signing_entry(item.filename):
                continue
            target.writestr(item, modified if item.filename == member else archive.read(item))
        target.writestr('lib/arm64-v8a/' + own.name, own.read_bytes(), compress_type=zipfile.ZIP_STORED)
    run([sdk / 'zipalign.exe', '-P', '16', '-f', '4', staging, aligned])
    run(prefix + ['sign', '--key', args.key, '--cert', args.cert, '--out', output, aligned])
    verification = run(prefix + ['verify', '--verbose', '--print-certs', output])
    if signer(verification) != certificate:
        raise ValueError('Certificate differs')
    expected = dict(baseline)
    expected[member] = hashlib.sha256(modified).hexdigest()
    expected['lib/arm64-v8a/' + own.name] = sha256(own)
    if payloads(output) != expected:
        raise ValueError('Unexpected original payload change')
    run([sdk / 'zipalign.exe', '-c', '-P', '16', '4', output])
    if sha256(source) != SOURCE_SHA:
        raise ValueError('Source changed during build')
    report = {'status': 'built-offline-verified-runtime-unverified', 'apk': str(output),
              'source_sha256': SOURCE_SHA, 'output_sha256': sha256(output),
              'signer_sha256': certificate, 'signature_verified': True,
              'zipalign_16k_verified': True, 'modified_original_entries': [member],
              'program_headers_inside_loadable_segment': True,
              'phdr_relocation': 'SEGMENT_GAP',
              'original_executable_sections_preserved_at_same_addresses': executable_sections,
              'added_dependency': own.name, 'libmain_needed': needed,
              'bootstrap_sha256': sha256(own), 'original_dex_and_manifest_unchanged': True,
              'protection_libraries_unchanged': True, 'contains_mod_loader': False,
              'phone_accessed': False, 'runtime_tested': False,
              'limitations': 'Log-only constructor. ELF layout/dependencies change; runtime correctness remains unverified.'}
    text = json.dumps(report, ensure_ascii=False, indent=2) + '\n'
    (lab / 'native-control-build.json').write_text(text, encoding='utf-8')
    (lab / 'signature-verification.txt').write_text(verification, encoding='utf-8')
    (ROOT / 'reports/standalone-native-control-build.json').write_text(text, encoding='utf-8')
    print(text)


if __name__ == '__main__':
    main()
