"""Build an isolated own texture bridge APK; never modify prior probe reports.

The runtime comes from the existing hash-pinned Mono package. No game, original
mod or Frida Gadget is bundled. An explicit external loopback debugger runs it.
"""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

from build_companion import run
from managed_api_sources import API_SOURCES, HOST_SUPPORT_SOURCES

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ('sdk', 'jdk', 'lab', 'key', 'cert'):
        parser.add_argument('--' + option, required=True, type=Path)
    parser.add_argument('--dotnet', type=Path, default=Path('C:/Program Files/dotnet'))
    parser.add_argument('--pinned-sots', type=Path, help='Private exact pinned SOTS archive; packages only the one checked image, never its DLL')
    args = parser.parse_args()
    lab = args.lab.resolve()
    if lab.exists() or lab.is_relative_to(ROOT):
        raise ValueError('A new private build folder outside the checkout is required')
    lab.mkdir(parents=True)
    runtime = json.loads((ROOT / 'reports/mono-runtime-dependency.json').read_text('utf-8'))
    package = Path(runtime['package_file'])
    if runtime['version'] != '8.0.31' or sha(package) != runtime['sha256']:
        raise ValueError('Pinned Mono Android ARM64 package differs')
    assets = lab / 'assets/managed'; assets.mkdir(parents=True)
    from texture_lab_profiles import OWN, PINNED, extract_reference
    profile = PINNED if args.pinned_sots else OWN
    resources = {}
    if args.pinned_sots:
        resource = assets / 'pinned-icon.rawimg'; resource.write_bytes(extract_reference(args.pinned_sots))
        resources[resource.name] = sha(resource)
    natives = {}
    with zipfile.ZipFile(package) as archive:
        for name in archive.namelist():
            if name.startswith('runtimes/android-arm64/') and name.endswith('.dll'):
                (assets / Path(name).name).write_bytes(archive.read(name))
            if name.startswith('runtimes/android-arm64/native/') and name.endswith('.so'):
                natives[Path(name).name] = archive.read(name)
        for name in ('LICENSE.TXT', 'THIRD-PARTY-NOTICES.TXT'):
            (assets / name).write_bytes(archive.read(name))
        crypto = lab / 'libSystem.Security.Cryptography.Native.Android.jar'
        crypto.write_bytes(archive.read('runtimes/android-arm64/native/' + crypto.name))
    dotnet = args.dotnet / 'dotnet.exe'
    csc = args.dotnet / 'sdk/8.0.425/Roslyn/bincore/csc.dll'
    refs = sorted((args.dotnet / 'packs/Microsoft.NETCore.App.Ref/8.0.31/ref/net8.0').glob('*.dll'))
    if not refs or not csc.is_file():
        raise ValueError('Pinned SDK and reference assemblies required')
    def compile(name, sources, extra=()):
        target = assets / name; response = lab / (name + '.rsp')
        lines = ['-nologo', '-nostdlib+', '-deterministic+', '-target:library', '-langversion:12', '-out:"' + str(target) + '"']
        lines += ['-r:"' + str(path) + '"' for path in [*refs, *extra]]
        lines += ['"' + str(ROOT / source) + '"' for source in sources]
        response.write_text('\n'.join(lines), encoding='utf-8')
        run([dotnet, csc, '@' + str(response)])
        return target
    shim = compile('tModLoader.dll', API_SOURCES)
    host_sources = [*HOST_SUPPORT_SOURCES, 'managed/tests/TextureBridgeChecks.cs', 'managed/tools/PinnedTextureLab.cs', 'managed/tools/AndroidTextureProbeHost.cs']
    host = compile('TerrariaMobile.ManagedDemo.dll', host_sources, [shim])
    sdk = args.sdk / 'build-tools/36.0.0'; android = args.sdk / 'platforms/android-35/android.jar'
    java = args.jdk / 'bin/java.exe'
    classes = lab / 'classes'; classes.mkdir()
    dex = lab / 'dex'; dex.mkdir()
    sources = sorted((ROOT / 'android/texture-probe').rglob('*.java'))
    run([args.jdk / 'bin/javac.exe', '--release', '8', '-encoding', 'UTF-8', '-cp', android, '-d', classes, *sources])
    run([java, '-cp', sdk / 'lib/d8.jar', 'com.android.tools.r8.D8', '--lib', android, '--min-api', '23',
         '--output', dex, *sorted(classes.rglob('*.class')), crypto])
    unsigned = lab / 'unsigned.apk'; aligned = lab / 'aligned.apk'; output = lab / 'Texture-Bridge-Probe.apk'
    run([sdk / 'aapt.exe', 'package', '-f', '-M', ROOT / 'android/texture-probe/AndroidManifest.xml',
         '-I', android, '-A', lab / 'assets', '-F', unsigned])
    with zipfile.ZipFile(unsigned, 'a') as archive:
        archive.writestr('classes.dex', (dex / 'classes.dex').read_bytes())
        for name, data in natives.items():
            archive.writestr('lib/arm64-v8a/' + name, data, compress_type=zipfile.ZIP_STORED)
    run([sdk / 'zipalign.exe', '-P', '16', '-f', '4', unsigned, aligned])
    signer = sdk / 'lib/apksigner.jar'
    run([java, '-jar', signer, 'sign', '--key', args.key, '--cert', args.cert, '--out', output, aligned])
    run([java, '-jar', signer, 'verify', output])
    run([sdk / 'zipalign.exe', '-c', '-P', '16', '4', output])
    script_sources = ['runtime/' + name for name in ('mono-runtime.js', 'managed-texture-host.js',
                      'texture-packet.js', 'texture-export.js', 'texture-bridge-probe.js')]
    script = lab / 'texture-bridge-probe.js'
    script.write_bytes(b'\n'.join((ROOT / name).read_bytes() for name in script_sources))
    evidence = {'format': 'tmal-texture-probe-build-v1', 'status': 'built-runtime-unverified', 'apk': str(output),
                'apk_sha256': sha(output), 'script_sha256': sha(script), 'runtime_sha256': runtime['sha256'],
                'files': {path.name: sha(path) for path in (host, shim)}, 'cryptography_java_jar_sha256': sha(crypto),
                'source_sha256': {name: sha(ROOT / name) for name in [*API_SOURCES, *host_sources, *script_sources,
                    'android/texture-probe/AndroidManifest.xml', *[p.relative_to(ROOT).as_posix() for p in sources]]},
                'original_mod_code_bundled': False, 'game_files_bundled': False, 'gadget_bundled': False}
    evidence.update(resource_profile=profile, resource_files=resources, original_texture_data_bundled=bool(resources))
    if resources:
        from texture_lab_profiles import TMOD_SHA, DLL_SHA, RAW_SHA
        evidence['original_reference'] = dict(version='0.25.1.9', tmod_sha256=TMOD_SHA, dll_sha256=DLL_SHA, rawimg_sha256=RAW_SHA)
    (lab / 'build.json').write_text(json.dumps(evidence, indent=2), encoding='utf-8')
    print(json.dumps({'status': evidence['status'], 'apk_sha256': evidence['apk_sha256'], 'own_managed_files': evidence['files']}))


if __name__ == '__main__':
    main()
