"""Build a private lab APK from the user's own file, retaining protection code."""
import argparse
import hashlib
import json
import lzma
import os
from pathlib import Path
import secrets
import subprocess
import zipfile
from apk_format import ACTIVITY, MOD_ACTIVITY, probe, replace_activity, sha256

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_SHA = '1f8e2ba7ddabaee961a1b2552d44bc0c281c9b5122480642b018779bcbf2fe8e'


def run(command, env=None):
    result = subprocess.run([str(x) for x in command], capture_output=True, text=True,
                            encoding='utf-8', errors='replace', env=env, timeout=180)
    if result.returncode:
        raise RuntimeError(f'{Path(str(command[0])).name} failed ({result.returncode}):\n{result.stdout}\n{result.stderr}')
    return result.stdout + result.stderr


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk', required=True, type=Path)
    parser.add_argument('--sdk', required=True, type=Path)
    parser.add_argument('--jdk', required=True, type=Path)
    parser.add_argument('--lab', required=True, type=Path)
    parser.add_argument('--gadget', required=True, type=Path)
    parser.add_argument('--gadget-info', required=True, type=Path)
    args = parser.parse_args()
    lab = args.lab.resolve()
    if lab.is_relative_to(ROOT): raise ValueError('Game-derived output must be outside the source repository')
    if sha256(args.apk) != EXPECTED_SHA: raise ValueError('APK differs from the investigated build; run recon first')
    fingerprint = probe(args.apk)
    if fingerprint['copper_shortsword_id'] != 3507: raise ValueError('Unexpected Copper Shortsword ID')
    item = fingerprint['classes']['Terraria.Item']
    if not any(m['name']=='SetDefaults' and m['parameters']==['Type','variant'] for m in item['methods']):
        raise ValueError('Unexpected Item.SetDefaults signature')
    gadget_info = json.loads(args.gadget_info.read_text(encoding='utf-8-sig'))
    if 'sha256:' + sha256(args.gadget) != gadget_info['digest']:
        raise ValueError('Gadget digest differs from official GitHub release asset')
    sdk_tools = args.sdk / 'build-tools' / '36.0.0'
    android_jar = args.sdk / 'platforms' / 'android-35' / 'android.jar'
    javac, java, keytool = [args.jdk / 'bin' / (name+'.exe') for name in ('javac','java','keytool')]
    for path in (android_jar,javac,java,keytool,sdk_tools/'zipalign.exe',sdk_tools/'lib/d8.jar'):
        if not path.is_file(): raise FileNotFoundError(path)
    classes, stubs, dex = [lab / name for name in ('classes','stubs','dex')]
    for directory in (lab,classes,stubs,dex): directory.mkdir(parents=True,exist_ok=True)
    run([javac,'--release','8','-encoding','UTF-8','-cp',android_jar,'-d',stubs,
         ROOT/'android/stubs/com/unity3d/player/UnityPlayerActivity.java'])
    run([javac,'--release','8','-encoding','UTF-8','-cp',str(android_jar)+os.pathsep+str(stubs),'-d',classes,
         ROOT/'android/src/tm/loader/ModActivity.java'])
    own_classes = sorted((classes/'tm').rglob('*.class'))
    run([java,'-cp',sdk_tools/'lib/d8.jar','com.android.tools.r8.D8','--lib',android_jar,
         '--classpath',stubs,'--min-api','23','--output',dex,*own_classes])
    gadget = lzma.decompress(args.gadget.read_bytes())
    if gadget[:6] != b'\x7fELF\x02\x01': raise ValueError('Gadget must be ELF64 little endian')
    config = {'interaction':{'type':'script','path':'libtmloader.js.so','on_change':'ignore'},'runtime':'qjs'}
    unsigned, aligned, output = [lab/name for name in ('unsigned.apk','aligned.apk','Terraria-Mobile-JSON-Loader-prototype.apk')]
    if output.resolve() == args.apk.resolve(): raise ValueError('Cannot overwrite input APK')
    removed = []
    with zipfile.ZipFile(args.apk) as source, zipfile.ZipFile(unsigned,'w') as target:
        bad = source.testzip()
        if bad: raise ValueError('Source ZIP integrity failure: '+bad)
        names = set(source.namelist())
        if 'classes2.dex' in names: raise ValueError('Expected a single DEX in investigated APK')
        for info in source.infolist():
            name = info.filename
            if name.startswith('META-INF/') and (name.upper().endswith(('.SF','.RSA','.DSA','.EC')) or name=='META-INF/MANIFEST.MF') or name=='stamp-cert-sha256':
                removed.append(name); continue
            content = source.read(name)
            if name=='AndroidManifest.xml': content=replace_activity(content)
            target.writestr(info,content)
        additions = {
            'classes2.dex':(dex/'classes.dex').read_bytes(),
            'assets/tmloader/CopperSwordDemo.json':(ROOT/'mods/CopperSwordDemo.json').read_bytes(),
            'lib/arm64-v8a/libfridagadget.so':gadget,
            'lib/arm64-v8a/libfridagadget.config.so':json.dumps(config).encode('utf-8'),
            'lib/arm64-v8a/libtmloader.js.so':(ROOT/'runtime/loader.js').read_bytes()
        }
        for name, content in additions.items():
            if name in names: raise ValueError('Refuse to overwrite original entry: '+name)
            target.writestr(name, content, compress_type=zipfile.ZIP_STORED)
    run([sdk_tools/'zipalign.exe','-P','16','-f','4',unsigned,aligned])
    keyfile, password_file = lab/'lab-signing.jks', lab/'lab-signing-password.txt'
    if keyfile.exists() != password_file.exists(): raise ValueError('Incomplete local signing state')
    if not password_file.exists(): password_file.write_text(secrets.token_urlsafe(32),encoding='utf-8')
    env = dict(os.environ, TMAL_SIGN_PASS=password_file.read_text(encoding='utf-8').strip())
    if not keyfile.exists():
        run([keytool,'-genkeypair','-keystore',keyfile,'-alias','tm-loader',
             '-storepass:env','TMAL_SIGN_PASS','-keypass:env','TMAL_SIGN_PASS',
             '-keyalg','RSA','-keysize','2048','-validity','3650',
             '-dname','CN=Terraria Mobile JSON Loader Lab','-noprompt'],env)
    run([java,'-jar',sdk_tools/'lib/apksigner.jar','sign','--ks',keyfile,'--ks-key-alias','tm-loader',
         '--ks-pass','env:TMAL_SIGN_PASS','--key-pass','env:TMAL_SIGN_PASS','--out',output,aligned],env)
    verification = run([java,'-jar',sdk_tools/'lib/apksigner.jar','verify','--verbose','--print-certs',output])
    (lab/'signature-verification.txt').write_text(verification,encoding='utf-8')
    run([sdk_tools/'zipalign.exe','-c','-P','16','4',output])
    badging = run([sdk_tools/'aapt.exe','dump','badging',output])
    if "launchable-activity: name='"+MOD_ACTIVITY+"'" not in badging:
        raise ValueError('Manifest does not launch our Activity')
    preserved = 0
    with zipfile.ZipFile(args.apk) as source, zipfile.ZipFile(output) as built:
        if built.testzip(): raise ValueError('Output ZIP integrity failure')
        for name in source.namelist():
            if name in removed: continue
            expected = source.read(name)
            if name=='AndroidManifest.xml': expected=replace_activity(expected)
            if built.read(name)!=expected: raise ValueError('Unexpected changed game entry: '+name)
            if name!='AndroidManifest.xml': preserved+=1
        new_signatures = {'META-INF/TM-LOADE.RSA','META-INF/TM-LOADE.SF','META-INF/MANIFEST.MF'}
        if set(built.namelist()) != (set(source.namelist())-set(removed)) | set(additions) | new_signatures:
            raise ValueError('Unexpected output APK entries')
    if sha256(args.apk) != EXPECTED_SHA: raise ValueError('Input APK changed during build')
    report = {'status':'built-static-verified-runtime-unverified','apk':str(output),
              'source_sha256':EXPECTED_SHA,'output_sha256':sha256(output),
              'gadget_asset':gadget_info,'original_entries_preserved_byte_for_byte':preserved,
              'modified_original_entries':['AndroidManifest.xml (Activity string only)'],
              'replaced_signing_entries':removed,'added_entries':list(additions),
              'signature_verified':True,'zipalign_16k_verified':True,
              'game_protection_code_modified':False,'in_game_verified':False,
              'pc_tmod_supported':False}
    text=json.dumps(report,ensure_ascii=False,indent=2)
    (lab/'build-report.json').write_text(text+'\n',encoding='utf-8')
    (ROOT/'reports').mkdir(exist_ok=True)
    (ROOT/'reports/build-report.json').write_text(text+'\n',encoding='utf-8')
    print(text)


if __name__=='__main__': main()
