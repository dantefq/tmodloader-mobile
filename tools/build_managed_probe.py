"""Build an isolated own Android app to test official Mono with an own C# assembly."""
import argparse
import json
import lzma
from pathlib import Path
import shutil
import zipfile
from apk_format import sha256
from build_companion import run
from api_bundle import copy_bundle

ROOT=Path(__file__).resolve().parents[1]

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('sdk','jdk','lab','gadget','key','cert'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--dotnet',type=Path,default=Path('C:/Program Files/dotnet'))
    p.add_argument('--managed-bundle',type=Path)
    args=p.parse_args()
    contract=json.loads((args.managed_bundle/'demo-contract.json').read_text()) if args.managed_bundle else {}
    mode=contract.get('mode','own-csharp')
    revision=contract.get('api_revision')
    unified_time=revision=='managed-foundation-v2' and mode=='time-rate'
    if revision is not None and not (revision=='managed-foundation-v1' and mode=='mod-item') and not unified_time:
        raise ValueError('Unknown experimental API revision')
    moditem=mode=='mod-item';time_rate=mode=='time-rate';respawn=mode=='respawn-snapshot'
    stem='respawn' if respawn else 'unified-sleep' if unified_time else 'unified-moditem' if revision else 'sleep' if time_rate else 'moditem' if moditem else 'api' if args.managed_bundle else 'managed'
    lab=args.lab.resolve()/(stem+'-probe')
    if lab.is_relative_to(ROOT): raise ValueError('Runtime and outputs must stay outside source repository')
    lab.mkdir(parents=True,exist_ok=True)
    dependency=json.loads((ROOT/'reports/mono-runtime-dependency.json').read_text())
    package=Path(dependency['package_file'])
    if sha256(package)!=dependency['sha256']: raise ValueError('Mono runtime package changed')
    gadget_info=json.loads((ROOT/'reports/dependencies.json').read_text())
    if 'sha256:'+sha256(args.gadget)!=gadget_info['digest']: raise ValueError('Gadget package changed')
    sdk=args.sdk/'build-tools/36.0.0';jar=args.sdk/'platforms/android-35/android.jar';java=args.jdk/'bin/java.exe'
    assets=lab/'assets/managed';assets.mkdir(parents=True,exist_ok=True)
    natives={}
    crypto_jar=lab/'libSystem.Security.Cryptography.Native.Android.jar'
    with zipfile.ZipFile(package) as archive:
        for name in archive.namelist():
            if name.startswith('runtimes/android-arm64/') and name.endswith('.dll'):
                (assets/Path(name).name).write_bytes(archive.read(name))
            if name.startswith('runtimes/android-arm64/native/') and name.endswith('.so'):
                natives[Path(name).name]=archive.read(name)
        for name in ('LICENSE.TXT','THIRD-PARTY-NOTICES.TXT'):
            (assets/name).write_bytes(archive.read(name))
        # JNI_OnLoad requires the matching runtime Java helpers even for SHA256.
        # Use the jar from the same hash-pinned NuGet, never placeholder classes.
        crypto_jar.write_bytes(archive.read('runtimes/android-arm64/native/'+crypto_jar.name))
    csc=args.dotnet/'sdk/8.0.425/Roslyn/bincore/csc.dll'
    own=assets/'TerrariaMobile.ManagedDemo.dll'
    if args.managed_bundle: copy_bundle(args.managed_bundle,assets)
    else:
        run([args.dotnet/'dotnet.exe',csc,'-nologo','-target:library','-nostdlib+',
             '-r:'+str(assets/'System.Private.CoreLib.dll'),'-r:'+str(assets/'System.Runtime.dll'),
             '-out:'+str(own),ROOT/'managed/ManagedSwordDemo.cs'])
    classes=lab/'classes';dex=lab/'dex'
    for folder in (classes,dex): folder.mkdir(parents=True,exist_ok=True)
    sources=sorted((ROOT/'android/managed-probe').rglob('*.java'))+sorted((ROOT/'android/shared').rglob('*.java'))
    run([args.jdk/'bin/javac.exe','--release','8','-encoding','UTF-8','-cp',jar,'-d',classes,*sources])
    run([java,'-cp',sdk/'lib/d8.jar','com.android.tools.r8.D8','--lib',jar,'--min-api','23','--output',dex,*sorted(classes.rglob('*.class')),crypto_jar])
    unsigned,aligned,output=[lab/name for name in ('unsigned.apk','aligned.apk','Terraria-CSharp-Probe.apk')]
    run([sdk/'aapt.exe','package','-f','-M',ROOT/'android/managed-probe/AndroidManifest.xml','-I',jar,'-A',lab/'assets','-F',unsigned])
    with zipfile.ZipFile(unsigned,'a') as archive:
        archive.writestr('classes.dex',(dex/'classes.dex').read_bytes())
        for name,data in natives.items(): archive.writestr('lib/arm64-v8a/'+name,data,compress_type=zipfile.ZIP_STORED)
        archive.writestr('lib/arm64-v8a/libfridagadget.so',lzma.decompress(args.gadget.read_bytes()),compress_type=zipfile.ZIP_STORED)
        archive.writestr('lib/arm64-v8a/libfridagadget.config.so',json.dumps({'interaction':{'type':'script','path':'libmanagedprobe.js.so','on_change':'ignore'},'runtime':'qjs'}),compress_type=zipfile.ZIP_STORED)
        script=b'\n'.join((ROOT/'runtime'/name).read_bytes() for name in ('mono-runtime.js','managed-respawn-host.js','respawn-probe.js')) if respawn else (ROOT/'runtime'/('managed-time-host.js' if time_rate else 'managed-host.js')).read_bytes()+b'\n'+(ROOT/'runtime'/('sleep-probe.js' if time_rate else 'managed-probe.js')).read_bytes()
        archive.writestr('lib/arm64-v8a/libmanagedprobe.js.so',script,compress_type=zipfile.ZIP_STORED)
    run([sdk/'zipalign.exe','-P','16','-f','4',unsigned,aligned])
    signer=sdk/'lib/apksigner.jar'
    run([java,'-jar',signer,'sign','--key',args.key,'--cert',args.cert,'--out',output,aligned])
    run([java,'-jar',signer,'verify',output]);run([sdk/'zipalign.exe','-c','-P','16','4',output])
    report={'status':'built-runtime-unverified','apk':str(output),'sha256':sha256(output),
            'own_assembly_sha256':sha256(own),'runtime_version':dependency['version'],
            'signature_verified':True,'game_apk_modified':False,'pc_tmod_supported':False}
    report['mode']=mode
    report['api_revision']=revision
    report['cryptography_java_jar_sha256']=sha256(crypto_jar)
    (lab/'probe-build.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    (ROOT/'reports'/(stem+'-probe-build.json')).write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2))

if __name__=='__main__':main()
