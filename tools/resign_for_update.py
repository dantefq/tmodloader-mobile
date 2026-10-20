"""Sign the verified lab build with a supplied matching development key."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import zipfile
from apk_format import sha256

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java',required=True,type=Path)
    parser.add_argument('--apksigner',required=True,type=Path)
    parser.add_argument('--key',required=True,type=Path)
    parser.add_argument('--cert',required=True,type=Path)
    parser.add_argument('--source',required=True,type=Path)
    parser.add_argument('--lab',required=True,type=Path)
    args=parser.parse_args()
    lab=args.lab.resolve()
    if lab.is_relative_to(ROOT): raise ValueError('Derived game build must remain outside source repository')
    report=json.loads((ROOT/'reports/build-report.json').read_text(encoding='utf-8'))
    original_build=Path(report['apk'])
    if sha256(original_build)!=report['output_sha256']: raise ValueError('Verified build hash differs')
    if sha256(args.source)!=report['source_sha256']: raise ValueError('Original APK hash differs')
    def run(*command):
        result=subprocess.run([str(args.java),'-jar',str(args.apksigner),*map(str,command)],
                              capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=60)
        if result.returncode: raise RuntimeError(result.stdout+'\n'+result.stderr)
        return result.stdout
    def signer(output):
        found=re.findall(r'Signer #\d+ certificate SHA-256 digest: ([0-9a-f]{64})',output)
        if len(found)!=1: raise ValueError('Expected exactly one verified signer')
        return found[0]
    source_signer=signer(run('verify','--print-certs',args.source))
    output=lab/'Terraria-Mobile-JSON-Loader-update.apk'
    run('sign','--key',args.key,'--cert',args.cert,'--out',output,lab/'aligned.apk')
    signature=run('verify','--verbose','--print-certs',output)
    if signer(signature)!=source_signer: raise ValueError('Update signer differs from installed source APK')
    def signature_entry(name):
        return name.startswith('META-INF/') and (name.upper().endswith(('.RSA','.SF','.DSA','.EC')) or name=='META-INF/MANIFEST.MF')
    with zipfile.ZipFile(original_build) as before,zipfile.ZipFile(output) as after:
        if after.testzip(): raise ValueError('Update APK ZIP integrity failure')
        before_names={n for n in before.namelist() if not signature_entry(n)}
        after_names={n for n in after.namelist() if not signature_entry(n)}
        if before_names!=after_names: raise ValueError('Unexpected content entries changed while signing')
        for name in before_names:
            if before.read(name)!=after.read(name): raise ValueError('Signing altered content: '+name)
    update_report=dict(report,apk=str(output),output_sha256=sha256(output),
                       matching_installed_signer=source_signer,installation_verified=False,
                       in_game_verified=False,source_game_code_modified=False)
    (lab/'update-signature-verification.txt').write_text(signature,encoding='utf-8')
    (ROOT/'reports/update-build-report.json').write_text(json.dumps(update_report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:update_report[k] for k in ('apk','output_sha256','matching_installed_signer','in_game_verified')},indent=2))


if __name__=='__main__': main()
