"""Read own sleep companion hashes without extracting its private bundled DLLs.

This artifact manifest does not verify Android signatures or runtime behavior.
"""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile


def inspect(path):
    files = {}
    with zipfile.ZipFile(path) as apk:
        names = apk.namelist()
        for name in ('TerrariaMobile.ManagedDemo.dll','tModLoader.dll','ChangeSleepTime.dll','demo-contract.json'):
            entry = 'assets/managed/'+name
            if names.count(entry)!=1:
                raise ValueError('Missing or duplicated sleep bundle member: '+name)
            if apk.getinfo(entry).file_size>128*1024*1024:
                raise ValueError('Oversized managed bundle member')
            files[name]=hashlib.sha256(apk.read(entry)).hexdigest()
        contract_info=apk.getinfo('assets/managed/demo-contract.json')
        if contract_info.file_size>4096:raise ValueError('Oversized sleep contract')
        contract=json.loads(apk.read(contract_info).decode('utf-8'))
        unified=contract.get('api_revision')=='managed-foundation-v2'
        if unified:
            entry='assets/managed/PcModItemDemo.tmod'
            if names.count(entry)!=1 or apk.getinfo(entry).file_size>128*1024*1024:
                raise ValueError('Missing, duplicated or oversized unified item archive')
            files['PcModItemDemo.tmod']=hashlib.sha256(apk.read(entry)).hexdigest()
        script='lib/arm64-v8a/libtmloader.js.so'
        if names.count(script)!=1:
            raise ValueError('Missing or duplicated runtime script')
        script_hash=hashlib.sha256(apk.read(script)).hexdigest()
    return dict(status='inspected-artifact-manifest',apk=str(path),variant='unified-sleep-demo' if unified else 'sleep-demo',
        output_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),own_api_bundle_files=files,
        runtime_script_sha256=script_hash,
        limitations=['Content hashes only; signature and in-game behavior require separate reports.'])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('apk',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    report=inspect(args.apk)
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(sha256=report['output_sha256'],output=str(args.output))))
