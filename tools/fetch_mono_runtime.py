"""Fetch the pinned official .NET 8 Mono Android ARM64 runtime into the private lab."""
import argparse
import base64
import hashlib
import gzip
import json
from pathlib import Path
import urllib.request
import zipfile

VERSION = '8.0.31'
PACKAGE = 'microsoft.netcore.app.runtime.mono.android-arm64'
BASE = f'https://api.nuget.org/v3-flatcontainer/{PACKAGE}/{VERSION}/{PACKAGE}.{VERSION}.nupkg'
ROOT = Path(__file__).resolve().parents[1]

def fetch(url):
    with urllib.request.urlopen(url, timeout=45) as r:
        data=r.read(100*1024*1024+1)
    if len(data)>100*1024*1024: raise ValueError('Download exceeds 100 MiB')
    return gzip.decompress(data) if data.startswith(b'\x1f\x8b') else data

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--lab',type=Path,required=True)
    args=p.parse_args()
    folder=args.lab.resolve()/'mono-runtime'
    if folder.is_relative_to(ROOT): raise ValueError('Third-party runtime goes outside source repository')
    folder.mkdir(parents=True,exist_ok=True)
    file=folder/(PACKAGE+'.'+VERSION+'.nupkg')
    registration=json.loads(fetch(f'https://api.nuget.org/v3/registration5-gz-semver2/{PACKAGE}/{VERSION}.json'))
    catalog=json.loads(fetch(registration['catalogEntry']))
    if catalog['id'].lower()!=PACKAGE or catalog['version']!=VERSION or catalog['packageHashAlgorithm']!='SHA512':
        raise ValueError('Unexpected runtime catalog metadata')
    advertised=catalog['packageHash']
    if not file.exists(): file.write_bytes(fetch(BASE))
    digest=base64.b64encode(hashlib.sha512(file.read_bytes()).digest()).decode()
    if digest != advertised: raise ValueError('Runtime package SHA512 differs from NuGet metadata')
    entries=[]
    with zipfile.ZipFile(file) as archive:
        for name in archive.namelist():
            relative=Path(name)
            if not name.startswith('runtimes/android-arm64/') or relative.suffix not in ('.dll','.so'): continue
            output=folder/'payload'/relative.name
            output.parent.mkdir(parents=True,exist_ok=True)
            output.write_bytes(archive.read(name)); entries.append({'entry':name,'name':relative.name,'bytes':output.stat().st_size})
    report={'package_id':PACKAGE,'version':VERSION,'source':BASE,'catalog':registration['catalogEntry'],'advertised_sha512_base64':advertised,
            'sha512_matches':True,'sha256':hashlib.sha256(file.read_bytes()).hexdigest(),
            'package_file':str(file),'entries':entries,'status':'downloaded-not-executed'}
    (ROOT/'reports/mono-runtime-dependency.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'file':str(file),'version':VERSION,'sha512_matches':True,'native':[e for e in entries if e['name'].endswith('.so')],'dll_count':sum(e['name'].endswith('.dll') for e in entries)},indent=2))

if __name__=='__main__': main()
