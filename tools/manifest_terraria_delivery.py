"""Hash a completed private delivery without including itself or Ghidra locks."""
import argparse, hashlib, json, pathlib
from concurrent.futures import ThreadPoolExecutor

def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        if path.stat().st_size<=1024*1024:
            h.update(stream.read())
        else:
            for block in iter(lambda:stream.read(1024*1024),b''):h.update(block)
    return h.hexdigest()

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',type=pathlib.Path,required=True);ap.add_argument('--apk',type=pathlib.Path,required=True);a=ap.parse_args()
    root=a.lab.resolve();source=sha(a.apk)
    expected=json.loads((root/'evidence/native-summary.json').read_text(encoding='utf-8-sig'))['apk_sha256']
    if expected!=source:raise ValueError('Original APK hash changed')
    paths=[p for p in sorted(root.rglob('*')) if p.is_file() and p.name!='artifact-manifest.json' and p.suffix not in ('.lock','.lock~')]
    def inspect(path):
        if path.is_symlink():raise ValueError('Unexpected symlink')
        return {'path':path.relative_to(root).as_posix(),'size':path.stat().st_size,'sha256':sha(path)}
    rows=[]
    with ThreadPoolExecutor(max_workers=16) as pool:
        for offset in range(0,len(paths),1024):rows.extend(pool.map(inspect,paths[offset:offset+1024]))
    result={'source_apk':str(a.apk),'apk_sha256':source,'file_count':len(rows),'total_bytes':sum(r['size'] for r in rows),'files':rows,'scope':'Delivered local artifacts; hashes prove file identity, not semantic equivalence or original source recovery.'}
    (root/'artifact-manifest.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    print(json.dumps({k:v for k,v in result.items() if k!='files'},ensure_ascii=False))

if __name__=='__main__':main()
