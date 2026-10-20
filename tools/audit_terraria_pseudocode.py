"""Check provenance headers and inventory decompiler warnings in final C files."""
import argparse, collections, json, pathlib, re
from concurrent.futures import ThreadPoolExecutor

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',type=pathlib.Path,required=True);a=ap.parse_args();root=(a.lab/'pseudocode').resolve()
    rows=[json.loads(x) for x in (root/'coverage.jsonl').read_text(encoding='utf8').splitlines() if x]
    errors=[];warnings=[];kinds=collections.Counter();claimed=set();count=0;parents={}
    def confined(relative):
        relative=pathlib.Path(relative)
        if relative.is_absolute() or len(relative.parts)!=2 or any(p in ('.','..') for p in relative.parts):raise ValueError('Unexpected C path')
        parent=relative.parts[0]
        if parent not in parents:
            real=(root/parent).resolve()
            if not real.is_relative_to(root):raise ValueError('Directory escapes pseudocode root')
            parents[parent]=real
        p=parents[parent]/relative.parts[1]
        if p.is_symlink():raise ValueError('Unexpected C file symlink')
        return p
    def inspect(r):
        p=confined(r['file'])
        text=p.read_text(encoding='utf8');row_errors=[]
        header=('/* RECOVERED GHIDRA PSEUDOCODE; NOT ORIGINAL C#; static analysis only.\n'
                ' * Method: '+r['method'].replace('*/','* /')+'\n * ELF VA: '+r['address']+'; image base: 0\n'
                ' * Compiler unwind extent end-exclusive: '+r['compiler_end_exclusive']+'\n * Analysis profile: '+r['profile']+'\n */\n')
        if not text.startswith(header):row_errors.append({'address':r['address'],'file':r['file'],'error':'Provenance header differs from ledger'})
        if r['profile']!='bounded-fde-terminal-calls-signatures-v3':row_errors.append({'address':r['address'],'error':'Unexpected analysis profile'})
        messages=re.findall(r'/\*\s*WARNING:([\s\S]*?)\*/',text)
        return r,p,row_errors,[' '.join(m.split()) for m in messages]
    successful=[r for r in rows if r['status']=='decompiled']
    with ThreadPoolExecutor(max_workers=16) as pool:
        for offset in range(0,len(successful),1024):
            for r,p,row_errors,messages in pool.map(inspect,successful[offset:offset+1024]):
                if p in claimed:errors.append({'address':r['address'],'error':'Duplicate pseudocode file'})
                claimed.add(p);count+=1;errors.extend(row_errors)
                if messages:
                    warnings.append({'address':r['address'],'method':r['method'],'file':r['file'],'warnings':messages});kinds.update(messages)
    extra=sorted(str(p.relative_to(root)) for p in root.rglob('*.c') if confined(p.relative_to(root)) not in claimed)
    result={'files_checked':count,'header_errors':errors,'unclaimed_c_files':extra,'functions_with_decompiler_warnings':len(warnings),'warning_instances':sum(kinds.values()),'warning_text_counts':dict(kinds),'passed':not errors and not extra,'scope':'Header/file identity and warning inventory only; absence of a warning does not prove correct semantics.'}
    (root/'pseudocode-audit.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    with (root/'decompiler-warnings.jsonl').open('w',encoding='utf8') as stream:
        for w in warnings:stream.write(json.dumps(w,ensure_ascii=False)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='warning_text_counts'},ensure_ascii=False))
    if not result['passed']:raise SystemExit(1)

if __name__=='__main__':main()
