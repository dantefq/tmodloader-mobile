"""Merge an append-only retry journal into a complete, immutable baseline ledger."""
import argparse, collections, json, pathlib

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',type=pathlib.Path,required=True);ap.add_argument('--baseline',type=pathlib.Path,required=True);a=ap.parse_args();out=(a.lab/'pseudocode').resolve()
    rows=[json.loads(x) for x in a.baseline.read_text(encoding='utf8').splitlines() if x]
    if len(rows)!=93990:raise ValueError('Incomplete baseline')
    by={r['address']:r for r in rows}
    if len(by)!=len(rows):raise ValueError('Duplicate baseline address')
    extents=dict(line.split('\t') for line in (a.lab/'native/unwind-function-ranges.tsv').read_text().splitlines() if line)
    retry=out/'retry-results.jsonl';updates={}
    if retry.exists():
        lines=retry.read_text(encoding='utf8').splitlines(keepends=True)
        for i,line in enumerate(lines):
            if not line.strip():continue
            try:r=json.loads(line)
            except json.JSONDecodeError:
                if i==len(lines)-1 and not line.endswith('\n'):break
                raise
            old=by.get(r.get('address'))
            if not old or old['status']=='decompiled':raise ValueError('Retry outside baseline failures')
            if r['address'] in updates:raise ValueError('Duplicate retry result')
            for key in ('address','image_base','image','method','compiler_end_exclusive','compiler_size','instructions','instruction_bytes','instruction_coverage_complete','profile'):
                if r.get(key)!=old.get(key):raise ValueError('Retry changed identity/listing: '+key)
            if r['compiler_end_exclusive']!=extents[r['address']]:raise ValueError('Wrong FDE extent')
            if r['status'] not in ('decompiled','decompile_failed','export_error','missing_function'):raise ValueError('Unexpected retry status')
            if not 1<=r['timeout_seconds']<=3600 or not 1<=r['max_instructions']<=1000000:raise ValueError('Invalid resource limits')
            if r['status']=='decompiled':
                p=(out/r['file']).resolve()
                if not p.is_relative_to(out) or not p.is_file():raise ValueError('Missing/confined C file')
                header=('/* RECOVERED GHIDRA PSEUDOCODE; NOT ORIGINAL C#; static analysis only.\n'
                    ' * Method: '+r['method'].replace('*/','* /')+'\n * ELF VA: '+r['address']+'; image base: 0\n'
                    ' * Compiler unwind extent end-exclusive: '+r['compiler_end_exclusive']+'\n * Analysis profile: '+r['profile']+'\n */\n')
                if not p.read_text(encoding='utf8').startswith(header):raise ValueError('Retry header mismatch')
            updates[r['address']]=r
    merged=[updates.get(r['address'],r) for r in rows]
    for r in merged:
        if 'max_instructions' not in r:
            r['max_instructions']=100000
            r['max_instructions_origin']='Pinned Ghidra 12.1.4 private-program default used in baseline export'
    counts=collections.Counter(r['status'] for r in merged)
    temporary=out/'coverage.merged.tmp'
    with temporary.open('w',encoding='utf8') as stream:
        for r in merged:stream.write(json.dumps(r,ensure_ascii=False,separators=(',',':'))+'\n')
    temporary.replace(out/'coverage.jsonl')
    progress={'finished':True,'workers':4,'total':len(rows),'processed':len(rows),'completed':len(rows),
        'decompiled':counts['decompiled'],'failed':counts['decompile_failed'],'missing':counts['missing_function'],'export_error':counts['export_error'],
        'cached':sum(r['status']=='decompiled' for r in rows),'profile':'bounded-fde-terminal-calls-signatures-v3',
        'retry_results_merged':len(updates),'retry_failures_not_attempted':sum(r['status']!='decompiled' and r['address'] not in updates for r in rows),
        'resource_limits':'See individual rows; original successes retained their original limits.',
        'instructions_and_calls_unchanged':True}
    (out/'progress.json').write_text(json.dumps(progress,indent=2)+'\n',encoding='utf8');print(json.dumps(progress))

if __name__=='__main__':main()
