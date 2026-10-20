"""Derive a direct static call graph from recorded Ghidra call references."""
import argparse, collections, csv, json, pathlib

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',type=pathlib.Path,required=True);a=ap.parse_args();out=a.lab/'pseudocode'
    rows=[json.loads(x) for x in (out/'coverage.jsonl').read_text(encoding='utf8').splitlines() if x]
    methods={int(r['address'],16):r for r in rows}
    edges=collections.Counter();classes=collections.Counter();unknown=collections.Counter();sites=0
    with (out/'calls.tsv').open(encoding='utf8',newline='') as stream:
        reader=csv.reader(stream,delimiter='\t');header=next(reader)
        if header!=['caller','source','target','type']:raise ValueError('Unexpected calls table header')
        for row in reader:
            source,site=int(row[0],16),int(row[1],16)
            if source not in methods:raise ValueError('Caller absent from coverage')
            sites+=1
            try:target=int(row[2],16)
            except ValueError:unknown[row[2]]+=1;continue
            if target not in methods:unknown[target]+=1;continue
            edges[source,target]+=1
            s,t=methods[source],methods[target]
            classes[(s['image'],s['method'].split('::',1)[0],t['image'],t['method'].split('::',1)[0])]+=1
    with (out/'managed-call-edges.csv').open('w',encoding='utf8',newline='') as stream:
        writer=csv.writer(stream);writer.writerow(['caller_va','caller','callee_va','callee','recorded_call_sites'])
        for (s,t),n in sorted(edges.items()):writer.writerow([hex(s),methods[s]['method'],hex(t),methods[t]['method'],n])
    with (out/'class-call-edges.csv').open('w',encoding='utf8',newline='') as stream:
        writer=csv.writer(stream);writer.writerow(['caller_image','caller_type','callee_image','callee_type','recorded_call_sites'])
        for edge,n in sorted(classes.items()):writer.writerow([*edge,n])
    summary={'functions':len(methods),'recorded_call_references':sites,'managed_edges':len(edges),'managed_call_sites':sum(edges.values()),'class_edges':len(classes),'targets_without_managed_seed':len(unknown),'references_to_targets_without_managed_seed':sum(unknown.values()),'scope':'Direct static call references only, including bounded FDE flow annotations. Indirect calls, runtime dispatch and reachability are not established; call-site counts are not execution counts.'}
    (out/'callgraph-summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf8');print(json.dumps(summary))
    declarations=[json.loads(x) for x in (a.lab/'metadata/methods.jsonl').read_text(encoding='utf8').splitlines() if x]
    generics=json.loads((a.lab/'native/generic-method-addresses.json').read_text(encoding='utf8'))
    instantiated={r['method_index'] for r in generics if r.get('address')}
    gaps=[]
    for r in declarations:
        if r.get('native_address') or r['index'] in instantiated:continue
        gaps.append({'method_index':r['index'],'image':r['assembly'],'signature':r['display_signature'],
                     'flags':hex(r['flags']),'implementation_flags':hex(r['implementation_flags']),
                     'status':'abstract_declaration' if r['flags']&0x400 else 'concrete_without_mapped_entrypoint'})
    (out/'implementation-gaps.json').write_text(json.dumps({'counts':dict(collections.Counter(r['status'] for r in gaps)),'declarations':gaps,'scope':'No direct or instantiated generic entrypoint in the recovered tables; stripping, internal-call lowering or other cause is not established.'},ensure_ascii=False,indent=2)+'\n',encoding='utf8')

if __name__=='__main__':main()
