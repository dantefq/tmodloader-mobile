"""Conservative IL2CPP direct-method ABI catalogue; excludes unproved aggregate ABI."""
import argparse, collections, json, pathlib, re

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',type=pathlib.Path,required=True);args=ap.parse_args();lab=args.lab
    def jsonl(name):return [json.loads(line) for line in (lab/'metadata'/name).read_text(encoding='utf8').splitlines() if line]
    methods=jsonl('methods.jsonl');params={p['index']:p for p in jsonl('parameters.jsonl')}
    native=json.loads((lab/'native/il2cpp-types.json').read_text(encoding='utf8'))['types'];types={t['type_index']:t for t in native}
    codes={1:'void',2:'bool',3:'u16',4:'i8',5:'u8',6:'i16',7:'u16',8:'i32',9:'u32',10:'i64',11:'u64',12:'f32',13:'f64',24:'i64',25:'u64'}
    reasons=collections.Counter();rows=[];seen=set()
    def decode(index,return_type=False):
        t=types[index];tag=t['type_tag']
        if t['byref'] or tag in (15,16,20,29,14,18,28):return 'ptr'
        if tag in codes:
            if tag==1 and not return_type:raise ValueError('void_parameter')
            return codes[tag]
        if tag==17 and t['name'] in ('System.IntPtr','System.UIntPtr'):return 'i64' if t['name']=='System.IntPtr' else 'u64'
        raise ValueError('unproved_type_tag_'+str(tag))
    for m in methods:
        address=m.get('native_address')
        if not address:reasons['no_direct_address']+=1;continue
        if m.get('native_address_alias_count',0)>1 or address in seen:reasons['aliased_address']+=1;continue
        if m['generic_container_index']>=0:reasons['generic_method_definition']+=1;continue
        try:
            ret=decode(m['return_type_index'],True);pc=[];pn=[]
            if not(m['flags']&0x10):pc.append('ptr');pn.append('__this')
            for i,pindex in enumerate(m['parameter_indices']):
                p=params[pindex];pc.append(decode(p['type_index']));pn.append('p'+str(i)+'_'+re.sub(r'[^A-Za-z0-9_]','_',p['name'])[:80])
            pc.append('ptr');pn.append('__methodInfo')
            rows.append('\t'.join([address,ret,','.join(pc),','.join(pn),str(m['index'])]));seen.add(address)
        except (ValueError,KeyError) as e:reasons[str(e)]+=1
    (lab/'native/signatures.tsv').write_text('\n'.join(rows)+'\n',encoding='utf8')
    summary={'direct_signatures':len(rows),'total_method_declarations':len(methods),'excluded':dict(reasons),'profile':'conservative-il2cpp-primitives-refs-v1','hidden_method_info_last':True,'aggregate_abi_inferred':False}
    (lab/'native/signatures-summary.json').write_text(json.dumps(summary,indent=2),encoding='utf8');print(json.dumps(summary))

if __name__=='__main__':main()
