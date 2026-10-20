"""Strict flat-aggregate and enum signatures from IL2CPP layouts, kept apart from v3."""
import argparse, collections, json, pathlib, re

PRIMITIVES={1:('void',0),2:('bool',1),3:('u16',2),4:('i8',1),5:('u8',1),6:('i16',2),7:('u16',2),8:('i32',4),9:('u32',4),10:('i64',8),11:('u64',8),12:('f32',4),13:('f64',8),24:('i64',8),25:('u64',8)}
NAMES={f'Microsoft.Xna.Framework.{x}' for x in ('Point','Rectangle','Vector2','Vector3','Vector4','Quaternion','Color')}
NAMES|={'Microsoft.Xna.Framework.Graphics.Color','UnityEngine.Vector2','UnityEngine.Vector3','UnityEngine.Vector4','UnityEngine.Quaternion','UnityEngine.Color'}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',type=pathlib.Path,required=True);a=ap.parse_args();lab=a.lab
    def lines(name):return [json.loads(x) for x in (lab/'metadata'/name).read_text(encoding='utf8').splitlines() if x]
    ts=lines('types.jsonl');fs=lines('fields.jsonl');ms=lines('methods.jsonl');ps=lines('parameters.jsonl')
    native={r['type_index']:r for r in json.loads((lab/'native/il2cpp-types.json').read_text())['types']}
    typedef={r['full_name']:r for r in ts};fields=collections.defaultdict(list)
    for f in fs:
        if f['native_field_offset_scope']=='instance_storage':fields[f['owner_type']].append(f)
    enums={};aggregates={};excluded=collections.Counter()
    for t in ts:
        name=t['full_name'];ff=fields[name]
        if t['parent_type_name']=='System.Enum':
            if len(ff)!=1 or ff[0]['name']!='value__':excluded['enum_field_shape']+=1;continue
            n=native[ff[0]['type_index']];p=PRIMITIVES.get(n['type_tag'])
            if not p or n['type_tag'] not in (4,5,6,7,8,9,10,11) or ff[0]['native_field_offset_raw']!=16 or t['native_native_size']!=p[1]:excluded['enum_layout']+=1;continue
            enums[name]={'code':p[0],'size':p[1],'type_definition_index':t['index'],'value_field_index':ff[0]['index']}
        if name not in NAMES:continue
        if t['parent_type_name']!='System.ValueType' or t['generic_container_index']>=0 or not ff:excluded['aggregate_shape']+=1;continue
        size=t['native_native_size'];members=[];offset=0
        for f in sorted(ff,key=lambda r:r['native_field_offset_raw']):
            n=native[f['type_index']];p=PRIMITIVES.get(n['type_tag']);actual=f['native_field_offset_raw']-16
            if not p or p[1]==0 or n['byref'] or actual!=offset:break
            members.append({'name':f['name'],'offset':actual,'code':p[0],'size':p[1],'field_index':f['index']});offset+=p[1]
        else:
            if offset==size and size<=16 and t['native_instance_size']==size+16:
                code='s'+str(t['index']);hfa=all(f['code']=='f32' for f in members) and len(members)<=4
                aggregates[name]={'code':code,'name':name,'size':size,'alignment':max(f['size'] for f in members),'fields':members,'type_definition_index':t['index'],'aapcs64_classification':'HFA_f32_'+str(len(members)) if hfa else 'small_integer_aggregate'};continue
        excluded['aggregate_layout']+=1
    known={**{n:r['code'] for n,r in enums.items()},**{n:r['code'] for n,r in aggregates.items()}}
    rejects=collections.Counter();rows=[];seen=set();enhanced=0
    def decode(index,ret=False):
        n=native[index];tag=n['type_tag']
        if n['byref'] or tag in (15,16,20,29,14,18,28):return 'ptr'
        if tag in PRIMITIVES:
            if tag==1 and not ret:raise ValueError('void_parameter')
            return PRIMITIVES[tag][0]
        if tag==17:
            if n['name'] in ('System.IntPtr','System.UIntPtr'):return 'i64' if n['name']=='System.IntPtr' else 'u64'
            if n['name'] in known:return known[n['name']]
        raise ValueError('unknown_tag_'+str(tag))
    for m in ms:
        address=m.get('native_address')
        if not address:rejects['no_direct_address']+=1;continue
        if address in seen or m.get('native_address_alias_count',0)>1:rejects['alias']+=1;continue
        if m['generic_container_index']>=0:rejects['generic_method']+=1;continue
        try:
            ret=decode(m['return_type_index'],True);codes=[];names=[]
            if not m['flags']&0x10:codes.append('ptr');names.append('__this')
            for i,pi in enumerate(m['parameter_indices']):
                p=ps[pi];codes.append(decode(p['type_index']));names.append('p'+str(i)+'_'+re.sub(r'[^A-Za-z0-9_]','_',p['name'])[:80])
            codes.append('ptr');names.append('__methodInfo');rows.append('\t'.join([address,ret,','.join(codes),','.join(names),str(m['index'])]));seen.add(address)
            if any(c.startswith('s') for c in [ret,*codes]) or any(native[i]['name'] in enums for i in [m['return_type_index'],*[ps[p]['type_index'] for p in m['parameter_indices']]]):enhanced+=1
        except ValueError as e:rejects[str(e)]+=1
    out=lab/'native/abi-v4';out.mkdir(exist_ok=True)
    (out/'aggregates.json').write_text(json.dumps(list(aggregates.values()),indent=2)+'\n',encoding='utf8')
    (out/'enums.json').write_text(json.dumps(enums,indent=2)+'\n',encoding='utf8')
    (out/'signatures.tsv').write_text('\n'.join(rows)+'\n',encoding='utf8')
    summary={'signatures':len(rows),'enum_or_aggregate_signatures':enhanced,'aggregates':len(aggregates),'enums':len(enums),'excluded_layouts':dict(excluded),'excluded_methods':dict(rejects),'profile':'metadata-flat-aggregates-enums-v4-candidate','validated_abi_storage':False,'source':'IL2CPP native field offsets/sizes and enum value__ underlying type; Arm AAPCS64 https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst','limits':'Flat whitelist <=16 bytes only. Boxed header subtraction 16 must be validated against actual register use. No unknown/nested/generic aggregate ABI inferred.'}
    (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf8');print(json.dumps(summary))

if __name__=='__main__':main()
