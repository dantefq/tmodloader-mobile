"""Bounded static JNI/ELF inventory. Never loads or executes target libraries."""
import argparse
from collections import Counter,defaultdict
import hashlib
import json
from pathlib import Path
import re
import struct
import zipfile
from terraria_native_map import ELF


def jni_escape(value):
    result=''
    for char in value:
        if char.isascii() and char.isalnum(): result+=char
        elif char=='/': result+='_'
        elif char=='_': result+='_1'
        elif char==';': result+='_2'
        elif char=='[': result+='_3'
        else:
            for i in range(0,len(char.encode('utf-16be')),2):
                result+='_0'+char.encode('utf-16be')[i:i+2].hex()
    return result


def valid_signature(value):
    field=r'(?:\[*[ZBCSIJFD]|\[*L[^.;\[()\x00]+;)'
    return bool(re.fullmatch(r'\((?:'+field+r')*\)(?:V|'+field+r')',value))


def library_catalog(data, dex_methods):
    elf=ELF(data)
    def string_at(va,limit=512):
        try:
            off=elf.file_offset(va)
            end=data.find(b'\0',off,min(off+limit,len(data)))
            if end<0: return None
            return data[off:end].decode('ascii')
        except (ValueError,UnicodeDecodeError): return None
    # The shared ELF parser supports RELATIVE and RELR. Add locally resolvable ABS64.
    abs_resolved=0;abs_unresolved=0
    for sec in elf.sections:
        if sec['type']!=4: continue
        for off in range(sec['offset'],sec['offset']+sec['size'],sec['entsize'] or 24):
            target,info,addend=struct.unpack_from('<QQq',data,off)
            if info&0xffffffff!=257: continue
            symbols=elf.sections[sec['link']]
            index=info>>32
            symbol_off=symbols['offset']+index*(symbols['entsize'] or 24)
            if symbol_off+24>symbols['offset']+symbols['size']: raise ValueError('ABS64 symbol outside table')
            name,attrs,other,defined,value,size=struct.unpack_from('<IBBHQQ',data,symbol_off)
            if defined:
                elf.relocations[target]=value+addend;abs_resolved+=1
            else: abs_unresolved+=1
    exports=[s for s in elf.symbols if s['defined'] and s['binding'] in (1,2)]
    imports=[s for s in elf.symbols if not s['defined']]
    java=[s for s in exports if s['name'].startswith('Java_')]
    onloads=[s for s in exports if s['name'] in ('JNI_OnLoad','JNI_OnUnload')]
    needed=[]
    for sec in elf.sections:
        if sec['type']!=6: continue
        st=elf.sections[sec['link']]
        strings=data[st['offset']:st['offset']+st['size']]
        for off in range(sec['offset'],sec['offset']+sec['size'],sec['entsize'] or 16):
            tag,value=struct.unpack_from('<qQ',data,off)
            if tag==1:
                end=strings.find(b'\0',value)
                needed.append(strings[value:end].decode('ascii'))
    methods_by_pair=defaultdict(list)
    for method in dex_methods:
        methods_by_pair[(method['method_name'],method['signature'])].append(method['descriptor'])
    candidates=[];scanned=0
    for sec in elf.sections:
        # Only file-backed, allocated, non-executable pointer tables.
        if not sec['flags']&2 or sec['flags']&4 or sec['type']==8 or sec['size']<24: continue
        start=(sec['vaddr']+7)&~7
        for address in range(start,sec['vaddr']+sec['size']-23,8):
            scanned+=1
            try:
                nameptr=elf.pointer(address)
                name=string_at(nameptr,256)
                if not name or not re.fullmatch(r'[A-Za-z_$][A-Za-z0-9_$]*',name): continue
                sigptr=elf.pointer(address+8)
                signature=string_at(sigptr)
                if not signature or not valid_signature(signature): continue
                fn=elf.pointer(address+16)
                if not elf.executable(fn): continue
                candidates.append({'table_address':hex(address),'section':sec['name'],'name':name,'signature':signature,
                                   'name_address':hex(nameptr),'signature_address':hex(sigptr),'function_address':hex(fn),
                                   'relocated_pointer_slots':sum(address+i in elf.relocations for i in (0,8,16)),
                                   'matching_dex_native_declarations':methods_by_pair.get((name,signature),[])})
            except (ValueError,struct.error): pass
    exports_by_name={s['name']:s for s in java}
    bindings=[]
    class_method_counts=Counter((m['class'],m['method_name']) for m in dex_methods)
    for method in dex_methods:
        short='Java_'+jni_escape(method['class'])+'_'+jni_escape(method['method_name'])
        long=short+'__'+jni_escape(method['signature'][1:method['signature'].index(')')])
        for symbol_name,kind in ((short,'short'),(long,'long')):
            if symbol_name in exports_by_name:
                symbol=exports_by_name[symbol_name]
                bindings.append({'dex_native_declaration':method['descriptor'],'symbol':symbol_name,'address':symbol['address'],
                                 'name_form':kind,'native_overload_count':class_method_counts[(method['class'],method['method_name'])],
                                 'executable_address':elf.executable(int(symbol['address'],16))})
    # Plain class strings are catalogued separately; proximity does not bind a registration table.
    class_strings=[]
    for cls in sorted({m['class'] for m in dex_methods}):
        needle=cls.encode()+b'\0';pos=0;locations=[]
        while True:
            pos=data.find(needle,pos)
            if pos<0: break
            try: locations.append(hex(elf.va(pos)))
            except ValueError: pass
            pos+=1
        if locations: class_strings.append({'class':cls,'addresses':locations})
    known_class_addresses={int(address,16):entry['class'] for entry in class_strings for address in entry['addresses']}
    tables={int(c['table_address'],16):c for c in candidates}
    class_table_records=[]
    for sec in elf.sections:
        if not sec['flags']&2 or sec['flags']&4 or sec['type']==8 or sec['size']<24: continue
        for address in range((sec['vaddr']+7)&~7,sec['vaddr']+sec['size']-23,8):
            try:
                cls=known_class_addresses.get(elf.pointer(address))
                if not cls: continue
                for table_slot,count_slot,layout in ((8,16,'class,methods,count'),(16,8,'class,count,methods')):
                    table=elf.pointer(address+table_slot);count=elf.pointer(address+count_slot)
                    if table not in tables or not 0<count<=512: continue
                    entries=[tables.get(table+i*24) for i in range(count)]
                    if not all(entries): continue
                    class_decls={m['descriptor'] for m in dex_methods if m['class']==cls}
                    if not all(class_decls.intersection(e['matching_dex_native_declarations']) for e in entries): continue
                    class_table_records.append({'record_address':hex(address),'layout':layout,'class':cls,
                                                'table_address':hex(table),'count':count,
                                                'all_entries_match_declaring_class_name_and_signature':True,
                                                'runtime_registration_proven':False})
            except (ValueError,struct.error): pass
    return {'sha256':hashlib.sha256(data).hexdigest(),'size':len(data),'dynamic_symbol_count':len(elf.symbols),
            'export_count':len(exports),'import_count':len(imports),'java_export_count':len(java),
            'needed_libraries':needed,'relocation_types':dict(elf.relocation_types),
            'resolved_relative_or_relr_pointer_count':len(elf.relocations)-abs_resolved,
            'locally_resolved_abs64_count':abs_resolved,'unresolved_import_abs64_count':abs_unresolved,
            'onload_exports':onloads,'pointer_slots_scanned':scanned,
            'plaintext_jni_candidate_count':len(candidates),
            'candidate_count_matching_dex_native_name_and_signature':sum(bool(c['matching_dex_native_declarations']) for c in candidates),
            'export_name_binding_count':len(bindings),'export_name_bindings':bindings,
            'plaintext_jni_candidates':candidates,'native_declaring_class_strings':class_strings,
            'plausible_class_table_records':class_table_records,'plausible_class_table_record_count':len(class_table_records),
            'java_exports':java,'exports':exports,'imports':imports,
            'runtime_registration_proven':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk',type=Path,required=True)
    parser.add_argument('--dex-catalog',type=Path,required=True)
    parser.add_argument('--private-output',type=Path,required=True)
    parser.add_argument('--summary',type=Path,required=True)
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1];out=args.private_output.resolve()
    if out.is_relative_to(root): raise ValueError('Native libraries/listings must stay outside source repository')
    out.mkdir(parents=True,exist_ok=True)
    dex=json.loads(args.dex_catalog.read_text(encoding='utf8'))
    methods=[]
    for d in dex['methods']:
        if not d['native']: continue
        cls,rest=d['name'].split(';->',1);name,signature=rest.split('(',1)
        methods.append({'class':cls[1:],'method_name':name,'signature':'('+signature,'descriptor':d['name']})
    summaries=[];bindings=[];candidates=[]
    with zipfile.ZipFile(args.apk) as archive:
        for member in archive.namelist():
            if not re.fullmatch(r'lib/[^/]+/[^/]+\.so',member): continue
            data=archive.read(member);name=Path(member).name
            (out/name).write_bytes(data)
            catalog=library_catalog(data,methods)
            (out/(name+'.json')).write_text(json.dumps(catalog,ensure_ascii=False,indent=2),encoding='utf8')
            summaries.append({'apk_path':member,**{k:v for k,v in catalog.items() if k not in ('exports','imports','java_exports','plaintext_jni_candidates','export_name_bindings','native_declaring_class_strings','plausible_class_table_records')}})
            bindings.extend({'library':name,**b} for b in catalog['export_name_bindings'])
            candidates.extend({'library':name,**c} for c in catalog['plaintext_jni_candidates'])
    exact={b['dex_native_declaration'] for b in bindings if b['executable_address']}
    candidate_matches={d for c in candidates for d in c['matching_dex_native_declarations']}
    summary={'apk':str(args.apk),'apk_sha256':hashlib.file_digest(args.apk.open('rb'),'sha256').hexdigest(),
             'native_library_count':len(summaries),'dex_native_declaration_count':len(methods),'libraries':summaries,
             'dex_native_declarations_with_exact_export_name':len(exact),
             'dex_native_declarations_with_candidate_name_signature_match':len(candidate_matches),
             'dex_native_declarations_without_export_or_candidate':len(methods)-len(exact|candidate_matches),
             'unique_candidate_name_signature_pairs':len({(c['name'],c['signature']) for c in candidates}),
             'exact_export_matches_by_declaring_class':dict(Counter(d.split(';->')[0][1:] for d in exact)),
             'candidate_matches_by_declaring_class':dict(Counter(d.split(';->')[0][1:] for d in candidate_matches)),
             'private_artifacts':str(out),'limitations':['No target library was loaded or executed.',
                 'Export-name matching identifies a JNI naming-convention association, not successful runtime resolution.',
                 'JNINativeMethod candidates require valid plaintext name/signature and local executable function pointer; RegisterNatives calls and class arguments are not proven.',
                 'Name/signature matching across classes is ambiguous and is never reported as a proven dynamic class binding.',
                 'Encrypted, generated, packed, unaligned, unresolved-import or runtime-constructed tables can be missed.',
                 'Target ELF VAs are relative static addresses; ASLR/runtime load bases are not established.']}
    (out/'dex-export-bindings.json').write_text(json.dumps(bindings,ensure_ascii=False,indent=2),encoding='utf8')
    (out/'jni-table-candidates.json').write_text(json.dumps(candidates,ensure_ascii=False,indent=2),encoding='utf8')
    (out/'unresolved-dex-native-declarations.json').write_text(json.dumps([m for m in methods if m['descriptor'] not in exact|candidate_matches],ensure_ascii=False,indent=2),encoding='utf8')
    args.summary.parent.mkdir(parents=True,exist_ok=True)
    args.summary.write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf8')
    print(json.dumps({k:v for k,v in summary.items() if k not in ('libraries','limitations')},ensure_ascii=False))


if __name__=='__main__':
    main()
