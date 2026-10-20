"""Offline IL2CPP v31 method-token to ELF64/AArch64 address recovery.

Preserves executable and metadata bytes outside the source repository. This is
an address catalog, not source recovery or proof of precise function extents.
Only Python's standard library is needed; no target code is executed.
"""
import argparse
import csv
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
import struct
import zipfile

ROOT = Path(__file__).resolve().parents[1]
META_PATH = 'assets/bin/Data/Managed/Metadata/global-metadata.dat'
LIB_PATH = 'lib/arm64-v8a/libil2cpp.so'


def digest(data):
    return hashlib.sha256(data).hexdigest()


class ELF:
    def __init__(self, data):
        self.data = data
        if data[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', data, 18)[0] != 183:
            raise ValueError('Expected ELF64 little-endian AArch64')
        self.segments = []
        phoff = struct.unpack_from('<Q', data, 32)[0]
        phsize, phcount = struct.unpack_from('<HH', data, 54)
        for i in range(phcount):
            p = struct.unpack_from('<II6Q', data, phoff + i * phsize)
            self.segments.append(dict(type=p[0], flags=p[1], offset=p[2], vaddr=p[3], filesz=p[5], memsz=p[6]))
        shoff = struct.unpack_from('<Q', data, 40)[0]
        shsize, shcount, shstrndx = struct.unpack_from('<3H', data, 58)
        records = [struct.unpack_from('<IIQQQQIIQQ', data, shoff+i*shsize) for i in range(shcount)]
        s = records[shstrndx]
        pool = data[s[4]:s[4]+s[5]]
        self.sections = []
        for p in records:
            name = pool[p[0]:pool.find(b'\0', p[0])].decode('utf-8')
            self.sections.append(dict(name=name, type=p[1], flags=p[2], vaddr=p[3], offset=p[4], size=p[5], link=p[6], entsize=p[9]))
        self.relocations = {}
        self.relocation_types = Counter()
        for s in self.sections:
            if s['type'] == 4:  # SHT_RELA
                for off in range(s['offset'], s['offset']+s['size'], s['entsize'] or 24):
                    target, info, addend = struct.unpack_from('<QQq', data, off)
                    typ = info & 0xffffffff
                    self.relocation_types[str(typ)] += 1
                    if typ == 1027:  # R_AARCH64_RELATIVE
                        self.relocations[target] = addend
            if s['type'] == 19:  # SHT_RELR; in-place addends, ELF64 bitmap format
                where = 0
                for off in range(s['offset'], s['offset']+s['size'], 8):
                    entry = struct.unpack_from('<Q', data, off)[0]
                    if not entry & 1:
                        where = entry
                        self.relocations[where] = self.raw_pointer(where)
                        where += 8
                    else:
                        for bit in range(1,64):
                            if entry & (1 << bit):
                                target = where + (bit-1)*8
                                self.relocations[target] = self.raw_pointer(target)
                        where += 63*8
        self.symbols = []
        for s in self.sections:
            if s['type'] != 11:
                continue
            st = self.sections[s['link']]
            strings = data[st['offset']:st['offset']+st['size']]
            for off in range(s['offset'], s['offset']+s['size'], s['entsize'] or 24):
                n, info, other, shndx, value, size = struct.unpack_from('<IBBHQQ', data, off)
                name = strings[n:strings.find(b'\0', n)].decode('utf-8', 'replace') if n else ''
                if name:
                    self.symbols.append(dict(name=name, defined=bool(shndx), binding=info>>4, type=info&15, address=hex(value), size=size))

    def file_offset(self, va):
        for s in self.segments:
            if s['type'] == 1 and s['vaddr'] <= va < s['vaddr']+s['filesz']:
                return s['offset']+va-s['vaddr']
        raise ValueError(f'VA outside file-backed LOAD segments: {va:x}')

    def va(self, off):
        for s in self.segments:
            if s['type'] == 1 and s['offset'] <= off < s['offset']+s['filesz']:
                return s['vaddr']+off-s['offset']
        raise ValueError('Offset outside LOAD segments')

    def raw_pointer(self, va):
        return struct.unpack_from('<Q', self.data, self.file_offset(va))[0]

    def pointer(self, va):
        return self.relocations.get(va, self.raw_pointer(va))

    def executable(self, va):
        return any(s['type']==1 and s['flags']&1 and s['vaddr']<=va<s['vaddr']+s['filesz'] for s in self.segments)


def metadata(data):
    if struct.unpack_from('<II', data) != (0xfab11baf, 31):
        raise ValueError('Expected metadata v31')
    def table(header, stride):
        start, size = struct.unpack_from('<II', data, header)
        if start+size > len(data) or size % stride:
            raise ValueError(f'Invalid metadata table {header}')
        return [struct.unpack_from({40:'<10I',88:'<16I8H2I',36:'<7I4H'}[stride], data, off) for off in range(start,start+size,stride)]
    string_start, string_size = struct.unpack_from('<II', data, 24)
    def name(i):
        if i>=string_size:
            raise ValueError('String index outside table')
        start=string_start+i
        return data[start:data.index(b'\0',start,string_start+string_size)].decode('utf-8')
    images=table(168,40)
    types=table(160,88)
    methods=table(48,36)
    owners={}
    image_rows=[]
    for im in images:
        image_name=name(im[0])
        for ti in range(im[2],im[2]+im[3]):
            owners[ti]=image_name
        image_rows.append(dict(name=image_name,type_start=im[2],type_count=im[3]))
    type_names=[]
    for t in types:
        ns=name(t[1])
        type_names.append((ns+'.' if ns else '')+name(t[0]))
    # declaringType is an Il2CppType index, not a TypeDefinition index.
    # Recover nested ownership from the nestedTypes table instead.
    nested_start,nested_size=struct.unpack_from('<II',data,128)
    nested=struct.unpack_from('<'+str(nested_size//4)+'I',data,nested_start)
    for _ in range(8):
        changed=False
        for ti,t in enumerate(types):
            for ni in range(t[12],t[12]+t[20]) if t[12]!=0xffffffff else []:
                child=nested[ni]
                n=type_names[ti]+'+'+name(types[child][0])
                if type_names[child]!=n:
                    type_names[child]=n;changed=True
        if not changed: break
    rows=[]
    for mi,m in enumerate(methods):
        rows.append(dict(method_index=mi,image=owners.get(m[1],''),type_index=m[1],type=type_names[m[1]],name=name(m[0]),token=hex(m[6]),rid=m[6]&0xffffff,parameter_count=m[10],flags=hex(m[7]),generic_container_index=m[5]))
    return image_rows,rows,type_names,types


def recover_registration(elf, meta, type_names, type_records, output):
    """Find metadata registration using two matching typedef-count fields.

    The layout is accepted only after all typedef byval indices resolve to
    the same definition index (apart from primitive type tags).
    """
    n=len(type_records)
    needle=struct.pack('<Q',n)
    candidates=[]
    start=0
    while True:
        start=elf.data.find(needle,start)
        if start<0: break
        if elf.data[start+16:start+24]==needle:
            try:
                va=elf.va(start)-80
                count=elf.pointer(va+48)
                table=elf.pointer(va+56)
                if not n<=count<1000000: raise ValueError('Invalid type count')
                checks=0
                for ti,t in enumerate(type_records):
                    p=elf.pointer(table+8*t[2])
                    off=elf.file_offset(p)
                    data,bits=struct.unpack_from('<QI',elf.data,off)
                    tag=(bits>>16)&255
                    if tag in (17,18) and data!=ti: raise ValueError('Type definition crosscheck failed')
                    checks+=1
                candidates.append(dict(address=hex(va),types_count=count,types_pointer_array=hex(table),typedef_byval_crosschecks=checks))
            except (ValueError,struct.error): pass
        start+=1
    if len(candidates)!=1:
        return dict(status='unresolved',candidate_count=len(candidates))
    reg=candidates[0]
    base=int(reg['address'],16)
    names=['generic_classes','generic_insts','generic_method_table','types','method_specs','field_offsets','type_sizes','metadata_usages']
    for i,name in enumerate(names):
        reg[name+'_count']=elf.pointer(base+i*16)
        reg[name+'_pointer']=hex(elf.pointer(base+i*16+8))
    type_table=int(reg['types_pointer_array'],16)
    generic_start,generic_size=struct.unpack_from('<II',meta,104)
    string_start,string_size=struct.unpack_from('<II',meta,24)
    def generic_name(index):
        if index>=generic_size//16: return f'!unknown_{index}'
        strindex=struct.unpack_from('<I',meta,generic_start+16*index+4)[0]
        off=string_start+strindex
        return meta[off:meta.index(b'\0',off,string_start+string_size)].decode()
    primitives={1:'System.Void',2:'System.Boolean',3:'System.Char',4:'System.SByte',5:'System.Byte',6:'System.Int16',7:'System.UInt16',8:'System.Int32',9:'System.UInt32',10:'System.Int64',11:'System.UInt64',12:'System.Single',13:'System.Double',14:'System.String',22:'System.TypedReference',24:'System.IntPtr',25:'System.UIntPtr',28:'System.Object'}
    cache={}
    def resolve(pointer,depth=0):
        if pointer in cache: return cache[pointer]
        if depth>32: return '<depth-limit>'
        try:
            off=elf.file_offset(pointer)
            data,bits=struct.unpack_from('<QI',elf.data,off)
            tag=(bits>>16)&255
            if tag in primitives: name=primitives[tag]
            elif tag in (17,18): name=type_names[data] if data<len(type_names) else f'<bad-typedef:{data}>'
            elif tag in (15,16,29): name=resolve(data,depth+1)+{15:'*',16:'&',29:'[]'}[tag]
            elif tag in (19,30): name=('!!' if tag==30 else '!')+generic_name(data)
            elif tag==20:
                elem=elf.pointer(data)
                rank=elf.data[elf.file_offset(data+8)]
                name=resolve(elem,depth+1)+'['+','*max(0,rank-1)+']'
            elif tag==21:
                definition=elf.pointer(data)
                instance=elf.pointer(data+8)
                argc=struct.unpack_from('<I',elf.data,elf.file_offset(instance))[0]
                if argc>1024: raise ValueError('Generic argument count invalid')
                argv=elf.pointer(instance+8)
                args=[resolve(elf.pointer(argv+i*8),depth+1) for i in range(argc)]
                name=re.sub(r'`\d+','',resolve(definition,depth+1))+'<'+', '.join(args)+'>'
            else: name=f'<unresolved-type-tag:0x{tag:x},data:0x{data:x}>'
            if bits&(1<<29): name+='&'
            cache[pointer]=name
            return name
        except (ValueError,struct.error,IndexError): return f'<invalid-type-pointer:0x{pointer:x}>'
    rows=[]
    for i in range(reg['types_count']):
        pointer=elf.pointer(type_table+i*8)
        data,bits=struct.unpack_from('<QI',elf.data,elf.file_offset(pointer))
        rows.append(dict(type_index=i,pointer=hex(pointer),data=hex(data),type_tag=(bits>>16)&255,attributes=bits&65535,byref=bool(bits&(1<<29)),pinned=bool(bits&(1<<30)),value_type=bool(bits&(1<<31)),name=resolve(pointer)))
    unresolved=[r for r in rows if '<unresolved' in r['name'] or '<invalid' in r['name'] or '<bad-' in r['name'] or '<depth-' in r['name']]
    reg['decoded_type_count']=len(rows)-len(unresolved)
    reg['unresolved_type_count']=len(unresolved)
    reg['type_tags']=dict(Counter(r['type_tag'] for r in rows))
    (output/'il2cpp-types.json').write_text(json.dumps(dict(registration=reg,types=rows),ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    instances=[]
    for i in range(reg['generic_insts_count']):
        pointer=elf.pointer(int(reg['generic_insts_pointer'],16)+i*8)
        argc=struct.unpack_from('<I',elf.data,elf.file_offset(pointer))[0]
        if argc>1024: raise ValueError('Generic inst argc outside bound')
        argv=elf.pointer(pointer+8)
        instances.append(dict(index=i,pointer=hex(pointer),arguments=[resolve(elf.pointer(argv+j*8)) for j in range(argc)]))
    (output/'generic-instances.json').write_text(json.dumps(instances,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    layouts=[]
    field_offsets=int(reg['field_offsets_pointer'],16)
    type_sizes=int(reg['type_sizes_pointer'],16)
    for ti,t in enumerate(type_records):
        fp=elf.pointer(field_offsets+ti*8)
        sp=elf.pointer(type_sizes+ti*8)
        size=struct.unpack_from('<IiII',elf.data,elf.file_offset(sp)) if sp else None
        offsets=[]
        if fp:
            offsets=list(struct.unpack_from('<'+str(t[18])+'i',elf.data,elf.file_offset(fp)))
        layouts.append(dict(type_definition_index=ti,name=type_names[ti],field_start=t[8],field_count=t[18],field_offsets_pointer=hex(fp),field_offsets=offsets,instance_size=size[0] if size else None,native_size=size[1] if size else None,static_fields_size=size[2] if size else None,thread_static_fields_size=size[3] if size else None))
    (output/'type-layouts.json').write_text(json.dumps(layouts,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    return reg


def recover_generics(elf,registration,modules,methods,output,image_count):
    if 'generic_method_table_count' not in registration: return dict(status='metadata_registration_unresolved')
    # A contiguous table of codegen-module pointers terminates the code registration.
    known={int(m['module_address'],16) for m in modules.values()}
    refs=sorted(a for a,v in elf.relocations.items() if v in known)
    if not refs: return dict(status='module_array_unresolved')
    array=refs[0]
    candidates=[]
    for addr,value in elf.relocations.items():
        if value==array and elf.pointer(addr-8)==image_count:
            base=addr-112
            count=elf.pointer(base+16)
            pointer=elf.pointer(base+24)
            if 0<count<1000000:
                candidates.append((base,count,pointer))
    if len(candidates)!=1: return dict(status='code_registration_unresolved',candidate_count=len(candidates))
    base,count,pointer=candidates[0]
    generic_pointers=[elf.pointer(pointer+8*i) for i in range(count)]
    if not all(p==0 or elf.executable(p) for p in generic_pointers):
        return dict(status='generic_method_pointer_validation_failed')
    table=int(registration['generic_method_table_pointer'],16)
    specs=int(registration['method_specs_pointer'],16)
    instances=json.loads((output/'generic-instances.json').read_text(encoding='utf-8'))
    def args(index): return instances[index]['arguments'] if index>=0 else []
    rows=[]
    for i in range(registration['generic_method_table_count']):
        si,pi,invoker,adjustor=struct.unpack_from('<4i',elf.data,elf.file_offset(table)+16*i)
        if not 0<=si<registration['method_specs_count'] or not -1<=pi<count:
            raise ValueError('Generic mapping table outside registration bounds')
        mi,ci,gi=struct.unpack_from('<3i',elf.data,elf.file_offset(specs)+12*si)
        if not 0<=mi<len(methods): raise ValueError('MethodSpec definition index outside table')
        m=methods[mi]
        address=generic_pointers[pi] if pi>=0 else 0
        rows.append(dict(generic_table_index=i,method_spec_index=si,method_index=mi,image=m['image'],type=m['type'],name=m['name'],class_inst_index=ci,class_arguments=args(ci),method_inst_index=gi,method_arguments=args(gi),generic_method_pointer_index=pi,invoker_index=invoker,adjustor_thunk_index=adjustor,address=hex(address) if address else None,status='mapped' if address else 'null_generic_method_pointer'))
    (output/'generic-method-addresses.json').write_text(json.dumps(rows,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    with (output/'generic-method-addresses.csv').open('w',newline='',encoding='utf-8-sig') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    with (output/'generic-method-seeds.tsv').open('w',encoding='utf-8',newline='') as f:
        w=csv.writer(f,delimiter='\t',lineterminator='\n')
        written=set()
        for r in rows:
            if r['address'] and r['address'] not in written:
                written.add(r['address'])
                fullname=r['type']+('['+', '.join(r['class_arguments'])+']' if r['class_arguments'] else '')+'::'+r['name']+('['+', '.join(r['method_arguments'])+']' if r['method_arguments'] else '')
                label=re.sub(r'[^a-zA-Z0-9_]','_',fullname)+'__generic_'+str(r['generic_table_index'])
                w.writerow([r['address'],label,fullname,r['image']])
    generic_definitions={r['method_index'] for r in rows if r['address']}
    concrete_unresolved=[m for m in methods if not m['address'] and m['method_index'] not in generic_definitions and not int(m['flags'],16)&0x400]
    return dict(status='mapped',code_registration_address=hex(base),module_pointer_array=hex(array),codegen_module_count=image_count,generic_method_pointer_count=count,generic_table_rows=len(rows),mapping_status=dict(Counter(r['status'] for r in rows)),unique_generic_addresses=len(written),overlap_direct_method_addresses=len(written&{m['address'] for m in methods if m['address']}),generic_method_definition_count=len(generic_definitions),declarations_with_any_implementation=sum(bool(m['address']) or m['method_index'] in generic_definitions for m in methods),remaining_abstract_declarations=sum(not m['address'] and m['method_index'] not in generic_definitions and bool(int(m['flags'],16)&0x400) for m in methods),remaining_concrete_declarations=len(concrete_unresolved),remaining_concrete_method_indices=[m['method_index'] for m in concrete_unresolved])


def crosscheck_historical_fields(meta, output, prior):
    if not (output/'type-layouts.json').exists(): return []
    layouts=json.loads((output/'type-layouts.json').read_text(encoding='utf-8'))
    types=json.loads((output/'il2cpp-types.json').read_text(encoding='utf-8'))['types']
    byname={r['name']:r for r in layouts}
    ss,sz=struct.unpack_from('<II',meta,24)
    fs,_=struct.unpack_from('<II',meta,96)
    ts,_=struct.unpack_from('<II',meta,160)
    checks=[]
    for group,cls in [('player_fields','Terraria.Player'),('entity_fields','Terraria.Entity'),('npc_fields','Terraria.NPC'),('main_fields','Terraria.Main')]:
        for field,old in prior.get(group,{}).items():
            if old is None: continue
            row=byname.get(cls)
            while row:
                names=[]
                for i in range(row['field_count']):
                    index=struct.unpack_from('<I',meta,fs+12*(row['field_start']+i))[0]
                    off=ss+index
                    names.append(meta[off:meta.index(b'\0',off,ss+sz)].decode('utf-8'))
                if field in names:
                    value=row['field_offsets'][names.index(field)]
                    checks.append(dict(type=cls,field=field,declared_by=row['name'],offline_offset=value,historical_offset=old['offset'],match=value==old['offset']))
                    break
                parent=struct.unpack_from('<I',meta,ts+88*row['type_definition_index']+16)[0]
                row=layouts[int(types[parent]['data'],16)] if parent!=0xffffffff and types[parent]['type_tag'] in (17,18) else None
    return checks


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('apk',type=Path)
    ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--report',type=Path,required=True)
    args=ap.parse_args()
    if args.output.resolve().is_relative_to(ROOT):
        raise ValueError('Keep extracted game and derived catalogs outside repository')
    args.output.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(args.apk) as z:
        lib=z.read(LIB_PATH)
        meta=z.read(META_PATH)
    for filename,data in [('libil2cpp.so',lib),('global-metadata.dat',meta)]:
        target=args.output/filename
        if not target.exists(): target.write_bytes(data)
        elif digest(target.read_bytes())!=digest(data): raise ValueError('Output contains a different target: '+str(target))
    elf=ELF(lib)
    images,rows,type_names,type_records=metadata(meta)
    modules={}
    candidates=[]
    ptr_refs=defaultdict(list)
    for va,value in elf.relocations.items():
        ptr_refs[value].append(va)
    for image in images:
        needle=image['name'].encode()+b'\0'
        off=0
        while True:
            off=lib.find(needle,off)
            if off<0:
                break
            try:
                name_va=elf.va(off)
            except ValueError:
                off+=1;continue
            for candidate in ptr_refs[name_va]:
                try:
                    count=struct.unpack_from('<I',lib,elf.file_offset(candidate+8))[0]
                    pointer=elf.pointer(candidate+16)
                    methods=[r for r in rows if r['image']==image['name']]
                    max_rid=max((r['rid'] for r in methods),default=0)
                    if not 0<count<1000000 or count<max_rid:
                        continue
                    samples=[elf.pointer(pointer+8*(r['rid']-1)) for r in methods[:40]]
                    valid=sum(v==0 or elf.executable(v) for v in samples)
                    if valid==len(samples):
                        item=dict(image=image['name'],module_address=hex(candidate),method_pointer_count=count,max_method_rid=max_rid,method_pointer_array=hex(pointer),sample_count=len(samples),sample_executable_or_null=valid)
                        candidates.append(item)
                        if count==max_rid:
                            modules[image['name']]=item
                except (ValueError,struct.error):
                    pass
            off+=1
    for image in images:
        matches=[m for m in candidates if m['image']==image['name'] and m['method_pointer_count']==m['max_method_rid']]
        if len(matches)!=1:
            modules.pop(image['name'],None)
    for r in rows:
        mod=modules.get(r['image'])
        if not mod:
            r.update(address=None,file_offset=None,status='module_not_uniquely_resolved')
            continue
        pointer=elf.pointer(int(mod['method_pointer_array'],16)+8*(r['rid']-1))
        status='mapped' if pointer and elf.executable(pointer) else ('null_method_pointer' if not pointer else 'non_executable_pointer')
        r.update(address=hex(pointer) if pointer else None,file_offset=hex(elf.file_offset(pointer)) if pointer and elf.executable(pointer) else None,status=status)
    aliases=Counter(r['address'] for r in rows if r['status']=='mapped')
    for r in rows:
        r['address_alias_count']=aliases[r['address']] if r['address'] else 0
    if not (args.output/'method-seeds.tsv').exists():
        with (args.output/'method-seeds.tsv').open('w',encoding='utf-8',newline='') as f:
            w=csv.writer(f,delimiter='\t',lineterminator='\n')
            for r in rows:
                if r['status']=='mapped':
                    fullname=r['type']+'::'+r['name']
                    label=re.sub(r'[^a-zA-Z0-9_]','_',fullname)+'__'+str(r['method_index'])
                    w.writerow([r['address'],label,fullname,r['image']])
    registration=recover_registration(elf,meta,type_names,type_records,args.output)
    generic_registration=recover_generics(elf,registration,modules,rows,args.output,len(images))
    (args.output/'method-addresses.json').write_text(json.dumps(rows,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    with (args.output/'method-addresses.csv').open('w',newline='',encoding='utf-8-sig') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    (args.output/'elf-symbols.json').write_text(json.dumps(elf.symbols,indent=2)+'\n',encoding='utf-8')
    checks=[]
    prior=ROOT/'reports/android-respawn-method-metadata.json'
    if prior.exists():
        data=json.loads(prior.read_text(encoding='utf-8'))
        for group,typ in [('player_methods','Terraria.Player'),('main_methods','Terraria.Main'),('entity_methods','Terraria.Entity')]:
            for m in data.get(group,[]):
                matches=[r for r in rows if r['type']==typ and r['name']==m['name'] and r['parameter_count']==len(m['parameters'])]
                checks.append(dict(type=typ,name=m['name'],prior_address=m['native_module_offset'],offline_addresses=[r['address'] for r in matches],match=any(r['address']==m['native_module_offset'] for r in matches)))
    summary=dict(apk_path=str(args.apk),apk_sha256=hashlib.file_digest(args.apk.open('rb'),'sha256').hexdigest(),libil2cpp_sha256=digest(lib),metadata_sha256=digest(meta),metadata_version=31,abi='arm64-v8a',source='Offline token RID -> Il2CppCodeGenModule.methodPointers via ELF relocation-backed module-name reference; exact count match required',images=images,modules=list(modules.values()),module_candidate_count=len(candidates),metadata_method_count=len(rows),mapping_status=dict(Counter(r['status'] for r in rows)),unique_mapped_addresses=len(aliases),per_image={im['name']:dict(Counter(r['status'] for r in rows if r['image']==im['name'])) for im in images},elf=dict(size=len(lib),segments=elf.segments,sections=elf.sections,relocation_types=dict(elf.relocation_types),resolved_relative_pointer_count=len(elf.relocations),dynamic_symbol_count=len(elf.symbols),defined_dynamic_symbols=sum(s['defined'] for s in elf.symbols),il2cpp_export_count=sum(s['defined'] and s['name'].startswith('il2cpp_') for s in elf.symbols)),prior_runtime_crosschecks=checks,output_directory=str(args.output),limitations=['Static address recovery does not reconstruct original C# bodies, source comments, or exact function end addresses.','Null pointers may represent abstract/interface methods or generic methods whose shared implementations require separate generic registration analysis.','Method aliases can share implementation addresses; mapping does not prove semantic equivalence.','Prior runtime report is historical supporting evidence; this run does not execute the APK.'])
    summary['metadata_registration']=registration
    summary['generic_registration']=generic_registration
    summary['prior_runtime_field_offset_crosschecks']=crosscheck_historical_fields(meta,args.output,data) if prior.exists() else []
    summary['total_unique_managed_implementation_addresses']=len(aliases)+generic_registration.get('unique_generic_addresses',0)-generic_registration.get('overlap_direct_method_addresses',0)
    summary['limitations'][1]='Generic methods require context instantiations; the separate generic-method-addresses catalog maps available registered instances. Remaining concrete methods with no implementation address are explicitly counted.'
    summary['method_seeds_tsv']=str(args.output/'method-seeds.tsv')
    args.report.parent.mkdir(parents=True,exist_ok=True)
    args.report.write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    (args.output/'module-candidates.json').write_text(json.dumps(candidates,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:summary[k] for k in ['metadata_method_count','mapping_status','unique_mapped_addresses','module_candidate_count','prior_runtime_crosschecks','output_directory']},indent=2))


if __name__=='__main__':
    main()
