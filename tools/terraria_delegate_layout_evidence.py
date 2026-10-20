"""Verify metadata field names and native offset slots, without assigning object types to unnamed code."""
import argparse, hashlib, json, pathlib, struct
from terraria_native_map import ELF
from terraria_metadata_catalog import TABLES


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',type=pathlib.Path,required=True);a=ap.parse_args();lab=a.lab
    metadata=lab/'native/global-metadata.dat';binary=lab/'native/libil2cpp.so';raw=metadata.read_bytes();elf=ELF(binary.read_bytes())
    if sha(binary)!='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5' or sha(metadata)!='4c904c49d168913d28ef547c4f461e539d926d2ed27c0253ed53a2954e9585f7':raise ValueError('Original source mismatch')
    if struct.unpack_from('<II',raw)!=(0xfab11baf,31):raise ValueError('Metadata v31 required')
    spans={name:struct.unpack_from('<II',raw,8+i*8) for i,(name,_,_) in enumerate(TABLES)}
    formats={name:fmt for name,fmt,_ in TABLES}
    def record(name,index):
        offset,size=spans[name];width=struct.calcsize(formats[name]);p=offset+index*width
        if index<0 or p+width>offset+size:raise ValueError('Metadata record out of bounds')
        return p,struct.unpack_from(formats[name],raw,p)
    def string(index):
        offset,size=spans['strings']
        if not 0<=index<size:raise ValueError('String index out of bounds')
        return raw[offset+index:raw.index(b'\0',offset+index,offset+size)].decode('utf8')
    layouts=json.loads((lab/'native/type-layouts.json').read_text());evidence=[]
    with (lab/'metadata/fields.jsonl').open(encoding='utf8') as stream:
        for line in stream:
            field=json.loads(line)
            if field['owner_type'] not in ('System.Delegate','System.MulticastDelegate'):continue
            layout=layouts[field['owner_type_index']];tp,typ=record('types',field['owner_type_index'])
            typekeys=TABLES[next(i for i,x in enumerate(TABLES) if x[0]=='types')][2].split();values=dict(zip(typekeys,typ))
            typename=string(values['namespace_index'])+'.'+string(values['name_index'])
            if typename!=field['owner_type'] or values['field_start']!=layout['field_start']:raise ValueError('Owner identity mismatch')
            p,rec=record('fields',field['index'])
            if rec!=(field['name_index'],field['type_index'],field['token']) or string(rec[0])!=field['name']:raise ValueError('Field source mismatch')
            local=field['index']-values['field_start']
            if not 0<=local<values['field_count']:raise ValueError('Field owner bounds mismatch')
            slot=int(layout['field_offsets_pointer'],16)+local*4;offset=elf.file_offset(slot);native=struct.unpack_from('<i',elf.data,offset)[0]
            if native!=field['native_field_offset_raw'] or native!=layout['field_offsets'][local]:raise ValueError('Native field offset mismatch')
            evidence.append({'owner_type':typename,'field':field['name'],'field_index':field['index'],'metadata_field_file_offset':hex(p),
                             'metadata_type_file_offset':hex(tp),'name_string_index':rec[0],'native_offset':native,'native_offset_slot':hex(slot),
                             'native_offset_raw_bytes':elf.data[offset:offset+4].hex()})
    if len(evidence)!=14:raise ValueError('Incomplete delegate field scope')
    out=lab/'native-continuation-20261014';out.mkdir(exist_ok=True)
    doc={'elf_sha256':sha(binary),'metadata_sha256':sha(metadata),'producer_sha256':sha(pathlib.Path(__file__)),
         'verified_field_names_and_offsets':evidence,'interpretation':'Observed code offsets can be compared with these verified layouts. Matching offsets alone do not prove the input object is a Delegate or MulticastDelegate, nor recover an unnamed function identity.'}
    (out/'delegate-layout-offsets.json').write_text(json.dumps(doc,ensure_ascii=False,indent=2)+'\n',encoding='utf8');print(json.dumps({'verified_fields':len(evidence)}))


if __name__=='__main__':main()
