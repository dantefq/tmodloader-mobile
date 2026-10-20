"""Read-only APK/DEX/AXML catalog; private full listings stay outside this repository."""
import argparse
import collections
import hashlib
import json
import mmap
from pathlib import Path
import re
import struct
import zipfile
from apk_format import string_pool


def lz4_block(data, expected):
    """Decode raw LZ4 block with explicit size/bounds checks."""
    pos=0; out=bytearray()
    while pos<len(data):
        token=data[pos];pos+=1
        length=token>>4
        if length==15:
            while True:
                extra=data[pos];pos+=1;length+=extra
                if extra!=255: break
        if pos+length>len(data): raise ValueError('LZ4 literal outside input')
        out.extend(data[pos:pos+length]);pos+=length
        if pos==len(data): break
        offset=struct.unpack_from('<H',data,pos)[0];pos+=2
        if not 0<offset<=len(out): raise ValueError('LZ4 invalid match offset')
        length=(token&15)+4
        if (token&15)==15:
            while True:
                extra=data[pos];pos+=1;length+=extra
                if extra!=255: break
        if len(out)+length>expected: raise ValueError('LZ4 output exceeds expected size')
        while length:
            take=min(length,offset)
            start=len(out)-offset
            out.extend(out[start:start+take])
            length-=take
    if len(out)!=expected: raise ValueError('LZ4 decompressed size mismatch')
    return bytes(out)


def unityfs_catalog(data):
    pos=0
    def cstring():
        nonlocal pos
        end=data.index(0,pos);value=data[pos:end].decode('utf8');pos=end+1
        return value
    signature=cstring()
    if signature!='UnityFS': raise ValueError('Not a UnityFS bundle')
    version=struct.unpack_from('>I',data,pos)[0];pos+=4
    unity_version=cstring();generator=cstring()
    size,compressed,uncompressed,flags=struct.unpack_from('>QIII',data,pos);pos+=20
    if version>=7: pos=(pos+15)&~15
    start=len(data)-compressed if flags&0x80 else pos
    packed=data[start:start+compressed]
    codec=flags&63
    if codec==0: info=packed
    elif codec in (2,3): info=lz4_block(packed,uncompressed)
    else: raise ValueError('Unsupported UnityFS block-info codec '+str(codec))
    cursor=16
    count=struct.unpack_from('>I',info,cursor)[0];cursor+=4
    blocks=[]
    for _ in range(count):
        usize,csize,bflags=struct.unpack_from('>IIH',info,cursor);cursor+=10
        blocks.append({'uncompressed_size':usize,'compressed_size':csize,'flags':bflags})
    count=struct.unpack_from('>I',info,cursor)[0];cursor+=4
    nodes=[]
    for _ in range(count):
        offset,length,nflags=struct.unpack_from('>QQI',info,cursor);cursor+=20
        end=info.index(0,cursor)
        name=info[cursor:end].decode('utf8');cursor=end+1
        nodes.append({'path':name,'offset':offset,'size':length,'flags':nflags})
    data_start=pos if flags&0x80 else pos+compressed
    if flags&0x200: data_start=(data_start+15)&~15
    total=sum(b['uncompressed_size'] for b in blocks)
    return {'signature':signature,'format_version':version,'unity_version':unity_version,
            'generator_version':generator,'declared_size':size,'actual_size':len(data),'flags':hex(flags),
            'block_info_compressed_size':compressed,'block_info_uncompressed_size':uncompressed,
            'block_count':len(blocks),'node_count':len(nodes),'block_data_offset':data_start,
            'block_uncompressed_size':total,'block_compressed_size':sum(b['compressed_size'] for b in blocks),
            'all_nodes_within_block_data':all(n['offset']+n['size']<=total for n in nodes),
            'block_data_within_bundle':data_start+sum(b['compressed_size'] for b in blocks)<=len(data),
            'block_compression_counts':dict(collections.Counter(b['flags']&63 for b in blocks)),
            'nodes':nodes,'blocks':blocks}


def extract_unityfs(data, catalog, destination):
    """Stream bounded decoded blocks directly into node files, checking disk hashes."""
    destination.mkdir(parents=True,exist_ok=True)
    packed_pos=catalog['block_data_offset'];absolute=0;node_index=0;written=0
    nodes=sorted(catalog['nodes'],key=lambda n:n['offset'])
    for before,after in zip(nodes,nodes[1:]):
        if before['offset']+before['size']!=after['offset']: raise ValueError('Expected contiguous nodes')
    if nodes[0]['offset']!=0 or nodes[-1]['offset']+nodes[-1]['size']!=catalog['block_uncompressed_size']:
        raise ValueError('Nodes must cover complete decompressed stream')
    stream=None;hasher=None;results=[]
    try:
        for block in catalog['blocks']:
            packed=data[packed_pos:packed_pos+block['compressed_size']];packed_pos+=len(packed)
            codec=block['flags']&63
            decoded=packed if codec==0 else lz4_block(packed,block['uncompressed_size']) if codec in (2,3) else None
            if decoded is None or len(decoded)!=block['uncompressed_size']: raise ValueError('Unsupported or invalid payload block')
            local=0
            while local<len(decoded):
                node=nodes[node_index]
                if stream is None:
                    path=(destination/node['path']).resolve()
                    if not path.is_relative_to(destination.resolve()): raise ValueError('Unsafe bundle path')
                    path.parent.mkdir(parents=True,exist_ok=True)
                    stream=path.open('wb');hasher=hashlib.sha256();written=0
                take=min(len(decoded)-local,node['size']-written)
                part=decoded[local:local+take];stream.write(part);hasher.update(part)
                local+=take;absolute+=take;written+=take
                if written==node['size']:
                    stream.close();stream=None
                    with path.open('rb') as verify: diskhash=hashlib.file_digest(verify,'sha256').hexdigest()
                    if diskhash!=hasher.hexdigest() or path.stat().st_size!=node['size']: raise ValueError('Extracted node hash/size mismatch')
                    results.append({'path':str(path),'bundle_path':node['path'],'size':written,'sha256':diskhash,'disk_hash_verified':True})
                    node_index+=1
        if absolute!=catalog['block_uncompressed_size'] or packed_pos!=len(data) or node_index!=len(nodes):
            raise ValueError('UnityFS final coverage mismatch')
    finally:
        if stream is not None: stream.close()
    return {'decoded_block_count':len(catalog['blocks']),'decoded_bytes':absolute,'nodes':results,
            'all_node_disk_hashes_verified':True,'all_payload_blocks_size_checked':True}


UNITY_CLASS_NAMES={1:'GameObject',4:'Transform',21:'Material',28:'Texture2D',43:'Mesh',48:'Shader',49:'TextAsset',
                   83:'AudioClip',114:'MonoBehaviour',115:'MonoScript',128:'Font',142:'AssetBundle',213:'Sprite',
                   224:'RectTransform',687078895:'SpriteAtlas'}


def serialized_catalog(path):
    """Inventory modern Unity serialized headers/types/objects without reconstructing code."""
    with path.open('rb') as file, mmap.mmap(file.fileno(),0,access=mmap.ACCESS_READ) as data:
        if len(data)<48: raise ValueError('Too short for serialized file')
        metadata_size,filesize,version,data_offset=struct.unpack_from('>4I',data,0)
        endian='>' if data[16] else '<'
        cursor=20
        if version>=22:
            metadata_size,filesize,data_offset,unknown=struct.unpack_from('>IQQQ',data,cursor);cursor+=28
        if version<17 or version>22: raise ValueError('Unsupported serialized version '+str(version))
        if filesize!=len(data) or not cursor<=data_offset<=filesize: raise ValueError('Serialized file size/offset mismatch')
        metadata_start=cursor
        metadata_end=metadata_start+metadata_size
        if metadata_end>data_offset: raise ValueError('Metadata region overlaps object data')
        def read(fmt):
            nonlocal cursor
            size=struct.calcsize(endian+fmt)
            if cursor+size>metadata_end: raise ValueError('Serialized metadata read out of bounds')
            value=struct.unpack_from(endian+fmt,data,cursor);cursor+=size
            return value[0] if len(value)==1 else value
        def cstring():
            nonlocal cursor
            end=data.find(b'\0',cursor,metadata_end)
            if end<0: raise ValueError('Unterminated metadata string')
            value=data[cursor:end].decode('utf8',errors='replace');cursor=end+1
            return value
        unity_version=cstring();platform=read('i');typetree=read('?');type_count=read('i')
        if not 0<=type_count<100000: raise ValueError('Invalid serialized type count')
        types=[]
        for _ in range(type_count):
            cls=read('i');stripped=read('?');script_index=read('h')
            script_id=None
            if cls==114: script_id=data[cursor:cursor+16].hex();cursor+=16
            oldhash=data[cursor:cursor+16].hex();cursor+=16
            nodes=[]
            if typetree:
                node_count=read('i');string_size=read('i')
                if not 0<=node_count<100000 or not 0<=string_size<10000000: raise ValueError('Invalid type tree size')
                for _ in range(node_count):
                    vals=read('HBBIIiii'+('Q' if version>=19 else ''))
                    nodes.append({'level':vals[1],'type_offset':vals[3],'name_offset':vals[4],'byte_size':vals[5]})
                if cursor+string_size>metadata_end: raise ValueError('Type string buffer out of bounds')
                string_buffer=data[cursor:cursor+string_size];cursor+=string_size
                for node in nodes:
                    for kind in ('type','name'):
                        off=node[kind+'_offset']
                        if not off&0x80000000 and off<len(string_buffer):
                            end=string_buffer.find(b'\0',off)
                            node[kind]=string_buffer[off:end if end>=0 else len(string_buffer)].decode('utf8',errors='replace')
            dependencies=[]
            if typetree and version>=21:
                count=read('i')
                if not 0<=count<100000: raise ValueError('Invalid dependency count')
                dependencies=[read('i') for _ in range(count)]
            types.append({'class_id':cls,'class_name':UNITY_CLASS_NAMES.get(cls,str(cls)),'stripped':stripped,
                          'script_index':script_index,'script_id':script_id,'type_hash':oldhash,'tree_nodes':nodes,
                          'dependencies':dependencies})
        object_count=read('i')
        if not 0<=object_count<10000000: raise ValueError('Invalid object count')
        objects=[]
        for _ in range(object_count):
            cursor=(cursor+3)&~3
            path_id=read('q');byte_start=read('Q' if version>=22 else 'I');byte_size=read('I');type_index=read('i')
            if not 0<=type_index<len(types): raise ValueError('Object type index out of bounds')
            start=data_offset+byte_start
            if start+byte_size>filesize: raise ValueError('Object outside file')
            cls=types[type_index]['class_id'];name=None;content=None;mono_script=None
            # Named Object subclasses start with aligned UTF-8 m_Name. MonoBehaviour has another layout.
            if cls in (21,28,43,48,49,83,115,128,142,213,687078895) and byte_size>=4:
                size=struct.unpack_from(endian+'i',data,start)[0]
                if 0<=size<=min(byte_size-4,1048576):
                    try: name=data[start+4:start+4+size].decode('utf8')
                    except UnicodeDecodeError: name=None
                    if cls==49 and name is not None:
                        textpos=(start+4+size+3)&~3
                        if textpos+4<=start+byte_size:
                            textsize=struct.unpack_from(endian+'i',data,textpos)[0]
                            if 0<=textsize<=start+byte_size-textpos-4:
                                text=data[textpos+4:textpos+4+textsize]
                                text_utf8=None;json_keys=None;json_valid=False
                                try: text_utf8=text.decode('utf-8-sig')
                                except UnicodeDecodeError: pass
                                if text_utf8 is not None:
                                    try:
                                        parsed_json=json.loads(text_utf8);json_valid=True
                                        json_keys=list(parsed_json) if isinstance(parsed_json,dict) else None
                                    except (ValueError,RecursionError): pass
                                content_format='json' if json_valid else 'png' if text.startswith(b'\x89PNG\r\n\x1a\n') else 'pe' if text.startswith(b'MZ') else 'dex' if text.startswith(b'dex\n') else 'utf8' if text_utf8 is not None else 'binary'
                                content={'size':textsize,'sha256':hashlib.sha256(text).hexdigest(),
                                         'first_32_hex':text[:32].hex(),'looks_like_pe':text[:2]==b'MZ',
                                         'looks_like_dex':text[:4]==b'dex\n','format':content_format,
                                         'data_offset':textpos+4,'json_top_level_keys':json_keys,
                                         'source_code_markers':bool(text_utf8 is not None and not json_valid and re.search(r'\b(?:namespace\s+\w+|using\s+System\s*;|package\s+[a-z]+\.|public\s+class\s+\w+)',text_utf8))}
                    if cls==115 and name is not None:
                        script_pos=(start+4+size+3)&~3
                        if script_pos+20<=start+byte_size:
                            execution_order=struct.unpack_from(endian+'i',data,script_pos)[0]
                            properties_hash=data[script_pos+4:script_pos+20].hex();script_pos+=20
                            script_strings=[]
                            for _ in range(3):
                                if script_pos+4>start+byte_size: break
                                string_size=struct.unpack_from(endian+'i',data,script_pos)[0];script_pos+=4
                                if not 0<=string_size<=start+byte_size-script_pos: break
                                script_strings.append(data[script_pos:script_pos+string_size].decode('utf8',errors='replace'))
                                script_pos=(script_pos+string_size+3)&~3
                            if len(script_strings)==3:
                                mono_script={'execution_order':execution_order,'properties_hash':properties_hash,
                                             'class':script_strings[0],'namespace':script_strings[1],'assembly':script_strings[2]}
            objects.append({'path_id':path_id,'class_id':cls,'class_name':UNITY_CLASS_NAMES.get(cls,str(cls)),
                            'type_index':type_index,'offset':start,'size':byte_size,'name':name,'text_asset':content,'mono_script':mono_script})
        return {'path':str(path),'version':version,'unity_version':unity_version,'target_platform':platform,
                'enable_type_tree':typetree,'file_size':filesize,'metadata_size':metadata_size,'metadata_start':metadata_start,
                'data_offset':data_offset,'type_count':len(types),'object_count':len(objects),
                'all_object_bounds_valid':True,'metadata_object_table_end':cursor,
                'counts_by_class':dict(collections.Counter(o['class_name'] for o in objects)),
                'bytes_by_class':dict(collections.Counter({cls:sum(o['size'] for o in objects if o['class_name']==cls) for cls in {o['class_name'] for o in objects}})),
                'text_assets':[o for o in objects if o['class_id']==49],'mono_scripts':[o for o in objects if o['class_id']==115],
                'text_asset_formats':dict(collections.Counter(o['text_asset']['format'] for o in objects if o['text_asset'])),
                'text_assets_with_source_markers':sum(bool(o['text_asset'] and o['text_asset']['source_code_markers']) for o in objects),
                'monoscript_assembly_counts':dict(collections.Counter(o['mono_script']['assembly'] for o in objects if o['mono_script'])),
                'types':types,'objects':objects}


def uleb(data, offset):
    result = shift = 0
    for _ in range(5):
        value = data[offset]
        offset += 1
        result |= (value & 127) << shift
        if value < 128:
            return result, offset
        shift += 7
    raise ValueError('Invalid ULEB128')


def manifest_tree(data):
    strings, roots, stack = [], [], []
    offset = struct.unpack_from('<H', data, 2)[0]
    def s(index):
        return strings[index] if index != 0xffffffff else None
    while offset < len(data):
        kind, header, size = struct.unpack_from('<HHI', data, offset)
        if size < header or offset + size > len(data):
            raise ValueError('Invalid AXML chunk')
        chunk = data[offset:offset+size]
        if kind == 1:
            strings = string_pool(chunk)[0]
        elif kind == 0x102:
            ns, name, attr_start, attr_size, attr_count = struct.unpack_from('<IIHHH', chunk, 16)
            node = {'tag': s(name), 'attrs': {}, 'children': []}
            for n in range(attr_count):
                pos = 16 + attr_start + n * attr_size
                ans, aname, raw, vsize, res0, dtype, value = struct.unpack_from('<IIIHBBI', chunk, pos)
                if raw != 0xffffffff:
                    decoded = s(raw)
                elif dtype == 3:
                    decoded = s(value)
                elif dtype == 0x12:
                    decoded = bool(value)
                elif dtype in (0x10, 0x11):
                    decoded = value
                else:
                    decoded = {'type': dtype, 'value': hex(value)}
                node['attrs'][('android:' if ans != 0xffffffff else '') + s(aname)] = decoded
            (stack[-1]['children'] if stack else roots).append(node)
            stack.append(node)
        elif kind == 0x103:
            stack.pop()
        offset += size
    return roots[0]


def dex_catalog(data):
    if data[:4] != b'dex\n':
        raise ValueError('Not a standard DEX')
    def table(at):
        return struct.unpack_from('<II', data, at)
    nstrings, ostrings = table(56)
    ntypes, otypes = table(64)
    nprotos, oprotos = table(72)
    nfields, ofields = table(80)
    nmethods, omethods = table(88)
    nclasses, oclasses = table(96)
    strings = []
    for n in range(nstrings):
        off = struct.unpack_from('<I', data, ostrings + 4*n)[0]
        _, off = uleb(data, off)
        strings.append(data[off:data.index(0, off)].decode('utf-8', errors='replace'))
    types = [strings[struct.unpack_from('<I', data, otypes+4*n)[0]] for n in range(ntypes)]
    protos = []
    for n in range(nprotos):
        shorty, returns, params = struct.unpack_from('<III', data, oprotos+12*n)
        ps = []
        if params:
            count = struct.unpack_from('<I', data, params)[0]
            ps = [types[i] for i in struct.unpack_from('<'+'H'*count, data, params+4)]
        protos.append('('+''.join(ps)+')'+types[returns])
    methods = []
    for n in range(nmethods):
        cls, proto, name = struct.unpack_from('<HHI', data, omethods+8*n)
        methods.append(types[cls]+'->'+strings[name]+protos[proto])
    classes, definitions = [], []
    for n in range(nclasses):
        idx, flags, superidx, interfaces, source, ann, classdata, static = struct.unpack_from('<8I', data, oclasses+32*n)
        cls = {'name':types[idx], 'super':types[superidx] if superidx != 0xffffffff else None,
               'access_flags':hex(flags), 'source_file':strings[source] if source != 0xffffffff else None}
        classes.append(cls)
        if not classdata:
            continue
        off = classdata
        counts = []
        for _ in range(4):
            value, off = uleb(data, off)
            counts.append(value)
        for count in counts[:2]:
            for _ in range(count):
                _, off = uleb(data, off)
                _, off = uleb(data, off)
        for count in counts[2:]:
            midx = 0
            for _ in range(count):
                diff, off = uleb(data, off)
                flags, off = uleb(data, off)
                code, off = uleb(data, off)
                midx += diff
                definitions.append({'id':midx,'name':methods[midx], 'flags':hex(flags),
                                    'native':bool(flags & 0x100), 'code_offset':code})
    # Decode instruction boundaries to identify direct call references and constant strings.
    widths = [1]*256
    for op in [0x02,0x05,0x08,0x13,0x15,0x16,0x19,0x1a,0x1c,0x1f,0x20,0x22,0x23,0x29]: widths[op]=2
    for op in [0x03,0x06,0x09,0x14,0x17,0x1b,0x24,0x25,0x26,0x2a,0x2b,0x2c]: widths[op]=3
    widths[0x18]=5
    for op in range(0x2d,0x3e): widths[op]=2
    for op in range(0x44,0x6e): widths[op]=2
    for op in list(range(0x6e,0x73))+list(range(0x74,0x79)): widths[op]=3
    for op in range(0x90,0xb0): widths[op]=2
    for op in range(0xd0,0xe3): widths[op]=2
    widths[0xfa]=widths[0xfb]=4
    widths[0xfc]=widths[0xfd]=3
    widths[0xfe]=widths[0xff]=2
    findings = []
    load_callers = []
    decode_errors = []
    for definition in definitions:
        code = definition['code_offset']
        if not code:
            continue
        size = struct.unpack_from('<I', data, code+12)[0]
        units = struct.unpack_from('<'+'H'*size, data, code+16)
        constants, calls = [], []
        pos = 0
        try:
            while pos < size:
                unit = units[pos]
                op = unit & 255
                width = widths[op]
                if op == 0 and unit >> 8:
                    payload = unit >> 8
                    if payload == 1: width=4+2*units[pos+1]
                    elif payload == 2: width=2+4*units[pos+1]
                    elif payload == 3:
                        length=units[pos+2] | (units[pos+3]<<16)
                        width=4+(units[pos+1]*length+1)//2
                    else: raise ValueError('Unknown payload')
                if op in (0x1a,0x1b):
                    idx=units[pos+1]+((units[pos+2]<<16) if op==0x1b else 0)
                    constants.append({'code_unit':pos,'string':strings[idx]})
                if op in list(range(0x6e,0x73))+list(range(0x74,0x79)):
                    calls.append({'code_unit':pos,'method':methods[units[pos+1]]})
                if pos+width > size: raise ValueError('Instruction past code end')
                pos += width
            relevant=[c for c in calls if '->loadLibrary(' in c['method'] or '->load(' in c['method'] or '->native' in c['method']]
            if relevant:
                item={'method':definition['name'],'calls':relevant,'constants':constants}
                findings.append(item)
                if any('Ljava/lang/System;->loadLibrary(' in c['method'] for c in relevant): load_callers.append(item)
        except (IndexError,ValueError) as error:
            decode_errors.append({'method':definition['name'],'error':str(error)})
    prefixes=collections.Counter('.'.join(c['name'][1:-1].split('/')[:-1][:3]) for c in classes)
    return {'magic':data[:8].decode('ascii', errors='replace'), 'string_count':nstrings,
            'type_reference_count':ntypes,'method_reference_count':nmethods,'field_reference_count':nfields,
            'class_definition_count':nclasses,'method_definition_count':len(definitions),
            'methods_with_code':sum(bool(d['code_offset']) for d in definitions),
            'native_method_count':sum(d['native'] for d in definitions),
            'packages':dict(prefixes.most_common()),'load_library_callers':load_callers,
            'instruction_decode_errors':decode_errors,'classes':classes,'methods':definitions,
            'native_and_load_calls':findings, 'native_methods':[d['name'] for d in definitions if d['native']]}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk',type=Path,required=True)
    parser.add_argument('--private-output',type=Path,required=True)
    parser.add_argument('--summary',type=Path,required=True)
    parser.add_argument('--extract-unity-payload',type=Path)
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]
    out=args.private_output.resolve()
    if out.is_relative_to(root): raise ValueError('Private output must be outside repository')
    out.mkdir(parents=True,exist_ok=True)
    write=lambda path,obj:path.write_text(json.dumps(obj,ensure_ascii=False,indent=2),encoding='utf-8')
    sha=hashlib.file_digest(args.apk.open('rb'),'sha256').hexdigest()
    with zipfile.ZipFile(args.apk) as z:
        infos=z.infolist()
        inventory=[{'path':i.filename,'size':i.file_size,'compressed_size':i.compress_size,
                    'compression':i.compress_type,'crc32':f'{i.CRC:08x}'} for i in infos]
        write(out/'zip-inventory.json',inventory)
        manifest=manifest_tree(z.read('AndroidManifest.xml'))
        write(out/'manifest.json',manifest)
        dex=[]
        for info in infos:
            if re.fullmatch(r'classes\d*\.dex',info.filename):
                data=z.read(info)
                (out/info.filename).write_bytes(data)
                cat=dex_catalog(data)
                write(out/(info.filename+'.json'),cat)
                dex.append({'path':info.filename, **{k:v for k,v in cat.items() if k not in ('classes','methods','native_methods','native_and_load_calls')},
                            'native_declarations_by_package':dict(collections.Counter('.'.join(d['name'][1:d['name'].index(';')].split('/')[:-1][:3]) for d in cat['methods'] if d['native']))})
        assets=[i for i in infos if i.filename.startswith('assets/')]
        native=[i for i in inventory if i['path'].startswith('lib/')]
        groups=collections.defaultdict(lambda:{'count':0,'size':0,'compressed_size':0})
        for info in inventory:
            key='/'.join(info['path'].split('/')[:3]) if info['path'].startswith('assets/bin/') else info['path'].split('/')[0]
            g=groups[key]
            g['count']+=1;g['size']+=info['size'];g['compressed_size']+=info['compressed_size']
        markers=[]
        bundles=[];payloads=[]
        for info in assets:
            if info.filename.endswith(('globalgamemanagers','data.unity3d','boot.config','globalgamemanagers.assets')):
                with z.open(info) as stream: head=stream.read(8192)
                versions=sorted(set(v.decode() for v in re.findall(rb'(?:20\d\d|6000)\.\d+\.\d+[abfp]\d+',head)))
                markers.append({'path':info.filename,'first_64_hex':head[:64].hex(),'unity_versions_in_first_8192_bytes':versions,
                                'text':head.decode('utf8',errors='replace') if info.filename.endswith('boot.config') else None})
                if head.startswith(b'UnityFS\x00'):
                    bundle=unityfs_catalog(z.read(info))
                    write(out/'unityfs-catalog.json',bundle)
                    bundles.append({'path':info.filename,**{k:v for k,v in bundle.items() if k not in ('nodes','blocks')},
                                    'node_names':[n['path'] for n in bundle['nodes']],
                                    'node_size_by_extension':dict(collections.Counter({ext:sum(n['size'] for n in bundle['nodes'] if Path(n['path']).suffix==ext) for ext in {Path(n['path']).suffix for n in bundle['nodes']}}))})
                    if args.extract_unity_payload:
                        dest=args.extract_unity_payload.resolve()
                        if dest.is_relative_to(root): raise ValueError('Unity payload must be outside repository')
                        extracted=extract_unityfs(z.read(info),bundle,dest)
                        serialized=[]
                        for node in extracted['nodes']:
                            path=Path(node['path'])
                            if path.suffix=='.resS': continue
                            try:
                                objects=serialized_catalog(path)
                                write(path.with_name(path.name+'.objects.json'),objects)
                                serialized.append({k:v for k,v in objects.items() if k not in ('types','objects','text_assets','mono_scripts')})
                                serialized[-1]['text_asset_count']=len(objects['text_assets'])
                                serialized[-1]['mono_script_count']=len(objects['mono_scripts'])
                                serialized[-1]['text_assets_with_embedded_pe_or_dex']=sum(bool(o['text_asset'] and (o['text_asset']['looks_like_pe'] or o['text_asset']['looks_like_dex'])) for o in objects['text_assets'])
                            except ValueError as error:
                                serialized.append({'path':str(path),'parse_error':str(error)})
                        payloads.append({**extracted,'serialized_files':serialized})
        app=next(n for n in manifest['children'] if n['tag']=='application')
        manifest_summary={'package':manifest['attrs'],'uses_sdk':[n['attrs'] for n in manifest['children'] if n['tag']=='uses-sdk'],
                          'permissions':[n['attrs'] for n in manifest['children'] if n['tag'].startswith('uses-permission')],
                          'features':[n['attrs'] for n in manifest['children'] if n['tag']=='uses-feature'],
                          'application':app['attrs'],'components':[n for n in app['children'] if n['tag'] in ('activity','service','provider','receiver','activity-alias')],
                          'application_metadata':[n for n in app['children'] if n['tag']=='meta-data']}
        result={'apk':str(args.apk),'sha256':sha,'apk_size':args.apk.stat().st_size,'zip_entry_count':len(infos),
                'duplicate_paths':len(infos)-len({i.filename for i in infos}),'zip_crc_failure':z.testzip(),
                'zip_uncompressed_size':sum(i.file_size for i in infos),'zip_compressed_size':sum(i.compress_size for i in infos),
                'compression_methods':dict(collections.Counter(i.compress_type for i in infos)),
                'groups':dict(groups),'manifest':manifest_summary,'dex':dex,'native_libraries':native,
                'unity_markers':markers,'unityfs_bundles':bundles,'unityfs_payloads':payloads,'asset_count':len(assets),'largest_assets':sorted([i for i in inventory if i['path'].startswith('assets/')],key=lambda x:x['size'],reverse=True)[:25],
                'private_artifacts':str(out),'limitations':['Static declarations and call references do not prove runtime execution.',
                    'Library constants are collected per method, not proven register-to-argument dataflow.',
                    'Patched-build modifications cannot be attributed without a trusted matching baseline.']}
    args.summary.parent.mkdir(parents=True,exist_ok=True)
    write(args.summary,result)
    print(json.dumps({'summary':str(args.summary),'private_artifacts':str(out),'sha256':sha,
                      'zip_entry_count':len(infos),'dex':[{k:d[k] for k in ('path','class_definition_count','method_definition_count','native_method_count')} for d in dex]}))


if __name__=='__main__':
    main()
