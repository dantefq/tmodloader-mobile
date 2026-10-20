"""Independent source checks plus piecewise routing oracle; no producer imports."""
import copy,hashlib,json,mmap,pathlib,struct
LAB=pathlib.Path('C:/Temp/terraria-re-20261012');OUT=LAB/'projectile-ai-dispatch-20261015'
def need(x,m):
    if not x:raise ValueError(m)
def sha(b):return hashlib.sha256(b).hexdigest()
def signed(v,b):return v-(1<<b) if v&(1<<(b-1)) else v
f=(LAB/'native/libil2cpp.so').open('rb');elf=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
ph=struct.unpack_from('<Q',elf,32)[0];ps,pn=struct.unpack_from('<HH',elf,54);loads=[]
for k in range(pn):
    t,_,o,a,_,n,_,_=struct.unpack_from('<II6Q',elf,ph+k*ps)
    if t==1:loads.append((a,a+n,o))
def read(a,n):
    for lo,hi,o in loads:
        if lo<=a and a+n<=hi:return elf[o+a-lo:o+a-lo+n]
    raise ValueError('source range')
def word(a):return int.from_bytes(read(a,4),'little')
def reloc(target):
    so=struct.unpack_from('<Q',elf,40)[0];sz,n=struct.unpack_from('<HH',elf,58);v=[]
    for j in range(n):
        s=struct.unpack_from('<II4QII2Q',elf,so+j*sz)
        if s[1]==4:
            for p in range(s[4],s[4]+s[5],s[9] or 24):
                a,i,d=struct.unpack_from('<QQq',elf,p)
                if a==target:need(i==1027,'RELATIVE');v.append(d)
    need(len(v)==1,'unique relocation');return v[0]
def validate(d):
    need(sha(elf)==d['elf_sha256']=='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5','ELF identity')
    meta=(LAB/'native/global-metadata.dat').read_bytes();need(sha(meta)==d['metadata_sha256']=='4c904c49d168913d28ef547c4f461e539d926d2ed27c0253ed53a2954e9585f7','metadata identity')
    def rec(table,index,fmt):
        o,n=struct.unpack_from('<II',meta,8+table*8);size=struct.calcsize(fmt);need(0<=index and (index+1)*size<=n,'metadata bounds');return o+index*size,struct.unpack_from(fmt,meta,o+index*size)
    def string(index):
        o,n=struct.unpack_from('<II',meta,24);need(0<=index<n,'string bounds');return meta[o+index:meta.index(b'\0',o+index,o+n)].decode()
    fp,field=rec(11,15933,'<IiI');_,typ=rec(19,1193,'<IIiiiiIIiiiiiiii8HII')
    need(string(field[0])=='aiStyle' and string(typ[0])=='Projectile' and string(typ[1])=='Terraria','metadata field/owner')
    local=15933-typ[8];need(0<=local<typ[18],'field owner range')
    table=reloc(0x2fdb588+0x58);offsets=reloc(table+1193*8);offset=int.from_bytes(read(offsets+4*local,4),'little')
    r=d['field'];native_type=reloc(reloc(0x2fdb588+0x38)+field[1]*8);native_bytes=read(native_type,16);need(int(r['native_type_pointer'],16)==native_type and r['native_type_bytes']==native_bytes.hex() and r['native_type_code']==((int.from_bytes(native_bytes[8:12],'little')>>16)&255)==8,'field type I4');need(r['index']==15933 and r['owner']==1193 and r['metadata_record_file_offset']==fp and r['field_type_index']==field[1] and r['native_field_offset']==offset==152 and r['local_index']==local and int(r['field_offset_pointer_table'],16)==table and int(r['owner_offset_array'],16)==offsets,'field evidence')
    addresses=set()
    for s in d['fragments']:
        a=int(s['start'],16);b=bytes.fromhex(s['bytes']);need(a+len(b)==int(s['end_exclusive'],16) and read(a,len(b))==b and sha(b)==s['sha256'],'source fragment');addresses.update(range(a,a+len(b),4))
    need(len(addresses)==d['router_instruction_count']==173 and word(0x14236f4)==0xb9409a68,'router coverage/source LDR')
    # Independently verify the signed upper partition chain from original raw CMP + B.LE.
    for cmpat,brat,upper,dest in [(0x14236f8,0x14236fc,25,0x1423868),(0x1423700,0x1423704,50,0x142389c),(0x1423738,0x14237a4,75,0x14238d0),(0x14237c0,0x14237fc,100,0x1423904),(0x1423800,0x1423810,125,0x14239ac),(0x1423824,0x1423828,150,0x1423e60),(0x142382c,0x1423830,175,0x1424088)]:
        need(word(cmpat)==0x7100011f+(upper<<10),'CMP W8 immediate')
        w=word(brat);need(w&0xff00001f==0x5400000d and brat+4*signed((w>>5)&0x7ffff,19)==dest,'signed B.LE destination')
    parts=[(25,1,25,0x1423868,0x1423888,0x1444428),(50,26,24,0x142389c,0x14238bc,0x1424078),(75,51,24,0x14238d0,0x14238f0,0x1425bf8),(100,76,23,0x1423904,0x1423944,0x1427e6c),(125,101,24,0x14239b4,0x14239ec,0x142b8c8),(150,126,24,0x1423e60,0x1423e94,0x1431ee0),(175,151,24,0x1424088,0x14240a8,0x1436150),(2147483647,176,35,0x1423834,0x1423854,0x1444428)]
    tabs={int(t['branch'],16):t for t in d['tables']};need(len(tabs)==8,'tables count')
    for _,bias,count,subat,br,fallback in parts:
        destreg=9 if bias==76 else 8;need(word(subat)==0x51000100+destreg+(bias<<10),'SUB W(index),W8 bias')
        need(word(subat+4)==0x7100001f+(destreg<<5)+((count-1)<<10),'CMP index count')
        w=word(subat+8);need(w&0xff00001f==0x54000008 and subat+8+4*signed((w>>5)&0x7ffff,19)==fallback,'unsigned B.HI destination')
        tab=tabs[br];a=int(tab['table'],16);anchor=int(tab['anchor'],16);raw=read(a,count*2);need(raw.hex()==tab['table_raw_bytes'] and sha(raw)==tab['table_sha256'] and tab['count']==count and tab['width']==2,'source table bytes')
        for j,en in enumerate(tab['entries']):need(en['index']==j and int(en['target'],16)==anchor+4*int.from_bytes(raw[j*2:j*2+2],'little'),'table target')
    need(len(d['routes'])==d['sample_count']==221,'sample count');samples=list(range(1,211))+[-2147483648,-2147483647,-65536,-211,-1,0,211,212,65535,2147483646,2147483647]
    for v,r in zip(samples,d['routes']):
        need(v==r['aiStyle_signed_Int32'],'sample identity');_,bias,count,_,br,fall=next(p for p in parts if v<=p[0]);idx=(v-bias)%(1<<32)
        if idx>=count:need(r['kind']=='guard_fallback' and int(r['target'],16)==fall,'fallback oracle')
        else:
            t=tabs[br];target=int(t['anchor'],16)+4*int.from_bytes(read(int(t['table'],16)+idx*2,2),'little')
            need(r['kind']=='table' and int(r['branch'],16)==br and r['index']==idx and r['table']==t['table'] and int(r['target'],16)==target,'table oracle')
        need(r['path'][0]=='0x14236f4' and all(int(p,16) in addresses for p in r['path']),'recorded path scope')
    methods={}
    catalog=LAB/'metadata/methods.jsonl';need(sha(catalog.read_bytes())==d['method_catalog_sha256'],'method catalog identity')
    for line in catalog.open(encoding='utf8'):
        r=json.loads(line)
        if r.get('native_address'):methods.setdefault(r['native_address'],[]).append({'metadata_method_index':r['index'],'label':r['owner_type']+'::'+r['name']})
    for target,p in d['first_BL_previews'].items():
        for n,row in enumerate(p['instructions']):need(int(row['address'],16)==int(target,16)+4*n and read(int(row['address'],16),4).hex()==row['bytes'],'preview source')
        if p['first_BL']:
            b=p['first_BL'];a=int(b['site'],16);w=word(a);dest=a+4*signed(w&0x3ffffff,26)
            need(w&0xfc000000==0x94000000 and dest==int(b['target'],16) and b['catalog_labels']==methods.get(hex(dest),[]) and p['instructions'][-1]['address']==b['site'],'source BL and catalog names')
    return True
def main():
    path=OUT/'dispatch.json';d=json.loads(path.read_text(encoding='utf8'));validate(d);need(sha(pathlib.Path(__file__).with_name('terraria_projectile_ai_dispatch.py').read_bytes())==d['producer_sha256'],'producer source SHA');
    for dependency in d['dependencies']:need(sha((LAB/dependency['relative_lab_path']).read_bytes())==dependency['sha256'],'dependency hash')
    neg=[]
    for label,mutate in [('field_offset',lambda x:x['field'].__setitem__('native_field_offset',156)),('source_fragment',lambda x:x['fragments'][0].__setitem__('bytes','00000000'+x['fragments'][0]['bytes'][8:])),('route_target',lambda x:x['routes'][0].__setitem__('target','0x1423370')),('route_index',lambda x:x['routes'][25].__setitem__('index',1)),('table_target',lambda x:x['tables'][0]['entries'][0].__setitem__('target','0x1423370'))]:
        m=copy.deepcopy(d);mutate(m)
        try:validate(m)
        except ValueError:neg.append(label)
        else:raise ValueError('negative accepted '+label)
    result={'profile':'independent-Projectile-AI-dispatch-source-and-piecewise-oracle-v1','integrity_passed':True,'evidence_sha256':sha(path.read_bytes()),'auditor_sha256':sha(pathlib.Path(__file__).read_bytes()),'negative_mutations_rejected':neg,'sample_count':221,'router_instruction_count':173,'limits':['Shares no producer code or parser imports; checks source fragments, fresh metadata/relocations, raw partition guards/SUB, tables, piecewise oracle and BL names.','Does not independently reexecute all non-routing setup instructions or prove complete recorded path sequence, memory fault freedom, all incoming paths, original native-method registration or runtime behavior.']}
    (OUT/'independent-audit.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':main()
