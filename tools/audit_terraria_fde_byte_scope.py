"""Read-only independent ELF64 interval audit; no disassembly and no C semantic claims."""
import argparse,datetime,hashlib,json,mmap,struct
from pathlib import Path
ELF_SHA='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
FDE_SHA='8b238f458b7a0505138fc56ea70ffe59c21d46a6b83ea2e4106f6f896a3f7756'

def digest(b):return hashlib.sha256(b).hexdigest()
def union(rows):
    out=[]
    for a,b in sorted(rows):
        assert a<=b
        if a==b:continue
        if out and a<=out[-1][1]:out[-1][1]=max(b,out[-1][1])
        else:out.append([a,b])
    return out

def size(rows):return sum(b-a for a,b in union(rows))
def intersect(left,right):
    left,right=union(left),union(right);out=[];i=j=0
    while i<len(left) and j<len(right):
        a,b=left[i];c,d=right[j]
        if max(a,c)<min(b,d):out.append([max(a,c),min(b,d)])
        if b<=d:i+=1
        else:j+=1
    return out

def subtract(left,right):
    left,right=union(left),union(right);out=[];j=0
    for a,b in left:
        while j<len(right) and right[j][1]<=a:j+=1
        k=j;cursor=a
        while k<len(right) and right[k][0]<b:
            c,d=right[k]
            if c>cursor:out.append([cursor,min(c,b)])
            cursor=max(cursor,d)
            if cursor>=b:break
            k+=1
        if cursor<b:out.append([cursor,b])
    return out

def public(rows):return [{'start':hex(a),'end_exclusive':hex(b),'bytes':b-a} for a,b in rows]
def checks():
    assert union([(0,4),(4,8),(2,5),(10,10)])==[[0,8]]
    assert intersect([(0,8),(10,20)],[(4,12),(14,16)])==[[4,8],[10,12],[14,16]]
    assert subtract([(0,8),(10,20)],[(4,12),(14,16)])==[[0,4],[12,14],[16,20]]
    assert subtract([(0,4)],[(0,4)])==[] and subtract([(0,4)],[])==[[0,4]]
    assert size([(0,4),(2,6)])==6

def main():
    p=argparse.ArgumentParser();p.add_argument('lab',type=Path);p.add_argument('--summary',type=Path);p.add_argument('--output',type=Path);a=p.parse_args();checks()
    lab=a.lab.resolve();elf=lab/'native/libil2cpp.so';catalogue=lab/'native/unwind-function-ranges.tsv';summary_path=a.summary or lab/'coarse-continuation-20261015/summary.json'
    fde_bytes=catalogue.read_bytes();assert digest(fde_bytes)==FDE_SHA
    fdes=[tuple(int(v,16) for v in line.split()) for line in fde_bytes.decode().splitlines()]
    assert len(fdes)==123152 and all(lo<hi and (lo|hi)%4==0 for lo,hi in fdes)
    snapshot=summary_path.read_bytes();summary=json.loads(snapshot);remaining=summary['remaining_methods'];index=dict(fdes)
    assert len(index)==len(fdes) and len({r['address'] for r in remaining})==len(remaining)
    missing=[]
    for r in remaining:
        lo=int(r['address'],16);hi=index[lo]
        if 'function_bytes' in r:assert r['function_bytes']==hi-lo
        missing.append((lo,hi))
    assert len(remaining)==summary['remaining_hard_methods_without_C']
    with elf.open('rb') as fh,mmap.mmap(fh.fileno(),0,access=mmap.ACCESS_READ) as raw:
        assert digest(raw)==ELF_SHA and raw[:6]==b'\x7fELF\x02\x01' and struct.unpack_from('<H',raw,18)[0]==183
        ph,sh=struct.unpack_from('<QQ',raw,32);phsize,phnum,shsize,shnum,shstrndx=struct.unpack_from('<HHHHH',raw,54)
        assert phsize>=56 and shsize>=64 and shstrndx<shnum and ph+phsize*phnum<=len(raw) and sh+shsize*shnum<=len(raw)
        sections=[struct.unpack_from('<IIQQQQIIQQ',raw,sh+i*shsize) for i in range(shnum)]
        strings=sections[shstrndx];name_table=raw[strings[4]:strings[4]+strings[5]]
        exec_sections=[];allocated_sections=[]
        for number,s in enumerate(sections):
            name,ty,flags,va,off,length,_,_,_,_=s;assert name<len(name_table)
            label=name_table[name:name_table.find(b'\0',name)].decode('utf8')
            if flags&2:allocated_sections.append(dict(index=number,name=label,virtual_address=va,size=length,flags=hex(flags),section_type=ty))
            if flags&4:
                assert ty!=8 and off+length<=len(raw)
                exec_sections.append(dict(index=number,name=label,virtual_address=va,file_offset=off,size=length,flags=hex(flags)))
        exec_segments=[]
        for number in range(phnum):
            ty,flags,off,va,_,filesz,memsz,align=struct.unpack_from('<IIQQQQQQ',raw,ph+number*phsize)
            if ty==1 and flags&1:
                assert filesz<=memsz and off+filesz<=len(raw)
                exec_segments.append(dict(index=number,virtual_address=va,file_offset=off,file_bytes=filesz,memory_bytes=memsz))
    fde_union=union(fdes);exec_file=union((r['virtual_address'],r['virtual_address']+r['file_bytes']) for r in exec_segments);exec_mem=union((r['virtual_address'],r['virtual_address']+r['memory_bytes']) for r in exec_segments);section_union=union((s['virtual_address'],s['virtual_address']+s['size']) for s in exec_sections)
    allocated_nonexec_in_X=[]
    for section in allocated_sections:
        if int(section['flags'],16)&4:continue
        n=size(intersect([(section['virtual_address'],section['virtual_address']+section['size'])],exec_file))
        if n:allocated_nonexec_in_X.append(dict(section,intersection_with_PF_X_file_bytes=n))
    for s in exec_sections:
        area=[(s['virtual_address'],s['virtual_address']+s['size'])];inside=intersect(area,fde_union);gaps=subtract(area,fde_union)
        s.update(fde_intersection_bytes=size(inside),without_FDE_bytes=size(gaps),without_FDE_interval_count=len(gaps),without_FDE_intervals=public(gaps))
    total=size(fde_union);remaining_size=size(missing);represented=total-remaining_size
    result=dict(audit_time_UTC=datetime.datetime.now(datetime.timezone.utc).isoformat(),integrity_passed=True,elf_sha256=ELF_SHA,fde_catalogue_sha256=FDE_SHA,coverage_snapshot_path=str(summary_path.resolve()),coverage_snapshot_sha256=digest(snapshot),auditor_sha256=digest(Path(__file__).read_bytes()),FDE_count=len(fdes),FDE_sum_bytes=sum(hi-lo for lo,hi in fdes),FDE_union_bytes=total,FDE_overlap_duplicate_bytes=sum(hi-lo for lo,hi in fdes)-total,remaining_without_C_count=len(missing),remaining_without_C_union_bytes=remaining_size,represented_FDE_union_bytes=represented,represented_FDE_byte_percent=100*represented/total,C_present_FDE_ranges_as_percent_of_executable_section_bytes=100*represented/size(section_union),catalogue_FDE_ranges_as_percent_of_executable_section_bytes=100*total/size(section_union),executable_section_sum_minus_union_bytes=sum(s['size'] for s in exec_sections)-size(section_union),allocated_nonexec_sections_intersecting_PF_X=allocated_nonexec_in_X,represented_FDE_address_percent=100*(len(fdes)-len(missing))/len(fdes),executable_PT_LOAD_file_bytes=size(exec_file),executable_PT_LOAD_memory_bytes=size(exec_mem),executable_sections_union_bytes=size(section_union),FDE_outside_executable_PT_LOAD_file_bytes=size(subtract(fde_union,exec_file)),FDE_outside_executable_sections_bytes=size(subtract(fde_union,section_union)),executable_PT_LOAD_file_without_FDE_bytes=size(subtract(exec_file,fde_union)),executable_PT_LOAD_file_outside_executable_sections_bytes=size(subtract(exec_file,section_union)),executable_sections_outside_PT_LOAD_file_bytes=size(subtract(section_union,exec_file)),exec_segments=exec_segments,exec_sections=exec_sections,PT_LOAD_file_without_FDE_intervals=public(subtract(exec_file,fde_union)),FDE_outside_exec_sections_intervals=public(subtract(fde_union,section_union)),remaining_FDE_intervals=public(missing),limitations=['Coverage is presence of a C candidate per original catalogue FDE, including conditional models; it does not prove every byte is represented by output statements.','95.1% if confirmed is only the original FDE-byte denominator, not all native code, all executable bytes, or semantic equivalence.','Executable bytes outside catalogue FDE are unclassified: possible code, stubs, islands, alignment or data; no disassembly was performed.','No claims about APK libraries other than this exact libil2cpp.so, runtime-loaded code, or original C# recovery.'])
    if a.output:
        destination=a.output.resolve();assert destination.is_relative_to(lab) and destination!=elf and destination!=catalogue
        destination.parent.mkdir(parents=True,exist_ok=True);destination.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    compact={k:v for k,v in result.items() if k not in ('exec_segments','exec_sections','allocated_nonexec_sections_intersecting_PF_X','PT_LOAD_file_without_FDE_intervals','FDE_outside_exec_sections_intervals','remaining_FDE_intervals','limitations')};compact['allocated_nonexec_sections_intersecting_PF_X']=allocated_nonexec_in_X;compact['exec_sections']=[{k:v for k,v in s.items() if k!='without_FDE_intervals'} for s in exec_sections];print(json.dumps(compact,ensure_ascii=False))
if __name__=='__main__':main()
