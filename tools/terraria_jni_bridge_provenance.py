"""Source-bound, selected-path JNI bridge provenance audit; no target execution.

This records a manually reviewed interprocedural chain and independently asserts
its critical instruction operands, JNI ABI slots, imported copy functions and
the constructed stack payload. It is not a general ARM64 emulator.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
from terraria_jni_bindings import ELF, decode, disassemble, imported_thunks, resolve_local_abs64


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--native-dir',type=Path,required=True)
    ap.add_argument('--prior',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--jni-header',type=Path,default=Path('C:/Program Files/Java/jdk-21.0.12.1/include/jni.h'))
    args=ap.parse_args();data=(args.native_dir/'libunity.so').read_bytes();elf=ELF(data);resolve_local_abs64(elf)
    checks=[]
    def check(pc,**expected):
        actual=decode(struct.unpack_from('<I',data,elf.file_offset(pc))[0],pc)
        if any(actual.get(k)!=v for k,v in expected.items()):raise ValueError((hex(pc),expected,actual))
        checks.append({'instruction':actual,'asserted_operands':expected})
    header=args.jni_header.read_bytes();text=header.decode();start=text.index('struct JNINativeInterface_ {');end=text.index('\n};',start)
    fields=[m.group(1) or m.group(2) for m in re.finditer(r'void\s*\*\s*(reserved\d+)\s*;|\(\s*JNICALL\s*\*\s*(\w+)\s*\)',text[start:end])]
    slots={k:fields.index(k)*8 for k in ('GetJavaVM','FindClass','NewGlobalRef','RegisterNatives')}
    assert slots=={'GetJavaVM':1752,'FindClass':48,'NewGlobalRef':168,'RegisterNatives':1720}
    # JNIEnv supplied by the independently bound UnityPlayer.initJni native ABI.
    specs=[(0x2f0f54,dict(op='str',rt=31,rn=31,imm=8)),(0x2f0f60,dict(op='addi',rd=1,rn=31,imm=8)),
      (0x2f0f68,dict(op='ldr',rt=8,rn=8,imm=1752)),(0x2f0f70,dict(op='blr',rn=8)),
      (0x2f0f74,dict(op='tbz',rt=0,bit=31,target=0x2f0f90)),(0x2f0f90,dict(op='ldr',rt=0,rn=31,imm=8)),
      (0x2f0f9c,dict(op='bl',target=0x2da738)),(0x2da750,dict(op='mov',rd=20,rm=0)),
      (0x2da85c,dict(op='mov',rd=0,rm=20)),(0x2da864,dict(op='bl',target=0x2cf144)),
      (0x2cf150,dict(op='mov',rd=1,rm=31)),(0x2cf154,dict(op='bl',target=0x7a61c8)),
      (0x7a61cc,dict(op='adrp',rd=9,value=0xc44000)),(0x7a61d8,dict(op='str',rt=0,rn=9,imm=0x3a0)),
      (0x7a61d4,dict(op='addi',rd=10,rn=10,imm=0x1bc)),(0x7a61dc,dict(op='str',rt=10,rn=8,imm=0x3a8)),
      (0x7a61e0,dict(op='cbz',rt=1,target=0x7a61f0)),(0x7a61c0,dict(op='ldr',rt=2,rn=8,imm=48)),
      (0x7a61c4,dict(op='br',rn=2)),(0x7a6acc,dict(op='ldr',rt=0,rn=8,imm=0x3a0)),
      (0x7a6ae0,dict(op='addi',rd=1,rn=31,imm=8)),(0x7a6ae8,dict(op='ldr',rt=8,rn=8,imm=48)),
      (0x7a6aec,dict(op='blr',rn=8)),(0x7a6af0,dict(op='ldr',rt=0,rn=31,imm=8)),
      (0x7a87c0,dict(op='bl',target=0x7a60e4)),(0x7a6108,dict(op='cbz',rt=22,target=0x7a6118)),
      (0x7a612c,dict(op='str',rt=21,rn=20,imm=8)),(0x7a613c,dict(op='str',rt=0,rn=20,imm=0)),
      (0x7a6150,dict(op='b',target=0x86790)),(0x78822c,dict(op='bl',target=0x7a6afc)),
      (0x7a6b08,dict(op='bl',target=0x7a6454)),(0x7a6b24,dict(op='ldr',rt=8,rn=8,imm=0x3a8)),
      (0x7a6b30,dict(op='blr',rn=8)),(0x7a6b34,dict(op='mov',rd=20,rm=0)),
      (0x7a6b44,dict(op='b',target=0x7a6b68)),(0x7a6b68,dict(op='mov',rd=0,rm=20)),
      (0x788248,dict(op='bl',target=0x7a6ed8)),(0x7a6f08,dict(op='ldr',rt=8,rn=8,imm=168)),
      (0x7a6f0c,dict(op='blr',rn=8)),(0x7882a8,dict(op='str',rt=19,rn=20,imm=8)),
      (0x7882ac,dict(op='ldr',rt=21,rn=19,imm=0)),(0x7882e8,dict(op='mov',rd=0,rm=21)),
      (0x7a882c,dict(op='bl',target=0x7a6ac4)),(0x7a8830,dict(op='mov',rd=19,rm=0)),
      (0x7a8838,dict(op='bl',target=0x78820c)),(0x7a8840,dict(op='mov',rd=1,rm=0)),
      (0x7a884c,dict(op='ldr',rt=8,rn=8,imm=1720)),(0x7a8850,dict(op='mov',rd=0,rm=19)),
      (0x7a8854,dict(op='blr',rn=8))]
    for pc,expected in specs:check(pc,**expected)
    imports=imported_thunks(elf)
    for va,name in ((0x86180,'strlen'),(0x86f40,'malloc'),(0x86790,'strcpy')):
        assert imports[va]['name']==name
    prior=json.loads((args.prior/'static-registration-bindings.json').read_text(encoding='utf8'))
    # Locate the prior proof without depending on its surrounding JSON schema.
    def walk(v):
        if isinstance(v,dict):
            if v.get('dex_descriptor')=='Lcom/unity3d/player/UnityPlayer;->initJni(Landroid/content/Context;)V':yield v
            for x in v.values():yield from walk(x)
        elif isinstance(v,list):
            for x in v:yield from walk(x)
    init=list(walk(prior));assert init and all(x['function_address']=='0x2f0f48' for x in init)
    old=json.loads((args.prior/'remaining-native-audit.json').read_text(encoding='utf8'))['jni_bridge_stack_table_evidence']
    # Reconstruct payload independently from immediate stores and original bytes.
    vals={};stack={}
    for ins in disassemble(elf,0x7a8790,0xf0):
        if ins['op']=='movz':vals[ins['rd']]=ins['imm']<<ins['shift']
        elif ins['op']=='movk' and ins['rd'] in vals:vals[ins['rd']]=(vals[ins['rd']]&~(65535<<ins['shift']))|(ins['imm']<<ins['shift'])
        elif ins['op']=='str' and ins['rn']==31 and ins['size']==4 and ins['rt'] in vals:
            stack.update({ins['imm']+i:b for i,b in enumerate(struct.pack('<I',vals[ins['rt']]&0xffffffff))})
    name=bytes(stack[i] for i in range(24,31));sigva=0x9d2da8
    sig=data[elf.file_offset(sigva):elf.file_offset(sigva)+80]+bytes(stack[i] for i in range(144,148))
    assert name==b'invoke\0' and sig.split(b'\0')[0].decode()==old['signature_constructed_from_simd_copy_and_tail_store']
    function=elf.pointer(0xb87000+1352);assert function==0x7a8748 and elf.executable(function)
    descriptor='Lbitter/jnibridge/JNIBridge;->invoke'+sig.split(b'\0')[0].decode()
    unresolved=json.loads((args.native_dir/'unresolved-dex-native-declarations.json').read_text(encoding='utf8'))
    assert descriptor in str(unresolved)
    windows=[(0x2f0f48,0x64),(0x2da738,0x138),(0x2cf144,0x1c),(0x7a61bc,0x38),(0x7a6ac4,0x38),
             (0x7a60e4,0x70),(0x78820c,0xe8),(0x7a6afc,0x7c),(0x7a6454,0x80),(0x7a6ed8,0x70),(0x7a8790,0xcc)]
    result={'library':'libunity.so','sha256':hashlib.sha256(data).hexdigest(),'source_size':len(data),
      'jni_header':{'path':str(args.jni_header),'sha256':hashlib.sha256(header).hexdigest(),'slots':slots},
      'method':{'dex_descriptor':descriptor,'function_address':hex(function),'register_natives_call':'0x7a8854','count':1},
      'vm_provenance':'UnityPlayer.initJni JNIEnv.GetJavaVM output -> 0x2da738 x20 -> 0x2cf144 -> 0x7a61c8 -> global 0xc443a0',
      'class_provenance':'constructor copies class string through strlen/malloc/strcpy; accessor -> FindClass thunk -> NewGlobalRef -> cached class -> x1 at registration',
      'asserted_instructions':checks,'relocation_verified_imports':{hex(k):imports[k] for k in (0x86180,0x86f40,0x86790)},
      'raw_instruction_windows':[{'entry':hex(a),'size':s,'instructions':disassemble(elf,a,s)} for a,s in windows],
      'selected_path_assumptions':['Native initJni is invoked with ABI-conformant JNIEnv and GetJavaVM succeeds.',
         'Earlier helpers return normally and preserve AAPCS64 callee-saved x20; no intervening write replaces the recorded VM global.',
         'Wrapper allocations and strcpy succeed; FindClass returns a valid class and modeled exception-check branches report no exception.',
         'GetEnv yields a valid JNIEnv; getter does not itself check its status, so this is an explicit precondition.',
         'Accessor uses fresh-class path first and its non-null cached-class path second; refcount cleanup preserves the returned class.'],
      'analysis_scope':'Manually reviewed selected interprocedural paths with critical operand assertions, not general symbolic execution or whole-program verification.',
      'complete_selected_path_class_vm_argument_chain':True,'runtime_registration_proven':False,
      'prior_binding_count':150,'additional_distinct_descriptor_count':1,'combined_distinct_descriptors_if_accepted':151,
      'remaining_descriptors_if_accepted':10}
    args.output.mkdir(parents=True,exist_ok=True)
    (args.output/'jnibridge-provenance.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf8')
    print(json.dumps({k:result[k] for k in ('additional_distinct_descriptor_count','remaining_descriptors_if_accepted','complete_selected_path_class_vm_argument_chain')}))


if __name__=='__main__':main()
