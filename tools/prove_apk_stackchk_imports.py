"""Bounded __stack_chk_fail PLT/GOT proof for one selected APK ELF."""
import argparse
import hashlib
import json
import struct
import zipfile
from pathlib import Path
from prove_libmain_stackchk_import import ELF, plt_effects, call_target, require

sha=lambda b:hashlib.sha256(b).hexdigest()
APK_SHA='1f8e2ba7ddabaee961a1b2552d44bc0c281c9b5122480642b018779bcbf2fe8e'
PARSER_SHA='b3fc8f7a171a177f97cf7b8be5d1514e312daf8d9661a32851bd800e2edffd3a'
ASSUMPTIONS=[
 'The loader selects a Bionic-compatible __stack_chk_fail honoring the abort/no-normal-return contract.',
 'No interposition, GOT rewriting, hook, modified PLT or replacement fabricates a normal return.',
 'Standard AArch64 BL/BR semantics apply; no return-address corruption or asynchronous PC rewriting fabricates a continuation.',
 'Signal, exception or other nonlocal transfers do not reenter a continuation that later returns normally from this call.']


def imports(raw):
 e=ELF(raw);s=e.section('.rela.plt');require(s['type']==4 and s['entsize']==24,'Expected RELA PLT')
 sy=e.sections[s['link']];st=e.sections[sy['link']]
 require(sy['type']==11 and sy['entsize']==24 and st['type']==3,'Expected dynsym/string links')
 plt=e.section('.plt');matches=[]
 for off in range(s['offset'],s['offset']+s['size'],24):
  slot,info,add=struct.unpack_from('<QQq',raw,off);idx=info>>32
  so=sy['offset']+idx*24;require(so+24<=sy['offset']+sy['size'],'Bad dynsym index')
  n,attr,other,shndx,value,size=struct.unpack_from('<IBBHQQ',raw,so)
  name=e.string(raw[st['offset']:st['offset']+st['size']],n)
  if name!='__stack_chk_fail':continue
  require(info&0xffffffff==1026 and add==0 and shndx==0 and value==0 and attr==0x12,'Expected undefined GLOBAL FUNC JUMP_SLOT')
  candidates=[]
  for pc in range(plt['va'],plt['va']+plt['size']-15,4):
   data=e.read(pc,16,True)
   try:effects=plt_effects(list(struct.unpack('<4I',data)),pc)
   except ValueError:continue
   if effects['slot']==slot:candidates.append((pc,data,effects))
  require(len(candidates)==1,'Missing or ambiguous stack-fail PLT')
  pc,data,effects=candidates[0]
  record=dict(address=hex(pc),end_exclusive=hex(pc+16),got_slot=hex(slot),symbol=name,plt_bytes_hex=data.hex(),
              plt_source_sha256=sha(data),relocation=dict(file_offset=off,slot=hex(slot),type=1026,symbol_index=idx,addend=add,raw_bytes=raw[off:off+24].hex()),
              dynamic_symbol=dict(file_offset=so,name=name,binding=attr>>4,type=attr&15,shndx=shndx,value=value,size=size,raw_bytes=raw[so:so+24].hex()),
              initial_GOT_pointer=hex(struct.unpack('<Q',e.read(slot,8))[0]),runtime_GOT_pointer_observed=False)
  matches.append(record)
 require(matches,'No supported stack-fail import found')
 return matches


def main():
 p=argparse.ArgumentParser();p.add_argument('--apk',type=Path,required=True);p.add_argument('--elf',type=Path,required=True)
 p.add_argument('--expected-elf-sha256',required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--call',action='append',default=[])
 a=p.parse_args();require(not a.output.exists(),'Fresh output required')
 parser=Path(__file__).with_name('prove_libmain_stackchk_import.py');require(sha(parser.read_bytes())==PARSER_SHA,'Frozen parser changed')
 require(sha(a.apk.read_bytes())==APK_SHA,'APK identity differs');raw=a.elf.read_bytes();require(sha(raw)==a.expected_elf_sha256,'ELF identity differs')
 with zipfile.ZipFile(a.apk) as z:require(z.read('lib/arm64-v8a/'+a.elf.name)==raw,'APK ELF extraction mismatch')
 records=imports(raw);e=ELF(raw);targets={int(r['address'],16) for r in records};calls=[]
 for value in a.call:
  pc=int(value,0);data=e.read(pc,4,True);word=struct.unpack('<I',data)[0];target=call_target(word,pc)
  require(target in targets,'Requested call does not target proved PLT')
  calls.append(dict(pc=hex(pc),raw_bytes=data.hex(),word=hex(word),target=hex(target),normal_continuation=hex(pc+4)))
 controls=[]
 def reject(label,fn):
  try:fn()
  except (ValueError,struct.error,IndexError):controls.append(label)
  else:raise ValueError('Negative accepted: '+label)
 # Mutate each selected PLT opcode independently. This tests raw decode, not runtime resolution.
 first=records[0];words=list(struct.unpack('<4I',e.read(int(first['address'],16),16,True)))
 for i in range(4):
  bad=words.copy();bad[i]=0xd503201f;reject('bad_PLT_opcode_'+str(i),lambda bad=bad:plt_effects(bad,int(first['address'],16)))
 bad=bytearray(raw);off=first['relocation']['file_offset'];slot,info,add=struct.unpack_from('<QQq',bad,off)
 struct.pack_into('<QQq',bad,off,slot,(info&~0xffffffff)|1025,add);reject('wrong_JUMP_SLOT_type',lambda:imports(bytes(bad)))
 summary=dict(schema_version=1,elf_sha256=sha(raw),APK_sha256=APK_SHA,imports=records,
              known_noreturn_imports=[{k:r[k] for k in ('address','end_exclusive','got_slot','symbol','plt_bytes_hex')} for r in records],
              conditional_noreturn_assumptions=ASSUMPTIONS,verified_requested_BL_calls=calls,
              scope='Static import binding only; conditional Bionic implementation contract, not actual runtime resolution',
              runtime_resolution_verified=False,NoReturn_annotation_applied=False,flow_override_applied=False,
              semantic_equivalence_verified=False,producer_sha256=sha(Path(__file__).read_bytes()),parser_sha256=PARSER_SHA,
              negative_controls_rejected=controls,
              contract_note='AOSP __stack_chk_fail invokes async_safe_fatal; its macro calls abort, declared __noreturn. Source URLs in companion libmain proof notes; actual loaded libc/interposition not verified.')
 a.output.mkdir(parents=True);(a.output/'evidence.json').write_text(json.dumps(summary,indent=2)+'\n')
 (a.output/'manifest.json').write_text(json.dumps(dict(producer_sha256=summary['producer_sha256'],parser_sha256=PARSER_SHA,evidence_sha256=sha((a.output/'evidence.json').read_bytes())),indent=2)+'\n')
 print(json.dumps(dict(evidence=str(a.output/'evidence.json'),evidence_sha256=sha((a.output/'evidence.json').read_bytes()),known_noreturn_imports=summary['known_noreturn_imports'],verified_calls=calls)))


if __name__=='__main__':main()
