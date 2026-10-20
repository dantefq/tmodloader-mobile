"""Join supplemental JNI findings, verify traces, compare independent rerun."""
import argparse,hashlib,json,struct
from pathlib import Path
from terraria_jni_bindings import ELF,resolve_local_abs64


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',type=Path,required=True);a=ap.parse_args();lab=a.lab
    previous=lab/'android-native/static-bindings-20261013';out=lab/'android-native/jni-remaining-20261013';rerun=lab/'android-native/jni-remaining-20261013-rerun'
    prior=json.loads((previous/'static-registration-bindings.json').read_text(encoding='utf8'))
    def walk(v):
        if isinstance(v,dict):
            if v.get('dex_descriptor') and v.get('matches_dex_native_declaration'):yield v
            for x in v.values():yield from walk(x)
        elif isinstance(v,list):
            for x in v:yield from walk(x)
    rows={x['dex_descriptor']:{**x,'evidence_file':'../static-bindings-20261013/static-registration-bindings.json'} for x in walk(prior)};assert len(rows)==150
    dex=json.loads((lab/'android/classes.dex.json').read_text(encoding='utf8'));native=set(dex['native_methods']);assert len(native)==161
    pd=ELF((lab/'android-native/libexternal_wrapper.so').read_bytes());resolve_local_abs64(pd)
    checks=[];slots=0
    for start in (0x89400,0x89f08,0x8a1f4,0x8a578):
        name=hex(start)+'-external_wrapper-model.json';path=out/name;other=rerun/name
        assert digest(path)==digest(other),'independent model output differs'
        flow=json.loads(path.read_text(encoding='utf8'));assert flow['error'] is None
        for ins in flow['trace']:
            off=pd.file_offset(int(ins['pc'],16));assert pd.data[off:off+4].hex()==ins['bytes'];slots+=1
        regs=[x for x in flow['calls'] if x.get('operation')=='RegisterNatives'];assert len(regs)==1
        for reg in regs:
            for row in reg['rows']:
                desc='L'+reg['class']+';->'+row['name']+row['signature'];assert desc in native and desc not in rows
                assert pd.executable(int(row['function_address'],16))
                rows[desc]={**row,'dex_descriptor':desc,'class':reg['class'],'library':'libexternal_wrapper.so','register_natives_call':reg['pc'],
                  'evidence_file':name,'provenance_scope':'JNI_OnLoad GetEnv helper argument; fresh guard initialization; successful FindClass selected path','runtime_success_proven':False}
        checks.append({'file':name,'sha256':digest(path),'independent_rerun_same_bytes':True,'instruction_count':len(flow['trace']),'unmodeled_instructions':0})
    bridge=json.loads((out/'jnibridge-provenance.json').read_text(encoding='utf8'));desc=bridge['method']['dex_descriptor'];assert desc in native and desc not in rows
    rows[desc]={**bridge['method'],'library':'libunity.so','evidence_file':'jnibridge-provenance.json','provenance_scope':bridge['analysis_scope'],'runtime_success_proven':False}
    assert len(rows)==160 and set(rows)<native;remaining=sorted(native-set(rows));assert len(remaining)==1 and 'NativeOnCompleteListener' in remaining[0]
    # Existing raw DEX catalog already decoded every method boundary, preserving
    # native invocation references and code-unit locations; zero decode errors.
    assert dex['instruction_decode_errors']==[]
    callers=[]
    for caller in dex['native_and_load_calls']:
        for call in caller['calls']:
            if call['method']==remaining[0]:callers.append({'caller':caller['method'],'callee':call['method'],'code_unit':call['code_unit']})
    assert len(callers)==1 and '->onComplete(' in callers[0]['caller']
    dexbytes=(lab/'android/classes.dex').read_bytes()
    targets={x['id']:x['name'] for x in dex['methods'] if 'Lcom/google/android/gms/tasks/NativeOnCompleteListener;->' in x['name']}
    widths=[1]*256
    for op in [0x02,0x05,0x08,0x13,0x15,0x16,0x19,0x1a,0x1c,0x1f,0x20,0x22,0x23,0x29]:widths[op]=2
    for op in [0x03,0x06,0x09,0x14,0x17,0x1b,0x24,0x25,0x26,0x2a,0x2b,0x2c]:widths[op]=3
    widths[0x18]=5
    for lo,hi in ((0x2d,0x3e),(0x44,0x6e),(0x90,0xb0),(0xd0,0xe3)):
        for op in range(lo,hi):widths[op]=2
    invokes=set(range(0x6e,0x73))|set(range(0x74,0x79))
    for op in invokes:widths[op]=3
    widths[0xfa]=widths[0xfb]=4; widths[0xfc]=widths[0xfd]=3;widths[0xfe]=widths[0xff]=2
    all_callback_calls=[];decoded=0
    for method in dex['methods']:
        off=method['code_offset']
        if not off:continue
        size=struct.unpack_from('<I',dexbytes,off+12)[0];units=struct.unpack_from('<'+'H'*size,dexbytes,off+16);pos=0
        while pos<size:
            unit=units[pos];op=unit&255;width=widths[op]
            if op==0 and unit>>8:
                tag=unit>>8
                if tag==1:width=4+2*units[pos+1]
                elif tag==2:width=2+4*units[pos+1]
                elif tag==3:width=4+(units[pos+1]*(units[pos+2]|units[pos+3]<<16)+1)//2
                else:raise ValueError('unknown DEX payload')
            assert pos+width<=size
            if op in invokes and units[pos+1] in targets:
                all_callback_calls.append({'caller':method['name'],'callee':targets[units[pos+1]],'code_unit':pos,'dex_file_offset':hex(off+16+2*pos),
                                           'raw_instruction_bytes':dexbytes[off+16+2*pos:off+16+2*(pos+width)].hex()})
            pos+=width
        decoded+=1
    assert decoded==8256
    source=lab/'jadx/sources/com/google/android/gms/tasks/NativeOnCompleteListener.java'
    original_audit=json.loads((previous/'remaining-native-audit.json').read_text(encoding='utf8'))
    absence=[x for x in original_audit['string_presence'] if x['dex_descriptor']==remaining[0]];assert len(absence)==1
    summary={'prior_bindings':150,'additional_external_wrapper_bindings':9,'additional_jni_bridge_bindings':1,'combined_distinct_dex_descriptors':160,
      'total_dex_native_declarations':161,'remaining_descriptors':remaining,'external_wrapper_instruction_trace_entries_verified':slots,'external_wrapper_instruction_bytes_verified':slots*4,'external_wrapper_rerun_checks':checks,
      'unsupported_external_wrapper_instructions':0,'unsupported_external_wrapper_conditions':0,
      'branch_policy':'Concrete byte values and implemented EQ/NE conditions; no manually chosen internal branches. External fresh-guard and JNI success preconditions remain explicit.',
      'jni_registration_observed_in_runtime':False,'native_oncomplete_incoming_dex_calls':callers,
      'native_oncomplete_all_class_incoming_calls':all_callback_calls,'dex_all_code_methods_scanned':decoded,'dex_sha256':hashlib.sha256(dexbytes).hexdigest(),
      'native_oncomplete_jadx_source':{'path':str(source),'sha256':digest(source)},
      'native_oncomplete_static_usage':'createAndAddCallback constructs the listener and adds it to Task; onComplete forwards native handle, result, successful/canceled booleans, and exception message.',
      'native_oncomplete_plaintext_presence_audit':absence[0],
      'analysis_dependency':{'capstone_version':'5.0.7','dll_sha256':digest(lab/'python-analysis/capstone/lib/capstone.dll'),
        'location':str(lab/'python-analysis'),'scope':'Capstone decodes original instructions; the explicit Python model interprets only the recorded supported operations.'},
      'source_libraries':[{ 'library':name,'sha256':digest(lab/'android-native'/name)} for name in ('libunity.so','libexternal_wrapper.so')],
      'limitations':['Original 150-binding corpus remains unchanged; combined table references its evidence.',
        'Offline instruction interpretation never executes the APK. Fresh initialization, successful JNI calls, and no competing global writes are path preconditions.',
        'The JNIBridge chain is manually reviewed with asserted critical operands, not a whole-program automated proof.',
        'No runtime JNI registration instrumentation was performed by this analysis. Other parent runtime menu evidence does not prove these registrations.',
        'NativeOnCompleteListener has no resolved local function binding. External packages, remotely loaded code and generated/packed runtime code were not analyzed; absence of plaintext does not prove dead code.']}
    (out/'combined-static-bindings.json').write_text(json.dumps({'bindings':list(rows.values()),'summary':summary},ensure_ascii=False,indent=2),encoding='utf8')
    (out/'continuation-summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf8')
    artifact_hashes={p.name:digest(p) for p in sorted(out.glob('*.json')) if p.name!='continuation-artifact-hashes.json'}
    (out/'continuation-artifact-hashes.json').write_text(json.dumps(artifact_hashes,indent=2),encoding='utf8')
    print(json.dumps({k:summary[k] for k in ('combined_distinct_dex_descriptors','remaining_descriptors','external_wrapper_instruction_trace_entries_verified','external_wrapper_instruction_bytes_verified','unsupported_external_wrapper_instructions')}))


if __name__=='__main__':main()
