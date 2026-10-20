"""Offline inventory and gated observation plan only: never invokes ADB or any target process."""
import hashlib,json,mmap
from pathlib import Path
import struct
LAB=Path('C:/Temp/terraria-re-20261012')
SDK=Path.home()/'AppData/Local/Android/Sdk'
OUT=LAB/'runtime-array-observation-plan-20261015'
def sha(data):return hashlib.sha256(data).hexdigest()

def props(path):
    result={}
    for line in path.read_text(encoding='utf8').splitlines():
        if not line.strip() or line.lstrip().startswith('#') or '=' not in line:continue
        k,v=line.split('=',1);result[k.strip()]=v.strip()
    return result

def main():
    marker=LAB/'runtime-world-20261014/launch.json';launch=json.loads(marker.read_text(encoding='utf-8-sig'))
    assert launch['avd']=='TerrariaRE' and launch['serial']=='emulator-5580' and launch['personal_avd_used'] is False
    config=LAB/'runtime-avd/TerrariaRE.avd/config.ini';conf=props(config)
    assert conf['AvdId']=='TerrariaRE' and conf['image.sysdir.1'].replace('\\','/').rstrip('/')==str(SDK/'system-images/android-34/google_apis_playstore/x86_64').replace('\\','/')
    image_inventory=[]
    for p in sorted((SDK/'system-images').rglob('build.prop')):
        d=props(p)
        image_inventory.append(dict(build_prop_path=str(p),build_prop_sha256=sha(p.read_bytes()),
                                    build_type=d.get('ro.build.type'),debuggable=d.get('ro.debuggable'),
                                    force_debuggable=d.get('ro.force.debuggable'),secure=d.get('ro.secure'),
                                    native_bridge=d.get('ro.dalvik.vm.native.bridge'),
                                    rootable_candidate_by_local_properties=d.get('ro.build.type') in ('userdebug','eng') and d.get('ro.debuggable')=='1'))
    currentpath=Path(conf['image.sysdir.1'])/'build.prop';current=props(currentpath)
    rootable=[r for r in image_inventory if r['rootable_candidate_by_local_properties']]
    source=LAB/'native/libil2cpp.so'
    with source.open('rb') as f:
      with mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as raw:
        assert sha(raw)=='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5'
        po=struct.unpack_from('<Q',raw,32)[0];ps,pn=struct.unpack_from('<HH',raw,54)
        segments=[struct.unpack_from('<II6Q',raw,po+i*ps) for i in range(pn)]
        load_segments=[dict(flags=s[1],file_offset=s[2],virtual_address=s[3],file_size=s[5],memory_size=s[6],alignment=s[7]) for s in segments if s[0]==1]
        def read(va,n):
            hit=[s[2]+va-s[3] for s in segments if s[0]==1 and s[3]<=va and va+n<=s[3]+s[5]]
            assert len(hit)==1;return raw[hit[0]:hit[0]+n]
        anchors=[dict(ELF_VA=hex(va),expected_ARM64_bytes=read(va,n).hex()) for va,n in [(0x7143a4,8),(0x751b1c,16),(0x753450,8)]]
        assert any(s['flags']&2 and s['virtual_address']<=0x310d958< s['virtual_address']+s['file_size'] for s in load_segments)
    dependencies={}
    for name in ['runtime-world-20261014/launch.json','runtime-world-20261014/summary.json',
                 'static-field-roots-20261015/static-field-roots.json','initialize-array-copy-model-20261015/copy-model.json',
                 'initializer-refinement-20261015/setfactory-size.json','itemsets-array-literals-20261015/array-literals.json']:
        p=LAB/name;dependencies[name]=sha(p.read_bytes())
    factory=json.loads((LAB/'initializer-refinement-20261015/setfactory-size.json').read_text())
    item=next(r for r in factory['results'] if r['initializer_type']=='Terraria.ID.ItemID+Sets')
    assert item['conditional_instance_field_result']=={'field':'Terraria.ID.SetFactory::_size','offset':16,'value':6196}
    doc=dict(profile='offline-read-only-runtime-array-observation-plan-v1',producer_sha256=sha(Path(__file__).read_bytes()),
             status='not_ready_no_supported_read_memory_device_established',AVD_or_app_started=False,ADB_invoked=False,
             memory_observed=False,owned_AVD='TerrariaRE',serial='emulator-5580',package='com.and.games505.TerrariaPaid',
             original_APK_sha256='1f8e2ba7ddabaee961a1b2552d44bc0c281c9b5122480642b018779bcbf2fe8e',
             original_ELF_sha256='9bf86a30b01efc6a02b9f7bc31bad1da982ed476a2b71c03b7669f172ca53cd5',
             dependencies=dependencies,owned_config_sha256=sha(config.read_bytes()),system_image_inventory=image_inventory,
             locally_installed_rootable_candidate_count=len(rootable),current_image_properties={k:current[k] for k in ('ro.build.type','ro.debuggable','ro.force.debuggable','ro.secure','ro.dalvik.vm.native.bridge')},
             availability_conclusion='Only Google Play API34 x86_64 user image is installed; local properties are ro.debuggable=0 and ro.force.debuggable=0. No rootable userdebug/eng image was found. Root/readmem capability has not been observed and is not treated as available.',
             ELF_PT_LOAD=load_segments,guest_ARM64_source_byte_anchors=anchors,
             future_identity_gates=['Parent explicitly resumes runtime work after the memory-heavy Ghidra queue; no AVD/app creation/start is part of this plan.',
                                    'Query only recorded emulator-5580 and require its emu avd name is exactly TerrariaRE plus the owned local marker/config. No fallback to another emulator, serial or package.',
                                    'Require boot complete, offline/no routes, exactly one installed base APK for the package with the exact original SHA256, and exactly one PID whose /proc/PID/cmdline is the exact package.',
                                    'Read-only inspect effective uid, ro.debuggable/build.type and SELinux status. If root/proc maps/mem access is not already legitimately available, stop with a capability gap. Do not invoke adb root, su, run-as bypass, setenforce, remount, install/repack, debugger/Frida injection or network changes.'],
             future_ASLR_gates=['Read only the verified package PID /proc/PID/maps. Identify the actual mapped ARM64 ELF image; host x86_64 translated code/nativebridge addresses are not the guest ELF base.',
                                'Match maps file offsets/page alignments to the original ELF PT_LOAD offsets and vaddrs; solve a unique load bias satisfying every available mapped segment. APK-backed embedded-library mapping offsets must account for the exact zip-member file origin, otherwise stop.',
                                'Before chasing pointers, require bytes at bias+0x7143a4/+0x751b1c/+0x753450 match the recorded ARM64 originals and that bias+0x310d958 lies in the matching readable library data mapping. Reject unresolved ambiguity or incompatible pointer width/layout.',
                                'All later pointer/range reads must be within readable mappings of this same verified PID; reject tagged/noncanonical/unmapped pointers rather than guessing tag stripping.'],
             future_bounded_reads=[
                 {'step':'class_root','formula':'read_u64(load_bias + 0x310d958)','gate':'Require a resolved mapped pointer, not original encoded usage0x2000968d.'},
                 {'step':'static_storage','formula':'read_u64(klass + 0xb8)','gate':'Require mapped readable pointer and stable root/header in a repeated check.'},
                 {'step':'factory_size','formula':'Factory=read_u64(static_storage + 0); size=read_i32(Factory + 16)','gate':'Require size==6196 from source constructor argument; do not increase read budget on mismatch.'},
                 {'step':'array_roots','formula':'read_u64(static_storage + offset) for offsets24/32/40/48','gate':'Expected fields DualEquipArmor,AllowSmartInteractOnCursorItem,ReceivesDiagonalCorrectionAsFakeFish,AccessoryIncompatibilityType from source-bound field offsets.'},
                 {'step':'array_layout','formula':'arrayklass=read_u64(array); element_size=read_u32(arrayklass+0x100); length=read_u64(array+0x18)','gate':'Require length==6196 and element sizes1/1/1/4 respectively; data starts at+0x20. Record this as an observation, not assumed ABI success.'},
                 {'step':'payloads','formula':'read data at array+0x20 for size*element_size bytes','gate':'Four buffers total43372bytes; individual chunks<=4096bytes and aggregate including pointers/headers<=65536bytes. Stop on any error/short read/change; never dump other memory.'},
                 {'step':'stability','formula':'Repeat only root pointers, factory size, array headers and optionally bounded payload hashes','gate':'Require equal observations to flag stable samples; this does not prove an atomic snapshot or absence of unobserved races.'}],
             future_output_directory=str(LAB/'runtime-array-observation-future'),
             evidence_requirements=['Save exact maps, identity facts, each requested address/size/read result and private buffer hashes; no memory dump in repository.',
                                    'Separate observed lengths/element sizes/values from source-expected values. Do not mark full semantic equivalence, full InitializeArray proof or full ItemID.Sets membership merely because four snapshots match.',
                                    'No screen interaction is needed for raw observation; prior screenshot-tap authorization remains recorded but this plan performs no input.'],
             remaining_gaps=['No installed rootable system image and no actual supported root/readmem device established.',
                             'No guest ARM64 maps/PT_LOAD load-bias identity checked in a live process.',
                             'No actual FieldInfo/class-cache construction, live array contents, live element sizes or root pointer stability observed.'])
    assert len(image_inventory)==1 and not rootable and current['ro.debuggable']=='0'
    OUT.mkdir(exist_ok=True);(OUT/'plan.json').write_text(json.dumps(doc,indent=2)+'\n')
    lines=['# План наблюдения четырёх runtime-массивов: пока недоступен','',
           'Ничего не запущено: AVD, игра, ADB и чтение памяти не выполнялись. Проверены только уже существующие локальные файлы.',
           '', 'Установлен единственный образ: Google Play API34 x86_64, build.type=user, ro.debuggable=0, ro.force.debuggable=0. GoogleAPIs/userdebug/eng образа нет. Поэтому доступ root/proc/mem на используемом TerrariaRE не подтверждён и не считается готовым маршрутом. adb root, SELinux changes и injection не выполнялись.',
           '', 'Будущее чтение ограничено исходным package/APK/ELF и emulator-5580/TerrariaRE. Сначала требуются уже доступные права и однозначный guest ARM64 load bias по PT_LOAD/maps/исходным байтам; host x86 nativebridge адреса нельзя автоматически использовать как guest base.',
           '', 'При выполнении всех gates можно прочитать class root0x310d958 → klass+0xb8 → Factory/_size и arrays+24/+32/+40/+48. Предложенный лимит:43372байта payload, chunk≤4096, общий≤65536. Наблюдение этих четырёх экземпляров поможет проверить конкретные layouts/размеры/значения; оно не доказывает полную семантическую эквивалентность.',
           '', '[Инвентарь, источники, ASLR gates, точные будущие чтения и оставшиеся gaps](plan.json). Исполняемый raw-memory sampler намеренно не создан, поскольку доступный маршрут чтения не установлен.']
    (OUT/'REPORT.ru.md').write_text('\n'.join(lines)+'\n',encoding='utf8')
    print(json.dumps(dict(status=doc['status'],installed_images=len(image_inventory),rootable_candidates=len(rootable),ADB_invoked=False,memory_observed=False)))

if __name__=='__main__':main()
