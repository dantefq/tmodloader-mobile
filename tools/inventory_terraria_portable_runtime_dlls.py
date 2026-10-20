"""Static inventory of exactly four pinned x86_64 LLVM-MinGW runtime DLLs.

Reads PE bytes using the frozen inspector class; never loads DLLs, resolves
dependencies, invokes utilities, or runs compiler/engine/Ghidra/angr.
"""
import argparse
import ast
import datetime
import hashlib
import json
from pathlib import Path
import struct

PARSER_SHA='fcecf18468c6c0568eca73c8cd1250f287ca81f7cb26199b69815518e36a78e8'
TOP='llvm-mingw-20260908-ucrt-x86_64'
EXPECTED={
    'libc++.dll':(2008576,'06a2ed158f5a91e4d500c8b0764a25dfe57097991d137d8272c529eeb5c66048'),
    'libunwind.dll':(190464,'aa282fa47bb2c4e210cea5e470cdbdca58568f0be0bc73e404d86ab9cd95ef6a'),
    'libwinpthread-1.dll':(270336,'755754ea51c3c5f269916014645a94a14198ef46b3125987bc78fa4f768b424e'),
    'libomp.dll':(954880,'5cbdfaf904925c0a9b062ae50b10f49ba4bdf636cf31d212f29a8b5f2c05f5f2'),
}

def sha(data):return hashlib.sha256(data).hexdigest()
def require(ok,message):
    if not ok:raise ValueError(message)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--lab',type=Path,default=Path('C:/Temp/terraria-re-20261012'))
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();lab=a.lab.resolve();out=a.output.resolve()
    require(out.is_relative_to(lab) and not out.exists(),'Fresh output within private lab required')
    base=lab/'portable-decompiler-baseline-prep-20261017'
    manifest_path=base/'preparation-manifest.json';manifest_raw=manifest_path.read_bytes();m=json.loads(manifest_raw)
    require(m['schema']=='portable-ghidra-baseline-preparation-v1','Wrong preparation schema')
    parser_path=Path(__file__).resolve().with_name('review_terraria_decompiler_pe.py');parser_raw=parser_path.read_bytes()
    require(sha(parser_raw)==PARSER_SHA,'Frozen PE inspector differs')
    tree=ast.parse(parser_raw.decode());classes=[n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='PE']
    require(len(classes)==1,'Expected exactly one PE parser class')
    ns={'struct':struct}
    # Compile definitions only: no inspector main, CLI, engine loading or native invocation.
    exec(compile(ast.Module(body=classes,type_ignores=[]),str(parser_path),'exec'),ns)
    PE=ns['PE'];rows=[];names={n.casefold():n for n in EXPECTED}
    for name,(size,digest) in EXPECTED.items():
        rel=f'{TOP}/x86_64-w64-mingw32/bin/{name}'
        matches=[v for v in m['toolchain_files'] if v['path']==rel]
        require(len(matches)==1 and matches[0]['bytes']==size and matches[0]['sha256']==digest,'Pinned manifest row differs: '+name)
        path=base/'toolchain'/rel
        require(path.resolve().is_relative_to(base.resolve()) and path.is_file() and not path.is_symlink() and not(getattr(path.lstat(),'st_file_attributes',0)&0x400),'Unsafe DLL input')
        raw=path.read_bytes();require(len(raw)==size and sha(raw)==digest,'DLL hash/size differs: '+name)
        pe=PE(raw)
        # Independent direct COFF/optional-header field read, not another PE loader.
        offset=struct.unpack_from('<I',raw,0x3c)[0]
        machine=struct.unpack_from('<H',raw,offset+4)[0]
        characteristics=struct.unpack_from('<H',raw,offset+22)[0]
        magic=struct.unpack_from('<H',raw,offset+24)[0]
        require(machine==pe.machine==0x8664 and magic==0x20b and bool(characteristics&0x2000),'Expected AMD64 PE32+ DLL')
        imports=pe.imports()  # EXE static_gate_failures deliberately never called for DLLs.
        dependencies=[]
        for imp in imports:
            dependencies.append(dict(dll=imp['dll'],ordinary_import_symbol_count=len(imp['symbols']),named_symbol_count=sum('name' in s for s in imp['symbols']),ordinal_symbol_count=sum('ordinal' in s for s in imp['symbols']),same_four_runtime_name=names.get(imp['dll'].casefold()),exports_or_runtime_resolution_verified=False))
        rows.append(dict(name=name,path=str(path.resolve()),bytes=size,sha256=digest,machine=hex(machine),optional_magic=hex(magic),DLL_characteristic=True,import_dlls=dependencies,ordinary_import_DLL_count=len(imports),ordinary_import_symbol_count=sum(len(i['symbols']) for i in imports),delay_import_directory=pe.directory(13),bound_import_directory=pe.directory(11),ordinary_imports=imports,dependencies_resolved=False,exports_resolved=False,DLL_loaded=False))
    edges=[dict(importer=r['name'],imported_DLL_name=d['dll'],same_four_runtime_name=d['same_four_runtime_name'],ordinary_import_symbol_count=d['ordinary_import_symbol_count'],evidence='Import descriptor basename matches a separately pinned DLL; exports and loader resolution not checked') for r in rows for d in r['import_dlls'] if d['same_four_runtime_name']]
    report=dict(schema='portable-runtime-DLL-static-inventory-v1',created_UTC=datetime.datetime.now(datetime.timezone.utc).isoformat(),inventory_script_sha256=sha(Path(__file__).read_bytes()),preparation_manifest=str(manifest_path),preparation_manifest_sha256=sha(manifest_raw),PE_parser_sha256=PARSER_SHA,scope='Exactly four prepared x86_64-w64-mingw32/bin runtime DLLs; file bytes only',files=rows,ordinary_import_name_matches_within_four=edges,all_other_dependencies_unresolved=True,transitive_closure_verified=False,export_resolution_verified=False,future_engine_dependency_set_known=False,compiler_invoked=False,engine_executed=False,native_utility_invoked=False,C_coverage_addition=0)
    out.write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
    print(json.dumps(dict(output=str(out),files=[dict(name=r['name'],bytes=r['bytes'],machine=r['machine'],ordinary_import_DLL_count=r['ordinary_import_DLL_count'],ordinary_import_symbol_count=r['ordinary_import_symbol_count'],import_dlls=r['import_dlls']) for r in rows],within_four_import_name_matches=edges),indent=2))

if __name__=='__main__':main()
