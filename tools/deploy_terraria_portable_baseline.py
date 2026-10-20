"""Copy a separate Ghidra installation and pinned baseline engine; never execute it."""
import hashlib
import json
import shutil
from pathlib import Path


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


lab = Path(r'C:\Temp\terraria-re-20261012').resolve()
base = lab / 'portable-decompiler-baseline-prep-20261017'
source = lab / 'ghidra-stack32'
target = lab / 'ghidra-portable-baseline-20261018'
engine = base / 'baseline-build/decompile.exe'
review = json.loads((lab / 'pe-review-portable-baseline-20261018.json').read_text())
assert sha(engine) == review['sha256'] == '5d39674818484db40000dd0a3171493661ed6e3efd01a80de47cc21321eac40c'
assert review['header_gates_passed'] is True
assert not target.exists() and target.parent == lab
dlls = {
    'libc++.dll': '06a2ed158f5a91e4d500c8b0764a25dfe57097991d137d8272c529eeb5c66048',
    'libunwind.dll': 'aa282fa47bb2c4e210cea5e470cdbdca58568f0be0bc73e404d86ab9cd95ef6a',
}
runtime = base / 'toolchain/llvm-mingw-20260908-ucrt-x86_64/x86_64-w64-mingw32/bin'
for name, expected in dlls.items():
    assert sha(runtime / name) == expected
shutil.copytree(source, target)
osdir = target / 'Ghidra/Features/Decompiler/os/win_x86_64'
original = sha(source / 'Ghidra/Features/Decompiler/os/win_x86_64/decompile.exe')
assert original == '1fd85827247f1ff1417fa412db26a53066d050c59017db98dd23ff196751521e'
shutil.copy2(engine, osdir / 'decompile.exe')
for name in dlls:
    shutil.copy2(runtime / name, osdir / name)
assert sha(osdir / 'decompile.exe') == review['sha256']
assert sha(source / 'Ghidra/Features/Decompiler/os/win_x86_64/decompile.exe') == original
for name, expected in dlls.items():
    assert sha(osdir / name) == expected
record = dict(target=str(target), engine_sha256=sha(osdir / 'decompile.exe'),
              original_installation_engine_unchanged=True, runtime_dlls=dlls,
              engine_executed=False, system_API_set_resolution_verified=False,
              C_coverage_addition=0)
(lab / 'portable-baseline-deployment-20261018.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(record))
