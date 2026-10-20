"""Freeze a separately versioned exact-extent-fill exporter and derived manifests."""
import hashlib
import json
import shutil
from pathlib import Path

LAB=Path(r'C:\Temp\terraria-re-20261012')
TOOLS=Path(__file__).resolve().parent
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
source=TOOLS/'apk-native-v2/ApkNativeRangeExport.java'
assert sha(source)=='99e33a4a11d48350de6dd83a2f1b8939badfb1f47b8774a90fdfc9d7b65627d4'
frozen=LAB/'other-native-exporter-v2-sources-20261019'
out=LAB/'other-native-range-v2-manifests-20261019'
assert not frozen.exists() and not out.exists()
frozen.mkdir();out.mkdir()
for name in ('ApkNativeRangeExport.java','audit_apk_native_range_export_v2.py'):
    shutil.copyfile(TOOLS/'apk-native-v2'/name,frozen/name)
parent=LAB/'other-native-range-manifests-20261019'
summary=json.loads((parent/'summary.json').read_text())
derived=[]
for r in summary:
    old=parent/(r['library']+'.manifest.json')
    assert sha(old)==r['manifest_sha256']
    m=json.loads(old.read_text())
    assert m['profile']=='apk-native-bounded-range-C-v1'
    m.update(profile='apk-native-bounded-range-C-v2',derived_from_manifest_sha256=sha(old),
             v2_generator_sha256=sha(Path(__file__)),v2_exporter_sha256=sha(source),
             body_fill_model='Only same-entry contiguous subset importer bodies may expand to the explicit input extent, within a rolled-back transaction; no other overlaps, thunks, or existing NoReturn functions accepted.')
    p=out/old.name;p.write_text(json.dumps(m,indent=2)+'\n')
    derived.append(dict(r,manifest_sha256=sha(p)))
(out/'summary.json').write_text(json.dumps(derived,indent=2)+'\n')
(frozen/'source-manifest.json').write_text(json.dumps([dict(name=p.name,sha256=sha(p)) for p in sorted(frozen.iterdir())],indent=2)+'\n')
print('V2 sources and separately derived manifests frozen; no engine execution.')
