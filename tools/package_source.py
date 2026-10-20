"""Package only this project's own source/docs/reports; no APKs, game data or keys."""
from pathlib import Path
import json
import zipfile
from check_publication import validate

root = Path(__file__).resolve().parents[1]
files = [root/'.gitignore', *root.glob('*.md'),
         *root.glob('START_*.cmd'), root/'reports/public-validation-summary.json']
for directory in ('android','runtime','managed','mods','tools'):
    files.extend(p for p in (root/directory).rglob('*')
                 if p.is_file() and p.suffix in ('.java','.xml','.js','.mjs','.cs','.c','.h','.json','.py','.md') and not any(part in ('__pycache__','bin','obj') for part in p.parts))
output = root/'dist/Terraria-Mobile-Managed-Loader-source.zip'
output.parent.mkdir(parents=True,exist_ok=True)
for source in files:
    validate(source.relative_to(root).as_posix(), source.read_bytes())
with zipfile.ZipFile(output,'w',compression=zipfile.ZIP_DEFLATED) as archive:
    for source in sorted(files):
        relative=source.relative_to(root)
        archive.write(source,relative.as_posix())
print(json.dumps({'source_archive':str(output),'file_count':len(files),'bytes':output.stat().st_size}))
