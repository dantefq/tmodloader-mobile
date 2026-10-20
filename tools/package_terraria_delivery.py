"""Copy only final, validated game-derived artifacts to a durable private folder."""
import argparse, json, pathlib, shutil, subprocess, os

def copy_tree(source,destination):
    if os.name!='nt':
        shutil.copytree(source,destination,dirs_exist_ok=True);return
    result=subprocess.run(['robocopy',str(source),str(destination),'/E','/COPY:DAT','/R:1','/W:1','/MT:16','/NFL','/NDL','/NJH','/NJS','/NP'],capture_output=True,text=True)
    if result.returncode>=8:raise RuntimeError('Local copy failed: '+result.stdout+result.stderr)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',type=pathlib.Path,required=True);ap.add_argument('--delivery',type=pathlib.Path,required=True);a=ap.parse_args()
    lab=a.lab.resolve();dest=a.delivery.resolve();repo=pathlib.Path(__file__).resolve().parents[1]
    if dest==lab or dest.is_relative_to(lab) or lab.is_relative_to(dest) or dest.is_relative_to(repo):raise ValueError('Unsafe delivery nesting')
    p=json.loads((lab/'pseudocode/progress.json').read_text())
    if p.get('finished') is not True or p.get('processed')!=93990:raise ValueError('Native export not finished')
    for name in ('instruction-verification.json','pseudocode-audit.json'):
        if json.loads((lab/'pseudocode'/name).read_text(encoding='utf8')).get('passed') is not True:raise ValueError(name+' did not pass')
    if (lab/'native-ranges-pseudocode').exists():
        for relative,key in [('native/native-ranges-export-audit.json','passed'),('hard-functions-ir/audit.json','integrity_passed'),('hard-functions-raw-ir/audit.json','integrity_passed'),('pseudocode-v4-hard/audit.json','passed')]:
            if json.loads((lab/relative).read_text(encoding='utf8')).get(key) is not True:raise ValueError(relative+' did not pass')
        for relative in ('pseudocode-stack32-retry/retry-progress.json','pseudocode-v4-hard/retry-progress.json'):
            if json.loads((lab/relative).read_text(encoding='utf8')).get('finished') is not True:raise ValueError(relative+' unfinished')
    dest.mkdir(parents=True,exist_ok=True)
    for name in ('metadata','native','android','assets','jadx','android-native','pseudocode'):
        copy_tree(lab/name,dest/name)
    if (lab/'native-ranges-pseudocode').exists():
        for name in ('native-ranges-pseudocode','hard-functions-ir','hard-functions-raw-ir','pseudocode-stack32-retry','pseudocode-v4-hard','abi-control-probe-v4','runtime-evidence'):
            copy_tree(lab/name,dest/name)
        for name in ('PHASE2.ru.md','phase2-evidence-summary.json','native-ranges.html','coverage-v3-before-stack32.jsonl','ghidra-stack32-provenance.json','decompiler-crash-events-minimal.json'):
            shutil.copy2(lab/name,dest/name)
        for path in lab.glob('runtime-*.txt'):shutil.copy2(path,dest/path.name)
        for name in ('runtime-preflight.json','runtime-start.txt','runtime-install.log'):
            shutil.copy2(lab/name,dest/name)
        typed_project=dest/'ghidra-project-v4';typed_project.mkdir(exist_ok=True)
        shutil.copy2(lab/'ghidra-project-v4/TerrariaAndroidFinal.gpr',typed_project/'TerrariaAndroidFinal.gpr')
        copy_tree(lab/'ghidra-project-v4/TerrariaAndroidFinal.rep',typed_project/'TerrariaAndroidFinal.rep')
    for name in ('README.ru.md','REPORT.ru.md','index.html','explorer-build.json','explorer-smoke.json'):
        if (lab/name).is_file():shutil.copy2(lab/name,dest/name)
    tools=dest/'tools';tools.mkdir(exist_ok=True)
    for path in (repo/'tools').iterdir():
        if path.is_file() and 'terraria' in path.name.lower():shutil.copy2(path,tools/path.name)
    shutil.copy2(repo/'tools/prepare_ghidra_stack_copy.py',tools/'prepare_ghidra_stack_copy.py')
    shutil.copy2(repo/'tools/apk_format.py',tools/'apk_format.py')
    shutil.copy2(repo/'.tools/terraria-re/tools.json',tools/'tool-provenance.json')
    evidence=dest/'evidence';evidence.mkdir(exist_ok=True)
    for path in (repo/'reports/terraria-re-20261012').glob('*-summary.json'):shutil.copy2(path,evidence/path.name)
    for pattern in ('terraria-rea-*-20261012.json','terraria-ghidra-*.log'):
        for path in (repo/'reports').glob(pattern):shutil.copy2(path,evidence/path.name)
    notes=dest/'notes';notes.mkdir(exist_ok=True)
    for path in (repo/'notes').glob('terraria-*-2026101[23].md'):
        text=path.read_text(encoding='utf8').replace(lab.as_posix(),dest.as_posix()).replace(str(lab),str(dest))
        (notes/path.name).write_text(text,encoding='utf8')
    project=dest/'ghidra-project';project.mkdir(exist_ok=True)
    shutil.copy2(lab/'ghidra-project/TerrariaAndroidFinal.gpr',project/'TerrariaAndroidFinal.gpr')
    copy_tree(lab/'ghidra-project/TerrariaAndroidFinal.rep',project/'TerrariaAndroidFinal.rep')
    print(json.dumps({'delivery':str(dest),'native_processed':p['processed'],'native_decompiled':p['decompiled'],'native_failed':p['failed'],'copied_final_project':'TerrariaAndroidFinal'},ensure_ascii=False))

if __name__=='__main__':main()
