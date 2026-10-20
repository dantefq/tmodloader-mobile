"""Plan explicitly named local targets and retain exact artifact identities.

Reads metadata only. Does not enable mods, load DLLs or install anything.
"""
import argparse
import json
from pathlib import Path
import subprocess
from plan_mod_load import build


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory',type=Path,default=Path('reports/workshop-inventory-current.json'))
    parser.add_argument('--dotnet',type=Path,default=Path('C:/Program Files/dotnet'))
    parser.add_argument('--lab',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('names',nargs='+')
    args=parser.parse_args()
    inventory=json.loads(args.inventory.read_text('utf-8'))
    selected=[]
    for name in args.names:
        candidates=[r for r in inventory['files'] if r['name']==name]
        if not candidates:raise ValueError('Local target missing: '+name)
        selected.append(max(candidates,key=lambda r:tuple(map(int,r['tmodloader_build_version'].split('.')))))
    command=build(args.dotnet,args.lab)
    result=subprocess.run([*command,'client',*[str(Path(inventory['root'])/r['path']) for r in selected]],
                          text=True,capture_output=True,timeout=300)
    if result.returncode not in (0,2):raise ValueError(result.stderr or result.stdout)
    report=json.loads(result.stdout)
    report['selection']='Highest loader build per explicitly named mod in the supplied local inventory; graph validity is not runtime compatibility.'
    report['assembly_executed']=False
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(valid=report['valid'],order=report['order'],issues=report['issues'],
                         selected=[dict(name=r['name'],version=r['version']) for r in report['artifacts']]),indent=2))


if __name__=='__main__':main()
