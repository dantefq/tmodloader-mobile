"""Join hash-matched dependency plans and static ABI diagnostics before execution."""
import argparse
import json
from pathlib import Path


def join(plan, signatures, time_signatures):
    if not plan.get('valid') or plan.get('issues'):
        raise ValueError('Dependency plan must pass before ABI diagnostics are joined')
    artifacts = {r['name']:r for r in plan['artifacts']}
    times = {r['mod']:r for r in time_signatures['candidates']}
    if len(artifacts) != len(plan['artifacts']):
        raise ValueError('Duplicate dependency artifact')
    results = []
    for row in signatures['candidates']:
        artifact = artifacts.get(row['mod'])
        if artifact is None or (artifact['sha256'],artifact['version'],artifact['loader_version']) != (
                row['tmod_sha256'],row['version'],row['loader']):
            raise ValueError('Plan/signature artifact identity differs: '+row['mod'])
        time = times.get(row['mod'])
        if time is None or (time['tmod_sha256'],time['assembly_sha256']) != (row['tmod_sha256'],row['assembly_sha256']):
            raise ValueError('Time/item audit identity differs: '+row['mod'])
        problems = [r for r in row['member_checks'] if r['status']!='exact-signature']
        overrides = [r for r in row['override_checks'] if r['status']!='exact-override']
        other_assemblies = [r for r in row['assembly_references'] if r['name']!='tModLoader' and
                            not r['name'].startswith('System.') and r['name'] not in ('System','mscorlib','netstandard')]
        narrow_sleep = (row['mod']=='ChangeSleepTime' and
            row['assembly_sha256']=='3170283e245da54517d960a0ee7667de00ee166b3fddd751e180c8f4797d47c8' and
            not time['missing_types'] and time['counts']=={'exact-signature':13} and
            time['override_counts']=={'exact-override':2})
        results.append(dict(name=row['mod'],version=row['version'],tmod_sha256=row['tmod_sha256'],
            dll_sha256=row['assembly_sha256'],loader_version=row['loader'],build_version=artifact['build_version'],
            side=artifact['side'],required=artifact['required'],weak=artifact['weak'],
            dependency_plan_valid=True, general_loader_launch_allowed=False,
            audited_route='hash-pinned sleep bridge' if narrow_sleep else None,
            item_api=dict(missing_types=row['missing_types'],member_counts=row['counts'],override_counts=row['override_counts'],
                first_member_diagnostics=problems[:5],first_override_diagnostics=overrides[:5]),
            additional_assembly_references=other_assemblies,
            reason=('Use only the separately verified original-DLL sleep bridge; common item API lacks time/config contracts.'
                if narrow_sleep else 'Unsupported or unresolved item API contracts; additional runtime assemblies and hooks require individual audit.'),
            compatibility_verified=False))
    return dict(format='terraria-mobile-compatibility-report-v1',assembly_executed=False,
        source_reports=['unified-small-mod-load-plan.json','small-mod-signatures.json','small-mod-time-signatures.json'],
        item_shim_sha256=signatures['shim_sha256'],time_shim_sha256=time_signatures['shim_sha256'],
        dependency_order=plan['order'],candidates=results,
        limitations=['Report describes preflight decisions; no general Android importer consumes it yet.',
            'A valid dependency graph or exact signature does not prove runtime compatibility.',
            'Loader build versions are reported, not declared interchangeable; MethodSpec constraints and external runtime versions are unresolved.',
            'Required and weak declarations come from Info; assembly references are a separate list.',
            'Detailed unresolved signature cases are retained in the source reports.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reports',type=Path,default=Path('reports'))
    args = parser.parse_args()
    read = lambda name: json.loads((args.reports/name).read_text(encoding='utf-8-sig'))
    report = join(read('unified-small-mod-load-plan.json'),read('small-mod-signatures.json'),read('small-mod-time-signatures.json'))
    (args.reports/'small-mod-compatibility.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(candidates=len(report['candidates']),general_launch_allowed=0,
        narrow_routes=[r['name'] for r in report['candidates'] if r['audited_route']])))


if __name__=='__main__':
    main()
