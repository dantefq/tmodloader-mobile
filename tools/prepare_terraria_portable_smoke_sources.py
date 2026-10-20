"""Generate a separately pinned portable-engine C smoke. Never compile or launch it."""
import argparse
import ast
import datetime
import hashlib
import json
from pathlib import Path
import shutil

LONG_SHA = '2a24e626b6f383b9705d8e37a66c1415973fa539b0f3f3fb6774934458bf24c0'
AUDIT_SHA = 'c806c13051b1f68213ca18bdf88de98e8516b65e6fef78d662685811f814d172'
OFFICIAL_ENGINE = '1fd85827247f1ff1417fa412db26a53066d050c59017db98dd23ff196751521e'
PE_INSPECTOR = 'fcecf18468c6c0568eca73c8cd1250f287ca81f7cb26199b69815518e36a78e8'
PROFILE = 'portable-baseline-conditional-untyped-C-smoke-v1'
CLASS = 'TerrariaPortableBaselineCSmoke'
AUDITOR = 'audit_terraria_portable_baseline_c_smoke.py'
HELPERS = ('TerrariaCoarseCopiesProbe.java', 'TerrariaUntypedCProbe.java',
           'TerrariaExtendedNoreturnProbe.java', 'audit_terraria_nullguard_noreturn_model.py')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('Expected unique source anchor: ' + old[:80])
    return text.replace(old, new, 1)


def templates(tools, engine_sha, build_sha, pe_sha):
    producer = tools / 'TerrariaLongBudgetCProbe.java'
    auditor = tools / 'audit_terraria_long_budget_c.py'
    if sha(producer) != LONG_SHA or sha(auditor) != AUDIT_SHA:
        raise ValueError('Frozen LongBudget sources changed')
    identities = (
        ('TerrariaLongBudgetCProbe', CLASS),
        ('audit_terraria_long_budget_c.py', AUDITOR),
        ('pseudocode-long-budget-c-', 'pseudocode-portable-baseline-c-'),
        ('verified-known-islands-conditional-noreturn-long-budget-C-v4-stack32-v1', PROFILE),
    )
    java, audit = producer.read_text(encoding='utf8'), auditor.read_text(encoding='utf8')
    for old, new in identities:
        java, audit = java.replace(old, new), audit.replace(old, new)
    fields = dict(derived_from_long_budget_sha256=LONG_SHA,
                  portable_build_manifest_sha256=build_sha, portable_PE_review_sha256=pe_sha)
    prefix = ''.join('rec.addProperty(' + json.dumps(key) + ',' + json.dumps(value) + ');'
                     for key, value in fields.items()) + 'rec.addProperty("engine_changed",true);'
    changes = [
        ('public class ' + CLASS + ' extends TerrariaCoarseCopiesProbe {',
         'public class ' + CLASS + ' extends TerrariaCoarseCopiesProbe {\n    static final String ENGINE="' + engine_sha + '";'),
        ('boolean smoke=args.length==5&&args[4].equals("c-smoke");',
         'boolean smoke=args.length==5&&args[4].equals("c-smoke");if(!smoke)throw new Exception("Portable baseline restricted to C smoke");'),
        ('rec.addProperty("only_budget_changed",true);',
         'rec.addProperty("only_budget_changed",false);' + prefix),
    ]
    for old, new in changes:
        java = replace_once(java, old, new)
    audit = replace_once(audit, "ENGINE='" + OFFICIAL_ENGINE + "'", "ENGINE='" + engine_sha + "'")
    # The auditor reconstructs the unchanged Untyped->LongBudget template itself,
    # then applies exactly these explicit portable identity/smoke restrictions.
    insert = ''.join('    expected=expected.replace(' + repr(old) + ',' + repr(new) + ')\n'
                     for old, new in changes)
    audit = replace_once(audit, '    assert a.producer.read_text()==expected,',
                         insert + '    assert a.producer.read_text()==expected,')
    audit = replace_once(audit, "r['only_budget_changed'] is True", "r['only_budget_changed'] is False")
    audit = replace_once(audit, 'only_budget_changed=True,baseline_hard_timeout_seconds',
                         'only_budget_changed=False,baseline_hard_timeout_seconds')
    audit = replace_once(audit, "('only_budget_changed',False)", "('only_budget_changed',True)")
    extra = '    assert r["engine_changed"] is True\n'
    extra += ''.join('    assert r[' + repr(key) + ']==' + repr(value) + '\n' for key, value in fields.items())
    audit = replace_once(audit, 'def model_record(r):\n', 'def model_record(r):\n' + extra)
    audit = replace_once(audit, '        model_record(good)\n',
                         '        good.update(' + repr(dict(fields, engine_changed=True)) + ')\n        model_record(good)\n')
    audit = replace_once(audit, '        out=a.lab/a.folder;',
                         '        assert a.address==SMOKE and a.folder==SMOKE_FOLDER\n        out=a.lab/a.folder;')
    # No smoke, including a successful one, may add a game C address.
    audit = replace_once(audit, "eligible_for_new_C_coverage=(not r['c_smoke'] and r['status']=='decompiled_conditional_candidate')",
                         'eligible_for_new_C_coverage=False')
    ast.parse(audit)
    return java, audit, fields


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--preparation', type=Path, required=True)
    parser.add_argument('--pe-review', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    base = args.preparation.resolve()
    build_path = base / 'baseline-build/build-manifest.json'
    build = json.loads(build_path.read_text(encoding='utf-8-sig'))
    preparation_path = base / 'preparation-manifest.json'
    if build['status'] != 'linked_uninspected_unexecuted' or build['preparation_manifest_sha256'] != sha(preparation_path):
        raise ValueError('A completed baseline build with matching preparation is required')
    preparation = json.loads(preparation_path.read_text(encoding='utf-8-sig'))
    compiled = [row['source'] for row in build['compiled']]
    if len(compiled) != 79 or len(set(compiled)) != 79 or compiled != preparation['sources']:
        raise ValueError('Expected all 79 baseline sources compiled in recorded order')
    engine = base / 'baseline-build/decompile.exe'
    pe = json.loads(args.pe_review.read_text(encoding='utf-8-sig'))
    if (sha(engine) != build['engine_sha256'] or pe['sha256'] != sha(engine)
            or pe['header_gates_passed'] is not True or pe['static_gate_failures']
            or pe['inspector_sha256'] != PE_INSPECTOR):
        raise ValueError('Fresh matching portable PE review required')
    tools = Path(__file__).resolve().parent
    java, audit, fields = templates(tools, sha(engine), sha(build_path), sha(args.pe_review))
    if args.output.exists() or args.output.resolve().parent != base.parent:
        raise ValueError('Fresh isolated source folder inside lab required')
    args.output.mkdir()
    (args.output / (CLASS + '.java')).write_text(java, encoding='utf8', newline='\n')
    (args.output / AUDITOR).write_text(audit, encoding='utf8', newline='\n')
    for name in HELPERS:
        shutil.copyfile(tools / name, args.output / name)
    record = dict(schema='portable-baseline-C-smoke-source-preparation-v1',
                  created_UTC=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  generator_sha256=sha(Path(__file__)), engine_sha256=sha(engine), **fields,
                  source_files=[dict(path=p.name, sha256=sha(p)) for p in sorted(args.output.iterdir())],
                  compiled=False, engine_executed=False, dependencies_resolved=False,
                  C_coverage_addition=0,
                  note='Sources only. Isolated Ghidra deployment, runtime dependency review, source audit and actual C smoke remain required.')
    (args.output / 'smoke-source-manifest.json').write_text(json.dumps(record, indent=2) + '\n', encoding='utf8')
    print(json.dumps(record))


if __name__ == '__main__':
    main()
