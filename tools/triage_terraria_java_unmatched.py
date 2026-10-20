"""Source-only unknown triage. Candidate improvements never alter prior mappings."""
import argparse
import collections
import json
import re
import shutil
from pathlib import Path
from reconcile_terraria_java_spans import Resolver, erase, original_name, read_jsonl, sha, need, validate_file


def ranking(counter):
    return [dict(key=k, count=v) for k, v in counter.most_common()]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--lab', type=Path, required=True)
    args = ap.parse_args()
    prior = args.lab / 'java-method-source-mapping-20261019'
    out = args.lab / 'java-method-unmatched-triage-20261019'
    need(not out.exists(), 'Fresh triage output required')
    rows = read_jsonl(prior / 'reconciled/methods.jsonl')
    files = read_jsonl(prior / 'source-ast.jsonl')
    classrows = read_jsonl(args.lab / 'android-java-method-ledger-20261019/classes.jsonl')
    resolver = Resolver(rows, classrows, files)
    encoded = {f['path']: validate_file(f, args.lab / 'jadx/sources') for f in files}
    byowner = collections.defaultdict(list)
    byname = collections.defaultdict(list)
    aliases = collections.defaultdict(set)
    source_method_reasons = collections.Counter()
    method_records = []
    for f in files:
        mapping = resolver.class_maps[f['path']]
        for c in f['classes']:
            owner = mapping.get(c['owner'])
            if owner:
                byowner[owner].append((f, c))
                aliases[(f['package']+'.' if f['package'] else '') + c['owner'].replace('$', '.')].add(owner)
                aliases[(f['package']+'.' if f['package'] else '') + c['owner']].add(owner)
        for m in f['methods']:
            owner = mapping.get(m['owner'])
            name = '<init>' if m['constructor'] else original_name(m['leading_trivia']) or m['name']
            args = [resolver.type(p['type'], f, m) for p in m['parameters']]
            ret = resolver.type(m['return_type'], f, m)
            failure = []
            for label, text, resolved in [('return', m['return_type'], ret)] + [('parameter_'+str(i), p['type'], value) for i,(p,value) in enumerate(zip(m['parameters'], args))]:
                if resolved is not None:
                    continue
                raw = erase(text)
                base = raw.removesuffix('[]') if raw else None
                if base in m['type_variables']:
                    why = 'generic_variable_bounds_not_emitted'
                elif raw is None:
                    why = 'unsupported_type_text_or_wildcard_bound_inside_generic'
                elif aliases.get(base):
                    why = 'fully_qualified_renamed_source_type_alias'
                else:
                    why = 'unresolved_or_ambiguous_type'
                failure.append(dict(position=label, text=text, reason=why))
                source_method_reasons[why] += 1
            record = dict(path=f['path'], source_sha256=f['sha256'], source_owner=m['owner'],
                          resolved_owner=owner, name=name, source_name=m['name'],
                          declaration_start=m['start'], declaration_end=m['end'],
                          body_start=m['body_start'], body_end=m['body_end'],
                          local_context=m['local_context'], parse_errors=f['parse_errors'],
                          resolved_parameters=args, resolved_return=ret, type_failures=failure,
                          type_variables=m['type_variables'], exact_source_method_signature_verified=False,
                          mapping_promoted=False)
            method_records.append((f,m,record))
            if owner:
                byname[owner,name].append(record)
    unknowns = []
    categories = collections.Counter()
    parse_nonoverlap = []
    for row in rows:
        if not row['code_offset'] or row['exact_syntactic_source_association']:
            continue
        owner = row['declaring_class']
        named = byname[owner,row['method_name']]
        owners = byowner[owner]
        resolved = [x for x in named if None not in x['resolved_parameters'] and x['resolved_return'] is not None]
        exact_excluded = [x for x in resolved if owner+'->'+x['name']+'('+''.join(x['resolved_parameters'])+')'+x['resolved_return'] == row['descriptor']]
        if row['method_name'] == '<clinit>':
            category = 'static_initializer_transformation'
        elif exact_excluded and any(x['parse_errors'] for x in exact_excluded):
            category = 'exact_signature_in_parse_error_file_excluded'
        elif not owners:
            category = 'no_resolved_source_owner_anonymous_or_local' if re.search(r'\$\d+(?:[;$])', owner) else 'no_resolved_source_owner_named'
        elif named and any(x['type_failures'] for x in named):
            category = 'same_owner_and_name_type_resolution_unknown'
        elif named:
            category = 'same_owner_and_name_different_descriptor'
        elif row['access_flags'] & 0x1000:
            category = 'synthetic_bridge_no_source_declaration' if row['access_flags'] & 0x40 else 'synthetic_no_source_declaration'
        elif row['method_name'] == '<init>':
            category = 'constructor_without_explicit_source_declaration'
        else:
            category = 'named_method_without_source_declaration_unresolved'
        categories[category] += 1
        item = dict(method_id=row['method_id'], descriptor=row['descriptor'], owner=owner,
                    package=owner[1:-1].rpartition('/')[0].replace('/', '.'), category=category,
                    access_flags=row['access_flags'], dex_synthetic=bool(row['access_flags']&0x1000),
                    dex_bridge=bool(row['access_flags']&0x40), candidate_source_files=row['candidate_source_files'],
                    resolved_source_owner_files=sorted({f['path'] for f,c in owners}),
                    same_owner_name_declarations=named, mapping_promoted=False,
                    semantic_equivalence_verified=False)
        unknowns.append(item)
        for candidate in exact_excluded:
            if not candidate['parse_errors']:
                continue
            f = next(x for x in files if x['path']==candidate['path'])
            a,b = candidate['declaration_start'], candidate['declaration_end']
            errors = [d for d in f['diagnostics'] if d['kind']=='ERROR']
            overlaps = [d for d in errors if not (0 <= d['start'] <= d['end']) or a <= d['start'] <= b or a <= d['end'] <= b or d['start'] <= a and d['end'] >= b]
            if not overlaps and 0 <= a < b:
                parse_nonoverlap.append(dict(descriptor=row['descriptor'], candidate=candidate,
                                             reason='signature resolves and diagnostic point ranges do not overlap declaration; recovery tree integrity still unproven', mapping_promoted=False))
    # Experimental alias-only candidates. They are ranked evidence, never promoted.
    alias_candidates=[]
    for f,m,record in method_records:
        if not record['resolved_owner'] or record['parse_errors'] or record['local_context']:
            continue
        if not record['type_failures'] or any(x['reason']!='fully_qualified_renamed_source_type_alias' for x in record['type_failures']):
            continue
        def alias_type(text, old):
            if old is not None:return old
            raw=erase(text); dimensions=0
            while raw and raw.endswith('[]'):
                raw=raw[:-2]; dimensions+=1
            found=aliases.get(raw,set())
            return '['*dimensions+next(iter(found)) if len(found)==1 else None
        params=[alias_type(p['type'],v) for p,v in zip(m['parameters'],record['resolved_parameters'])]
        ret=alias_type(m['return_type'],record['resolved_return'])
        if None in params or ret is None:continue
        desc=record['resolved_owner']+'->'+record['name']+'('+''.join(params)+')'+ret
        if any(x['descriptor']==desc for x in unknowns):
            alias_candidates.append(dict(descriptor=desc,candidate=record,mapping_promoted=False))
    need(len(unknowns)==1464, 'Unknown universe drift')
    out.mkdir()
    sources=out/'producer-sources-v1'; sources.mkdir()
    for name in ['JavaSourceSpanExtractor.java','reconcile_terraria_java_spans.py','verify_terraria_java_spans.py','triage_terraria_java_unmatched.py']:
        shutil.copyfile(Path(__file__).parent/name,sources/name)
    for name, records in [('unknown-code-methods.jsonl',unknowns),('source-method-triage.jsonl',[r for f,m,r in method_records]),('parse-error-nonoverlap-candidates.jsonl',parse_nonoverlap),('source-type-alias-candidates.jsonl',alias_candidates)]:
        with (out/name).open('w',encoding='utf-8') as stream:
            for record in records:stream.write(json.dumps(record)+'\n')
    summary=dict(schema=1, unknown_code_methods=len(unknowns), categories=dict(categories),
                 ranked_packages=ranking(collections.Counter(x['package'] for x in unknowns)),
                 ranked_owners=ranking(collections.Counter(x['owner'] for x in unknowns)),
                 source_type_failure_occurrences=dict(source_method_reasons),
                 exact_signature_parse_error_nonoverlap_candidates=len(parse_nonoverlap),
                 exact_descriptor_source_type_alias_candidates=len(alias_candidates),
                 producer_sources_sha256={p.name:sha(p.read_bytes()) for p in sources.iterdir()},
                 input_ast_sha256=sha((prior/'source-ast.jsonl').read_bytes()),
                 input_mapping_sha256=sha((prior/'reconciled/methods.jsonl').read_bytes()),
                 mapping_promoted=False, semantic_equivalence_verified=False,
                 limitations=['Categories describe bounded source/AST evidence; missing declaration does not prove missing original behavior',
                              'Nonoverlapping parser diagnostics do not prove intact recovery tree',
                              'Generic bounds require a new parser schema before exact resolution',
                              'Anonymous and synthetic transformations require explicit ownership evidence'])
    (out/'summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    print(json.dumps(summary))


if __name__=='__main__':main()
