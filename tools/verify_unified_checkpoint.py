"""Check captured unified ModItem regression evidence; never accesses a device.

Screenshots require a separate human/agent review manifest bound to their hashes.
Logs establish execution/save ordering, not visual correctness or general support.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

EVENT = re.compile(r'^(\d\d-\d\d \d\d:\d\d:\d\d\.\d{3})\s+(\d+)\s+\d+\s+\w\s+TMAL\s*:\s*(.*)$')
COMMIT = re.compile(r'^SIDECAR_COMMITTED generation=(\d+) key=PcModItemDemo/TestBlade slot=0 serialized=90 customSerialized=0 enabled=(true|false)$')
RESTORE = re.compile(r'^SIDECAR_RESTORED generation=(\d+) key=PcModItemDemo/TestBlade id=6196 damage=37$')
VISUALS = {'resume-tooltip': 'tooltip37', 'restart-tooltip': 'tooltip37',
           'off-tooltip': 'tooltip5', 'on-tooltip': 'tooltip37', 'final-save': 'main-menu'}
ERRORS = ('observer.error', 'SIDECAR_SAVE_REJECTED', 'SIDECAR_COMMIT_FAILED',
          'SIDECAR_LOAD_REJECTED', 'MODITEM_RESTORE_FAILED', 'CONTENT_FAILED',
          'MANAGED_FAILED', 'HOOK_FAILED')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def parse_events(text):
    return [{'time': m[1], 'pid': int(m[2]), 'message': m[3]}
            for line in text.splitlines() if (m := EVENT.match(line))]


def validate_events(first, final):
    require(first and final, 'Missing own runtime events')
    for rows in (first, final):
        require(len({r['pid'] for r in rows}) == 1, 'Mixed process evidence')
        for marker in ('UNIFIED_API_READY managed-foundation-v1', 'HOOK_READY', 'SIDECAR_READY'):
            require(any(marker in r['message'] for r in rows), 'Missing runtime readiness: ' + marker)
        require(not any(marker in r['message'] for r in rows for marker in ERRORS), 'Loader error in checkpoint')
    require(first[0]['pid'] != final[0]['pid'], 'Full process restart absent')
    require(first[-1]['time'] < final[0]['time'], 'Unsupported cross-day or unordered checkpoint')
    require(any(r['message'] == 'MODITEM_ACTUAL_USE id=6196 damage=37' for r in first), 'Actual item use absent')
    require(any(r['message'] == 'MODITEM_WEAPON_DAMAGE input=37 actual=37 usingItem=true' for r in first),
            'Native weapon damage during use absent')

    def commits(rows):
        found = []
        for row in rows:
            if not row['message'].startswith('SIDECAR_COMMITTED '):
                continue
            match = COMMIT.fullmatch(row['message'])
            require(match is not None, 'Unexpected serialization or content identity')
            found.append(dict(row, generation=int(match[1]), enabled=match[2] == 'true'))
        return found

    before, after = commits(first), commits(final)
    require(before and after, 'Missing save commits')
    require(before[-1]['enabled'] and after[-1]['enabled'], 'Initial/final save must be enabled')
    all_commits = before + after
    require(all(b['generation'] == a['generation'] + 1 and a['time'] < b['time']
                for a, b in zip(all_commits, all_commits[1:])), 'Missing, repeated or unordered save generation')
    restores = []
    for row in final:
        if row['message'].startswith('SIDECAR_RESTORED '):
            match = RESTORE.fullmatch(row['message'])
            require(match is not None, 'Unexpected restored content')
            restores.append(dict(row, generation=int(match[1])))
    resumed = next((r for r in restores if r['generation'] == before[-1]['generation']), None)
    require(resumed is not None, 'Saved generation not automatically restored in new PID')
    disabled = [c for c in after if not c['enabled']]
    require(disabled, 'No disabled save observed')
    off = disabled[-1]
    require(resumed['time'] < disabled[0]['time'], 'Disabled save precedes restart restoration')
    require(any(r['message'] == f"SIDECAR_LOAD_VALID generation={off['generation']} key=PcModItemDemo/TestBlade known=true"
                and off['time'] < r['time'] for r in final), 'Disabled data not reloaded')
    require(any(r['generation'] == off['generation'] and off['time'] < r['time'] < after[-1]['time']
                for r in restores), 'Disabled data not restored before final enabled save')
    toggles = [r for r in final if r['message'] in ('Managed demo enabled=false', 'Managed demo enabled=true')]
    require(any(r['message'].endswith('false') and resumed['time'] < r['time'] < disabled[0]['time'] for r in toggles),
            'Disable transition absent')
    require(any(r['message'].endswith('true') and off['time'] < r['time'] < after[-1]['time'] for r in toggles),
            'Re-enable transition absent')
    return {'process_restart': {'before': first[0]['pid'], 'after': final[0]['pid']},
            'commits': all_commits, 'automatic_restores': restores,
            'custom_id_serialized_in_observed_player_saves': False}


def reviewed_visuals(root, review):
    require(isinstance(review.get('reviewer'), str) and bool(review['reviewer'].strip()), 'Missing visual reviewer')
    result = []
    for label, observed in VISUALS.items():
        data = (root / label / 'screenshot.png').read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        row = review.get('screenshots', {}).get(label, {})
        require(data.startswith(b'\x89PNG\r\n\x1a\n') and row.get('sha256') == digest,
                'Missing or changed reviewed screenshot: ' + label)
        require(row.get('observed') == observed, 'Visual outcome not reviewed: ' + label)
        result.append({'label': label, 'sha256': digest, 'observed': observed})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence-root', type=Path, required=True)
    parser.add_argument('--visual-review', type=Path, required=True)
    parser.add_argument('--apk', type=Path, required=True, help='Pulled installed companion APK')
    parser.add_argument('--build-report', type=Path, required=True)
    parser.add_argument('--date', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    build = json.loads(args.build_report.read_text('utf-8-sig'))
    digest = hashlib.sha256(args.apk.read_bytes()).hexdigest()
    require(build.get('variant') == 'unified-moditem-demo' and build.get('api_revision') == 'managed-foundation-v1',
            'Wrong companion variant')
    require(digest == build['output_sha256'], 'Installed companion differs from build')
    read = lambda label: parse_events((args.evidence_root / label / 'logcat.txt').read_text('utf-8'))
    checks = validate_events(read('resume-first-save'), read('final-save'))
    visuals = reviewed_visuals(args.evidence_root, json.loads(args.visual_review.read_text('utf-8')))
    report = {'status': 'verified-unified-single-item-restart-and-disable-cycle', 'date_local': args.date,
              'device': 'Android ARM64 target Android14 native ARM64 no root', 'companion_sha256': digest,
              'installed_companion_apk_hash_matched': True, 'api_revision': build['api_revision'],
              'profile': 'TMAL_Test', 'world': 'TMAL_Lab', 'key': 'PcModItemDemo/TestBlade',
              **checks, 'visual_evidence': visuals, 'evidence_root': str(args.evidence_root),
              'visual_review_is_manual_not_ocr': True,
              'issuance_observation': 'Session operator used no issuance command in this regression.',
              'limitations': ['One fixed item in main test inventory only.',
                             'Player and JSON sidecar are not one atomic transaction; backup recovery absent.',
                             'Private sidecar export not implemented; Players/Worlds backup does not include it.',
                             'No general tmod importer, Calamity/Thorium support or time/item API unification.',
                             'Observed attacks are not a controlled NPC damage conformance test.'],
              'github_upload': False}
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': report['status'], 'commits': len(checks['commits']),
                      'final_generation': checks['commits'][-1]['generation']}))


if __name__ == '__main__':
    main()
