"""Summarize own checkpoint events without copying raw game logs or saves."""
import argparse
import hashlib
import json
import re
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence-root', type=Path, required=True)
    parser.add_argument('--apk', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    groups = []
    for label in ('sidecar-first-save', 'sidecar-final-menu'):
        rows = []
        for line in (args.evidence_root / label / 'logcat.txt').read_text(encoding='utf-8').splitlines():
            match = re.search(r'^(.{18})\s+(\d+)\s+\d+\s+I\s+TMAL\s+: (.*)$', line)
            if match:
                rows.append({'time': match[1].strip(), 'pid': int(match[2]), 'message': match[3]})
        require(rows, 'Missing own events: ' + label)
        require(not any(any(marker in row['message'] for marker in (
            'observer.error', 'SIDECAR_SAVE_REJECTED', 'SIDECAR_COMMIT_FAILED',
            'SIDECAR_LOAD_REJECTED', 'MODITEM_RESTORE_FAILED', 'CONTENT_FAILED'
        )) for row in rows), 'Runtime error in selected checkpoint')
        groups.append(rows)
    commits = [r for rows in groups for r in rows if r['message'].startswith('SIDECAR_COMMITTED ')]
    require(len(commits) == 4, 'Expected four commits')
    for generation, row in enumerate(commits, 1):
        enabled = 'true' if generation in (1, 4) else 'false'
        require(row['message'] == f'SIDECAR_COMMITTED generation={generation} key=PcModItemDemo/TestBlade slot=0 serialized=90 customSerialized=0 enabled={enabled}',
                'Unexpected commit sequence or serialization')
    restores = [r for r in groups[1] if r['message'].startswith('SIDECAR_RESTORED ')]
    require(len(restores) == 2, 'Expected two automatic restores')
    for generation, row in zip((1, 3), restores):
        require(row['message'] == f'SIDECAR_RESTORED generation={generation} key=PcModItemDemo/TestBlade id=6196 damage=37', 'Unexpected restored item')
    require(commits[0]['pid'] != commits[1]['pid'], 'Full process restart not observed')
    require(restores[0]['time'] < commits[1]['time'] < commits[2]['time'] < restores[1]['time'] < commits[3]['time'], 'Unexpected disable/save/re-enable sequence')
    visuals = [
        {'label': 'sidecar-issued-tooltip', 'damage': 37},
        {'label': 'sidecar-reloaded-full', 'damage': 37},
        {'label': 'sidecar-off-full', 'damage': 5},
        {'label': 'sidecar-reenabled-tooltip', 'damage': 37},
        {'label': 'sidecar-final-menu', 'screen': 'main menu'}
    ]
    for row in visuals:
        require((args.evidence_root / row['label'] / 'screenshot.png').read_bytes().startswith(b'\x89PNG\r\n\x1a\n'), 'Missing screenshot')
        row['review'] = 'Agent visual review recorded in session; not an OCR assertion'
    report = {
        'status': 'verified-single-lab-item-sidecar-restart-and-disable-cycle',
        'date_local': '2026-10-09', 'device': 'Android ARM64 target / Android 14 / native ARM64 / no root',
        'companion_sha256': hashlib.sha256(args.apk.read_bytes()).hexdigest(),
        'profile': 'TMAL_Test', 'world': 'TMAL_Lab', 'key': 'PcModItemDemo/TestBlade',
        'runtime_id': 6196, 'placeholder_id': 3507,
        'process_restart': {'before': commits[0]['pid'], 'after': commits[1]['pid']},
        'commits': commits, 'automatic_restores': restores, 'visual_evidence': visuals,
        'issuance_command_repeated_after_restart': False,
        'issuance_observation': 'Agent did not press either issuance button after first save; bootstrap clears own command file.',
        'custom_id_serialized_in_observed_player_saves': False,
        'general_pc_mod_support': False,
        'limitations': [
            'One fixed own item in the main test inventory; no general item/world saves.',
            'Player file and sidecar are not one atomic transaction; mismatch rejects application and retains sidecar.',
            'Write interruption and backup recovery were not fault-injection tested.',
            'Unknown key retention checked by host policy tests only, not an Android missing-mod scenario.',
            'Private sidecar is outside Players/Worlds backup; no private export yet.',
            'No new combat test or showcase video for this sidecar build.'
        ]
    }
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': report['status'], 'commits': len(commits), 'restores': len(restores)}))


if __name__ == '__main__':
    main()
