"""Small synthetic checks for malformed, interrupted and interleaved trace records."""
import argparse
import hashlib
import json
from pathlib import Path
from review_terraria_action_trace import inspect


class MemoryTrace:
    def __init__(self, text):
        self.text = text

    def read_bytes(self):
        return self.text.encode('ascii')

    def __str__(self):
        return '<synthetic trace>'


header = 'TRACEv1\tpid=1\tclock=steady_ns\tmax_events=500000\tmax_bytes=67108864\n'
suffix = '\tkind=command\tname=perform\tgroup=protocol\tfunction=f\tentry=0x1\texception_active=0\n'
begin = 'BEGIN\tseq=1\tparent=0\tdepth=0\ttime_ns=10\telapsed_ns=0' + suffix
end = 'END\tseq=1\tparent=0\tdepth=0\ttime_ns=11\telapsed_ns=1' + suffix
good = header + begin + end
assert inspect(MemoryTrace(good))['all_observed_scopes_closed']
bad = {
    'malformed_header': good.replace(header, 'TRACEv1\tgarbage\n'),
    'duplicate_header_field': good.replace('pid=1\t', 'pid=1\tpid=2\t'),
    'duplicate_event_field': good.replace('name=perform', 'name=perform\tname=x', 1),
    'end_before_own_begin': header + begin + end.replace('time_ns=11', 'time_ns=9').replace('elapsed_ns=1', 'elapsed_ns=-1'),
    'negative_elapsed': header + begin + end.replace('elapsed_ns=1', 'elapsed_ns=-1'),
    'orphan_end': header + end,
    'duplicate_begin': header + begin + begin + end,
    'wrong_parent': good.replace('parent=0', 'parent=9', 1),
    'wrong_depth': good.replace('depth=0', 'depth=1', 1),
    'changed_pair_identity': header + begin + end.replace('function=f', 'function=g'),
    'wrong_elapsed': header + begin + end.replace('elapsed_ns=1', 'elapsed_ns=2'),
}
for name, text in bad.items():
    try:
        inspect(MemoryTrace(text))
    except (AssertionError, ValueError):
        pass
    else:
        raise AssertionError('Invalid trace accepted: ' + name)
assert not inspect(MemoryTrace(header))['all_observed_scopes_closed']
assert len(inspect(MemoryTrace(header + begin))['open_scopes']) == 1
limited = inspect(MemoryTrace(good + 'LIMIT\ttime_ns=12\tevents=2\tbytes=100\n'))
assert not limited['all_observed_scopes_closed'] and limited['limits']
interleaved = header + begin + begin.replace('seq=1', 'seq=2').replace('time_ns=10', 'time_ns=9') + end.replace('seq=1', 'seq=2').replace('time_ns=11', 'time_ns=10') + end
r = inspect(MemoryTrace(interleaved))
assert r['all_observed_scopes_closed'] and r['nonmonotonic_observed_timestamps'] == 1
parser = argparse.ArgumentParser()
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
assert not args.output.exists()
report = dict(negative_controls_rejected=list(bad), negative_control_count=len(bad),
              empty_interrupted_and_LIMIT_are_incomplete=True,
              interleaved_global_timestamps_accepted_with_valid_pairs=True,
              inspector_sha256=r['inspector_sha256'],
              selftest_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
args.output.write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report))
