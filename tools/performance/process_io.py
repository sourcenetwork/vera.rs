"""Summarize kernel process I/O accounting over explicit observed sample intervals."""
import json
import math

FIELDS = ('read_bytes', 'write_bytes', 'cancelled_write_bytes')
STATES = ('complete', 'partial', 'unsupported', 'invalid_data', 'read_error', 'timed_out')


def summarize_io(path):
    members = None
    source = 'unavailable'
    with path.open() as stream:
        for line in stream:
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get('kind') == 'resource_configuration':
                if members is not None:
                    raise ValueError('duplicate process I/O configuration')
                source = row.get('process_io_source', 'unavailable')
                pids = row['node_pids']
                if (not isinstance(pids, list) or not pids
                        or any(type(pid) is not int or not 0 < pid <= (1 << 32) - 1 for pid in pids)
                        or len(set(pids)) != len(pids)):
                    raise ValueError('invalid process I/O member selection')
                members = {pid: {'samples': 0, 'unavailable_samples': 0, 'missing_samples': 0,
                                 'first': None, 'last': None} for pid in pids}
            elif row.get('kind') == 'resources' and source == 'linux_proc_io':
                elapsed = row['elapsed_seconds']
                if type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed < 0:
                    raise ValueError('invalid process I/O sample timestamp')
                seen = set()
                for sample in row['sample'].get('process_io', []):
                    pid = sample['pid']
                    if type(pid) is not int or pid not in members or pid in seen:
                        raise ValueError('unknown or duplicate process I/O member')
                    seen.add(pid)
                    state = sample['availability']
                    if state not in STATES:
                        raise ValueError('invalid process I/O availability')
                    member = members[pid]
                    if state != 'complete':
                        member['unavailable_samples'] += 1
                        continue
                    values = tuple(sample.get(field) for field in FIELDS)
                    if any(type(value) is not int or not 0 <= value <= (1 << 64) - 1 for value in values):
                        raise ValueError('invalid process I/O counter')
                    previous = member['last']
                    if previous is not None and (elapsed < previous[0]
                            or any(a < b for a, b in zip(values, previous[1]))):
                        raise ValueError('process I/O accounting regressed')
                    member['samples'] += 1
                    point = (elapsed, values)
                    if member['first'] is None:
                        member['first'] = point
                    member['last'] = point
                for pid in members.keys() - seen:
                    members[pid]['missing_samples'] += 1
    result = []
    if source == 'linux_proc_io' and members is not None:
        for pid, member in members.items():
            first, last = member.pop('first'), member.pop('last')
            window = None
            if member['samples'] >= 2 and last[0] > first[0]:
                window = {'start_elapsed_seconds': first[0], 'end_elapsed_seconds': last[0],
                          'duration_seconds': last[0] - first[0],
                          **{field + '_delta': end - start for field, start, end in zip(FIELDS, first[1], last[1])}}
            result.append({'pid': pid, **member, 'observed_window': window})
    return {'source': source, 'members': result,
            'scope': 'Non-atomic kernel process counters over observed sample intervals. Writes are charged at page dirtying; cancellations remain separate. Not physical-device write amplification or fsync latency.'}
