"""Summarize sampled resident memory and CPU time over observed intervals."""
from bisect import bisect_left
import json
import math
import re


CPU_TIME = re.compile(
    r'(?:(\d{1,7})-)?(?:(\d{1,7}):)?(\d{1,7}):([0-5]\d(?:\.\d{1,6})?)'
)


def cpu_seconds(value):
    match = CPU_TIME.fullmatch(value)
    if match is None:
        raise ValueError('invalid process CPU time')
    days, hours, minutes, seconds = match.groups()
    if ((days is not None and (hours is None or int(hours) >= 24))
            or (hours is not None and int(minutes) >= 60)):
        raise ValueError('invalid process CPU time')
    return int(days or 0) * 86400 + int(hours or 0) * 3600 + int(minutes) * 60 + float(seconds)


def summarize_resources(path, late_window_seconds=600):
    if type(late_window_seconds) not in (int, float) or not math.isfinite(late_window_seconds) or late_window_seconds <= 0:
        raise ValueError('invalid memory observation window')
    members = None
    previous = None
    with path.open() as stream:
        for line in stream:
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError('resource records must be JSON objects')
            if row.get('kind') == 'resource_configuration':
                if members is not None:
                    raise ValueError('duplicate resource configuration')
                pids = row['node_pids']
                if (not isinstance(pids, list) or not 1 <= len(pids) <= 16
                        or any(type(pid) is not int or not 0 < pid <= 0xffffffff for pid in pids)
                        or len(set(pids)) != len(pids)):
                    raise ValueError('invalid resource member selection')
                members = {pid: {'points': [], 'missing_samples': 0} for pid in pids}
            elif row.get('kind') == 'resources':
                if members is None:
                    raise ValueError('resource samples precede configuration')
                elapsed = row['elapsed_seconds']
                if (type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed < 0
                        or (previous is not None and elapsed <= previous)):
                    raise ValueError('resource timestamps must increase')
                previous = elapsed
                sample = row['sample']
                if not isinstance(sample, dict) or not isinstance(sample.get('rows', ''), str):
                    raise ValueError('invalid process resource sample')
                seen = set()
                for raw in sample.get('rows', '').splitlines():
                    fields = raw.split()
                    if len(fields) != 3 or not all(re.fullmatch(r'\d{1,20}', value) for value in fields[:2]):
                        raise ValueError('invalid process resource row')
                    pid, rss = map(int, fields[:2])
                    if pid not in members or pid in seen or rss > (1 << 64) - 1:
                        raise ValueError('invalid process resource member')
                    cpu = cpu_seconds(fields[2])
                    points = members[pid]['points']
                    if points and cpu < points[-1][2]:
                        raise ValueError('process CPU counter regressed')
                    points.append((elapsed, rss / 1024, cpu))
                    seen.add(pid)
                for pid in members.keys() - seen:
                    members[pid]['missing_samples'] += 1
    summaries = []
    for index, member in enumerate((members or {}).values()):
        points = member['points']
        usage = dict(member=index, samples=len(points), missing_samples=member['missing_samples'],
                     rss_mib=None, observed_window=None, late_rss_growth=None)
        if points:
            first, last = points[0], points[-1]
            usage['rss_mib'] = dict(first=first[1], last=last[1], peak=max(point[1] for point in points))
            if len(points) >= 2:
                duration = last[0] - first[0]
                usage['observed_window'] = dict(start_elapsed_seconds=first[0], end_elapsed_seconds=last[0],
                                                duration_seconds=duration, cpu_seconds=last[2] - first[2],
                                                average_cpu_cores=(last[2] - first[2]) / duration)
                if duration >= late_window_seconds:
                    start = bisect_left([point[0] for point in points], last[0] - late_window_seconds)
                    if start < len(points) - 1:
                        usage['late_rss_growth'] = dict(requested_window_seconds=late_window_seconds,
                            start_elapsed_seconds=points[start][0], end_elapsed_seconds=last[0],
                            observed_seconds=last[0] - points[start][0], delta_mib=last[1] - points[start][1])
        summaries.append(usage)
    return {'source': 'ps_rss_and_cpu_time' if members is not None else 'unavailable',
            'members': summaries,
            'scope': 'RSS and cumulative CPU time come from ps, excluding startup before the first sample. Linux /proc status counters are separate, non-atomic samples. Missing samples remain explicit. Late-window growth describes observed endpoints, not a steady-state or hard memory bound. CPU cores are process CPU-seconds divided by observed wall-seconds.'}


def markdown_resources(usage):
    lines = ['| Validator | Peak RSS (ps, MiB) | Mean CPU cores | Late-window RSS change (MiB) | Missing samples |',
             '| --- | ---: | ---: | ---: | ---: |']
    for member in usage['members']:
        rss, cpu, growth = member['rss_mib'], member['observed_window'], member['late_rss_growth']
        values = (rss['peak'] if rss else None, cpu['average_cpu_cores'] if cpu else None,
                  growth['delta_mib'] if growth else None)
        formatted = ['unavailable' if value is None else f'{value:.2f}' for value in values]
        lines.append('| %d | %s | %s | %s | %d |' % (member['member'], *formatted, member['missing_samples']))
    return '\n'.join(lines) + '\n\n' + usage['scope'] + '\n'
