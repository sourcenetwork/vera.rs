"""Select bounded hosted workloads before installing dependencies or building."""

import json
import os

FLAGS = (
    'ARCHIVE_RETENTION', 'SUSTAINED_FIXED_STATE', 'SUSTAINED_GROWING_STATE',
    'SUSTAINED_MEMORY_ATTRIBUTION', 'ALLOCATOR_COMPARISON', 'STORAGE_ATTRIBUTION',
    'EXTENDED_FIXED_STATE',
)


def selection(environment):
    flags = {}
    for name in FLAGS:
        value = environment.get(name, '')
        if value not in ('', 'true', 'false'):
            raise ValueError('invalid workload flag: ' + name)
        flags[name] = value == 'true'
    archive = flags['ARCHIVE_RETENTION']
    comparison = flags['ALLOCATOR_COMPARISON']
    extended = flags['EXTENDED_FIXED_STATE']
    fixed = flags['SUSTAINED_FIXED_STATE'] or comparison or extended
    growing = flags['SUSTAINED_GROWING_STATE']
    storage = flags['STORAGE_ATTRIBUTION']
    memory = flags['SUSTAINED_MEMORY_ATTRIBUTION'] or archive or comparison or extended
    if archive and (fixed or growing or storage):
        raise ValueError('archive retention requires its own bounded workload')
    if fixed and growing:
        raise ValueError('fixed and growing workloads are mutually exclusive')
    if (fixed or growing) and storage:
        raise ValueError('sustained workloads cannot combine with storage attribution')
    if memory and not (fixed or growing or archive):
        raise ValueError('memory attribution requires a sustained workload or archive retention')
    if extended and comparison:
        raise ValueError('extended fixed state selects one allocator case')
    return {
        'count': 360000 if extended else 90000 if fixed or growing else 6000 if archive else 3000,
        'objects': [128] if fixed or archive else [0] if growing else [0, 128],
        'arenas': ['2'] if extended else ['default', '2'] if comparison else ['default'],
        'controlled_arenas': comparison or extended,
        'timeout_seconds': 10800 if extended else 7200 if fixed or growing else 900,
        'memory': memory,
        'archive': archive,
    }


if __name__ == '__main__':
    try:
        print(json.dumps(selection(os.environ)))
    except ValueError as error:
        raise SystemExit(str(error)) from None
