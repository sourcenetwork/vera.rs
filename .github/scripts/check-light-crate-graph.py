#!/usr/bin/env python3
"""Keep the crates light consumers build free of the consensus and runtime stack.

DefraDB's delegation crate and other clients that encode module calls depend on
these crates on every platform a client runs on. Commonware's runtime does not
build for every such platform, so none of them may resolve it.
"""
import subprocess
import sys

LIGHT_CRATES = [
    'vera-modules',
    'vera-crypto',
    'vera-identity',
]

FORBIDDEN = [
    'commonware-runtime',
    'commonware-glue',
    'commonware-consensus',
    'commonware-p2p',
    'commonware-storage',
    'vera-domain',
]


def resolved(crate):
    result = subprocess.run(
        ['cargo', 'tree', '-p', crate, '-e', 'normal', '--locked', '--offline',
         '--target', 'all', '--prefix', 'none'],
        check=True, capture_output=True, text=True, timeout=300)
    return {line.split(' ', 1)[0] for line in result.stdout.splitlines() if line}


def main():
    failures = []
    for crate in LIGHT_CRATES:
        found = sorted(set(FORBIDDEN) & resolved(crate))
        if found:
            failures.append(f'{crate} resolves {", ".join(found)}')
        else:
            print(f'ok: {crate} resolves none of the consensus stack')
    for failure in failures:
        print(f'error: {failure}', file=sys.stderr)
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
