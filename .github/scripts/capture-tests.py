#!/usr/bin/env python3
"""Preserve a test command's exit status while keeping its output private."""
import argparse
import os
from pathlib import Path
import subprocess
import stat


def capture(logs, command):
    logs.mkdir(parents=True, mode=0o700, exist_ok=True)
    flags = (os.O_WRONLY | os.O_CREAT | os.O_TRUNC |
             getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    descriptor = os.open(logs / 'test-output.log', flags, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError('test output must be a regular file')
        os.fchmod(stream.fileno(), 0o600)
        result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT)
    code = result.returncode if result.returncode >= 0 else 128 - result.returncode
    (logs / 'test-exit-code').write_text(str(code) + '\n')
    return code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--logs', required=True, type=Path)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not args.command:
        parser.error('a test command is required')
    raise SystemExit(capture(args.logs, args.command))


if __name__ == '__main__':
    main()
