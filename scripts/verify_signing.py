#!/usr/bin/env python3
"""Reject releases without the pinned a.a.ustinoff certificate identity."""
import argparse
import hashlib
from pathlib import Path
import subprocess
import tempfile


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True)


def verify(app, identity):
    run('codesign', '--verify', '--deep', '--strict', str(app))
    result = run('codesign', '--display', '--requirements', '-', str(app))
    requirements = [line.split('designated =>', 1)[1].strip()
                    for line in (result.stdout + result.stderr).splitlines()
                    if 'designated =>' in line]
    if len(requirements) != 1:
        raise ValueError('Missing designated requirement')
    if 'cdhash' in requirements[0] or 'identifier "dev.ustinoff.notchlimits"' not in requirements[0]:
        raise ValueError('Release must have a stable Notchlimits certificate requirement')
    with tempfile.TemporaryDirectory(prefix='notchlimits-public-certificate-') as folder:
        prefix = str(Path(folder) / 'certificate')
        run('codesign', '--display', '--extract-certificates=' + prefix, str(app))
        if hashlib.sha1(Path(prefix + '0').read_bytes()).hexdigest().upper() != identity.upper():
            raise ValueError('Release was signed by a different identity')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('app', type=Path)
    parser.add_argument('--identity', required=True, help='Expected public certificate SHA1')
    args = parser.parse_args()
    verify(args.app, args.identity)
    print('Notchlimits certificate identity and sealed bundle verified')
