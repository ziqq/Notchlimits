#!/usr/bin/env python3
"""Verify the appcast/archive with Sparkle and reject same-size tampered copies.

Read the signing key from standard input; never log or persist it.
"""
import argparse
from pathlib import Path
import subprocess
import sys
import tempfile
from urllib.parse import unquote, urlparse
import xml.etree.ElementTree as ET

SPARKLE = '{http://www.andymatuschak.org/xml-namespaces/sparkle}'


def verify_feed(appcast, tool, key):
    def verify(path, signature=None, valid=True):
        args = [str(tool), '--ed-key-file', '-', '--verify', str(path)]
        if signature is not None:
            args.append(signature)
        result = subprocess.run(args, input=key, capture_output=True)
        if (result.returncode == 0) != valid:
            raise ValueError(f'Unexpected signature result for {path.name}; tool output omitted')

    verify(appcast)
    enclosures = ET.parse(appcast).findall('./channel/item/enclosure')
    if len(enclosures) != 1:
        raise ValueError('Expected one full DMG update')
    enclosure = enclosures[0]
    url = urlparse(enclosure.attrib['url'])
    name = unquote(url.path.rsplit('/', 1)[-1])
    if url.scheme != 'https' or Path(name).name != name or not name.endswith('.dmg'):
        raise ValueError('Expected an HTTPS DMG enclosure')
    archive = appcast.parent / name
    if archive.stat().st_size != int(enclosure.attrib['length']):
        raise ValueError('Archive length does not match appcast')
    signature = enclosure.attrib[SPARKLE + 'edSignature']
    verify(archive, signature)

    with tempfile.TemporaryDirectory(prefix='notchlimits-tampered-updates-') as folder:
        damaged_feed = Path(folder) / 'appcast.xml'
        feed = appcast.read_bytes()
        original = b'<title>Notchlimits</title>'
        if original not in feed:
            raise ValueError('Expected Notchlimits feed title')
        damaged_feed.write_bytes(feed.replace(original, b'<title>notchlimits</title>', 1))
        verify(damaged_feed, valid=False)

        damaged_archive = Path(folder) / name
        data = bytearray(archive.read_bytes())
        data[-1] ^= 1
        damaged_archive.write_bytes(data)
        verify(damaged_archive, signature, valid=False)
    print('Appcast and DMG signatures verified; tampered feed and DMG rejected')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('appcast', type=Path)
    parser.add_argument('--tool', type=Path,
                        default=Path('.build/artifacts/sparkle/Sparkle/bin/sign_update'))
    args = parser.parse_args()
    key = sys.stdin.buffer.read().strip()
    if not key:
        parser.error('Signing key required on standard input')
    verify_feed(args.appcast, args.tool.resolve(), key)
