#!/usr/bin/env python3
"""Bounded app-state sweep. Reports raw counts, never contents or filenames.

The caller supplies a private fixture HOME and the app process id. System
logs are restricted to that process and the app subsystem. Missing stores
are counted separately; unreadable stores and log query failures fail closed.
"""
import argparse
import base64
import json
import os
import pathlib
import stat
import subprocess
import sys
import urllib.parse

STORES = ('Library/Preferences', 'Library/Caches', 'Library/Saved Application State',
          'Library/Logs', 'Library/Logs/DiagnosticReports', 'tmp', 'cache', 'state')
LIMIT = 128 * 1024 * 1024


def forms(value):
    text = value.decode('utf-8')
    return set([value, base64.b64encode(value), base64.urlsafe_b64encode(value),
                base64.b64encode(value).rstrip(b'='), base64.urlsafe_b64encode(value).rstrip(b'='),
                value.hex().encode(), value.hex().upper().encode(),
                urllib.parse.quote_from_bytes(value, safe='').encode(),
                ''.join('%%%02X' % x for x in value).encode(),
                ''.join('%%%02x' % x for x in value).encode(),
                json.dumps(text, ensure_ascii=True)[1:-1].encode(),
                ''.join('\\u%04x' % x for x in value).encode(),
                text.encode('utf-16-le'), text.encode('utf-16-be')])


def count(data, needles):
    return sum(data.count(needle) for needle in needles)


def scan(home, needles):
    hits = files = size = missing = 0
    seen = set()
    for store in STORES:
        root = home / store
        if any((home / pathlib.Path(*pathlib.Path(store).parts[:i])).is_symlink() for i in range(1, len(pathlib.Path(store).parts) + 1)):
            raise ValueError('linked store')
        if not root.exists():
            missing += 1
            continue
        def onerror(_):
            raise ValueError('unreadable store')
        for directory, dirs, names, directory_fd in os.fwalk(root, follow_symlinks=False, onerror=onerror):
            for name in dirs + names:
                path = pathlib.Path(directory) / name
                meta = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISLNK(meta.st_mode):
                    raise ValueError('linked store')
                if not stat.S_ISREG(meta.st_mode):
                    if stat.S_ISDIR(meta.st_mode):
                        continue
                    raise ValueError('nonregular store')
                identity = (meta.st_dev, meta.st_ino)
                if identity in seen:
                    continue
                seen.add(identity)
                size += meta.st_size
                if size > LIMIT:
                    raise ValueError('scan limit')
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
                with os.fdopen(fd, 'rb') as source:
                    opened = os.fstat(source.fileno())
                    if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (meta.st_dev, meta.st_ino, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns):
                        raise ValueError('store changed during open')
                    data = source.read(LIMIT + 1)
                    after = os.fstat(source.fileno())
                    if (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns):
                        raise ValueError('store changed during scan')
                if len(data) != meta.st_size:
                    raise ValueError('store changed during scan')
                files += 1
                hits += count(data, needles)
    return dict(file_hits=hits, files=files, bytes=size, absent_stores=missing)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--home', required=True, type=pathlib.Path)
    parser.add_argument('--pid', required=True, type=int)
    args = parser.parse_args()
    value = sys.stdin.buffer.read(65_537)
    try:
        if args.home.parent != pathlib.Path('/tmp') or not args.home.name.startswith('ec05-') or args.home.is_symlink():
            raise ValueError('fixture home required')
        meta = args.home.stat()
        if meta.st_uid != os.getuid() or meta.st_mode & 0o077 or not 16 <= len(value) <= 65_536 or args.pid <= 0:
            raise ValueError('invalid sweep input')
        needles = forms(value)
        # Every encoding is independently planted and must be detected.
        controls = sum(count(b'prefix:' + n + b':suffix', needles) > 0 for n in needles)
        if controls != len(needles):
            raise ValueError('positive control missed')
        result = scan(args.home, needles)
        logs = subprocess.run(['/usr/bin/log', 'show', '--last', '10m', '--style', 'json', '--info', '--debug',
                               '--predicate', 'subsystem == "ai.envcloak.app" AND processIdentifier == %d' % args.pid],
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              env={'PATH': '/usr/bin:/bin', 'HOME': str(args.home)}, timeout=60)
        if logs.returncode or len(logs.stdout) > LIMIT:
            raise ValueError('log query incomplete')
        # Valid JSON confirms log show did not return an incomplete text error.
        json.loads(logs.stdout)
        result.update(log_hits=count(logs.stdout, needles), positive_controls=controls, complete=True)
        print(json.dumps(result, sort_keys=True))
        return int(result['file_hits'] + result['log_hits'] != 0)
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        print(json.dumps(dict(complete=False, reason='sweep_incomplete')))
        return 2


if __name__ == '__main__':
    sys.exit(main())
