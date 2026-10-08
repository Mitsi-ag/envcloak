#!/usr/bin/env python3
"""Independent stores and stdlib encoders plant the app sweep's controls."""
import base64
import importlib.util
import json
import os
import pathlib
import tempfile
import unittest
import urllib.parse
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('sweep', pathlib.Path(__file__).resolve().parents[1] / 'sweep.py')
sweep = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sweep)

# The requirement's stores, deliberately not read from the implementation.
STORES = ('Library/Preferences', 'Library/Caches', 'Library/Saved Application State',
          'Library/Logs', 'Library/Logs/DiagnosticReports', 'tmp', 'cache', 'state')


class Sweep(unittest.TestCase):
    def test_each_store_and_encoding_and_clean_control(self):
        value = ('fixture-' + os.urandom(30).hex() + '/猫').encode()
        text = value.decode()
        encodings = [value, base64.b64encode(value), base64.urlsafe_b64encode(value).rstrip(b'='),
                     value.hex().encode(), value.hex().upper().encode(),
                     json.dumps(text, ensure_ascii=True)[1:-1].encode(),
                     urllib.parse.quote_from_bytes(value, safe='').encode(),
                     text.encode('utf-16-le'), text.encode('utf-16-be')]
        for store in STORES:
            for index, encoded in enumerate(encodings):
                with self.subTest(store=store, encoding=index):
                    home = pathlib.Path(tempfile.mkdtemp(prefix='ec05-sweep-', dir='/tmp'))
                    folder = home / store
                    folder.mkdir(parents=True, exist_ok=True)
                    self.assertEqual(sweep.scan(home, sweep.forms(value))['file_hits'], 0)
                    (folder / 'control').write_bytes(encoded)
                    result = sweep.scan(home, sweep.forms(value))
                    self.assertGreater(result['file_hits'], 0)
                    self.assertEqual(result['files'], 1)

    def test_symlink_is_incomplete_not_clean(self):
        home = pathlib.Path(tempfile.mkdtemp(prefix='ec05-sweep-', dir='/tmp'))
        (home / 'cache').mkdir()
        (home / 'cache/link').symlink_to(home / 'absent')
        with self.assertRaises(ValueError):
            sweep.scan(home, {os.urandom(32)})

    def test_linked_store_root_is_incomplete(self):
        home = pathlib.Path(tempfile.mkdtemp(prefix='ec05-sweep-', dir='/tmp'))
        (home / 'owned').mkdir()
        (home / 'Library').symlink_to(home / 'owned', target_is_directory=True)
        with self.assertRaises(ValueError):
            sweep.scan(home, {os.urandom(32)})

    def test_size_limit_is_incomplete(self):
        home = pathlib.Path(tempfile.mkdtemp(prefix='ec05-sweep-', dir='/tmp'))
        (home / 'cache').mkdir()
        (home / 'cache/control').write_bytes(os.urandom(64))
        with patch.object(sweep, 'LIMIT', 32), self.assertRaises(ValueError):
            sweep.scan(home, {os.urandom(32)})


if __name__ == '__main__':
    unittest.main()
