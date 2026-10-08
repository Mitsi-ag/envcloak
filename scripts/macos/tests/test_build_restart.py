#!/usr/bin/env python3
"""Founder install restart contract, with the real installer and a CLI recorder."""
import os
import unittest
import test_build_swap as swap
from test_build_swap import write

CLI = '''#!/bin/sh
case "$1" in
 --version) echo 'envcloak 9.9.9-test';;
 status)
  [ "${BAD_STATUS:-}" != 1 ] || { echo '{}'; exit 0; }
  if [ -f "$FAKE/restarted" ]; then version="${AFTER_VERSION:-9.9.9-test}"; else version="${RUNNING_VERSION:-9.9.9-test}"; fi
  printf '{"daemon":{"version":"%s"}}\\n' "$version";;
 daemon)
  [ "$2" = install ] && [ "$3" = --daemon ] || exit 90
  case "$4" in */inst/EnvCloak.app/Contents/Helpers/EnvCloakAgent.app/Contents/MacOS/envcloakd) ;; *) exit 91;; esac
  printf '%s\\n' "$*" >> "$FAKE/restart-args"
  [ "${FAIL_INSTALL:-}" != 1 ] || exit 1
  : > "$FAKE/restarted";;
 *) exit 92;;
esac
'''

class Restart(unittest.TestCase):
    setUpClass = classmethod(swap.BuildApp.setUpClass.__func__)
    tearDownClass = classmethod(swap.BuildApp.tearDownClass.__func__)
    each = swap.BuildApp.each
    run_case = swap.BuildApp.run_case
    assertClean = swap.BuildApp.assertClean
    def test_restart_only_changed_version_and_verify_result(self):
        for version, flags, success, restart in [
            ('9.9.9-test', {}, True, False),
            ('old', {}, True, True),
            ('old', {'FAIL_INSTALL': '1'}, False, True),
            ('old', {'AFTER_VERSION': 'old'}, False, True),
            ('old', {'BAD_STATUS': '1'}, False, False),
        ]:
            def case(b):
                write(os.path.join(b.fake, 'bin/envcloak'), CLI, 0o755)
                b.start(RUNNING_VERSION=version, **flags)
                status, left = b.finish()
                self.assertEqual(status == 0, success, b.stderr())
                self.assertEqual(os.path.exists(os.path.join(b.fake, 'restart-args')), restart)
                self.assertClean(b, left)
            self.each(case, sites=('install',))

if __name__ == '__main__':
    unittest.main()
