#!/usr/bin/env python3
#
# Print the names of the tests that skipped in the last "meson test" run of a
# build directory, one per line, in the form "meson test" takes them.
#
# The test log does not hold the names "meson test" accepts: it records the
# name meson prints, which carries the project and the suite. How it does so
# depends on the meson version - "esdm / name" and "esdm:cuse / name" up to
# 1.7, "esdm:name" and "cuse - esdm:name" later - and "meson test" refuses all
# of those forms. So the logged name is matched against the test names the
# build directory defines instead of being taken apart.
#
# usage: skipped-tests.py <builddir>

import json
import subprocess
import sys

builddir = sys.argv[1]

tests = json.loads(subprocess.run(
	[ 'meson', 'introspect', '--tests', builddir ],
	check=True, capture_output=True, text=True).stdout)
names = { test['name'] for test in tests }

skipped = set()
with open(f'{builddir}/meson-logs/testlog.json') as log:
	for line in log:
		result = json.loads(line)
		if result['result'] != 'SKIP':
			continue

		logged = result['name']
		matches = [ name for name in names
			    if logged == name or
			       logged.endswith(' / ' + name) or
			       logged.endswith(':' + name) ]
		if not matches:
			sys.exit(f'skipped test "{logged}" is not one of the build')
		# The longest match, should a test name be the tail of another
		skipped.add(max(matches, key=len))

for name in sorted(skipped):
	# "meson test" reads a colon as the project separator and newer versions
	# take the name as a glob pattern
	if any(c in name for c in ':*?['):
		sys.exit(f'test name "{name}" cannot be passed to meson test')
	print(name)
