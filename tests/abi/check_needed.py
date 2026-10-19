#!/usr/bin/env python3
#
# Check the libraries a shared library needs - its NEEDED entries, as readelf
# tells them - against the ones it may need. libesdm_egd_client is to need
# the C library and nothing else, in every configuration: it is loaded into
# sandboxed processes, and a TLS stack linked in by accident would be loaded
# into each of them - see service-egd/client/meson.build.
#
# The runtimes of the toolchain are always allowed: those of the sanitizers,
# which a sanitizer build links into everything, and libgcc_s.
#
# usage: check_needed.py --readelf READELF --lib LIB [--allow REGEX ...]

import argparse
import re
import subprocess
import sys

TOOLCHAIN = [ r'lib(a|hwa|l|t|ub)san\.so(\..*)?', r'libgcc_s\.so(\..*)?' ]

NEEDED = re.compile(r'\(NEEDED\)\s+Shared library: \[([^\]]+)\]')

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('--readelf', required=True)
	parser.add_argument('--lib', required=True)
	parser.add_argument('--allow', action='append', default=[])
	args = parser.parse_args()

	out = subprocess.run([ args.readelf, '-d', '-W', args.lib ],
			     check=True, capture_output=True, text=True).stdout
	needed = NEEDED.findall(out)
	allowed = [ re.compile(a) for a in args.allow + TOOLCHAIN ]

	bad = [ n for n in needed
		if not any(a.fullmatch(n) for a in allowed) ]
	print('%s needs %s' % (args.lib, ', '.join(needed) or 'nothing'))
	if bad:
		print('Not to be needed: %s' % ', '.join(bad))
		return 1
	return 0

if __name__ == '__main__':
	sys.exit(main())
