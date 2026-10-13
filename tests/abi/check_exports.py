#!/usr/bin/env python3
#
# Check the dynamic symbol table of a shared library against the installed
# headers declaring its API:
#
#  - every function a header declares is exported, and not from a private
#    version node - a declared function the version script misses is local to
#    the library, and a program calling it fails to link;
#
#  - every function the library exports from a public version node is declared
#    by one of the headers - a function exported by accident becomes ABI with
#    the first program linking it.
#
# Without --header, --exactly names the complete list of exported functions,
# for a module such as an OpenSSL provider that has no header of its own.
#
# usage: check_exports.py --nm NM --lib LIB [--header H ...] [--exactly SYM ...]

import argparse
import re
import subprocess
import sys

# A function declaration: a return type ending in a blank or a star, the name,
# its parameter list. Not a function pointer, whose name is not right in front
# of the parenthesis.
FUNCTION = re.compile(r'^[\w\s\*]*[\s\*]([A-Za-z_]\w*)\s*\(')

def strip_comments(text):
	text = re.sub(r'/\*.*?\*/', ' ', text, flags=re.S)
	return re.sub(r'//[^\n]*', ' ', text)

def strip_preprocessor(text):
	# Joined continuation lines first, so that a multi-line macro goes as a
	# whole.
	text = text.replace('\\\n', ' ')
	return '\n'.join(line for line in text.split('\n')
			 if not line.lstrip().startswith('#'))

def statements(text):
	"""The declarations at file scope, with the bodies of struct, union and
	enum definitions and of inline functions left out."""
	# The C++ linkage block wraps everything but contributes no declaration.
	text = re.sub(r'extern\s*"C"\s*\{', ' ', text)

	depth = 0
	current = ''
	body_of_function = False
	for c in text:
		if c == '{':
			if depth == 0:
				body_of_function = current.rstrip().endswith(')')
			depth += 1
		elif c == '}':
			if depth == 0:
				# closing brace of the C++ linkage block
				continue
			depth -= 1
			if depth == 0 and body_of_function:
				yield ' '.join(current.split())
				current = ''
		elif depth > 0:
			continue
		elif c == ';':
			yield ' '.join(current.split())
			current = ''
		else:
			current += c

def declared_functions(header):
	with open(header) as f:
		text = strip_preprocessor(strip_comments(f.read()))

	functions = set()
	for statement in statements(text):
		if re.match(r'(typedef|static)\b', statement):
			continue
		match = FUNCTION.match(statement)
		if match:
			functions.add(match.group(1))
	return functions

def exported_functions(nm, lib):
	"""Name -> version node of every function the library exports. The node is
	None for a symbol without one."""
	out = subprocess.run([ nm, '-D', '--defined-only', lib ], check=True,
			     capture_output=True, text=True).stdout
	functions = {}
	for line in out.splitlines():
		fields = line.split()
		if len(fields) != 3 or fields[1] not in 'TWi':
			continue
		name, _, version = fields[2].partition('@')
		functions[name] = version.lstrip('@') or None
	return functions

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('--nm', required=True)
	parser.add_argument('--lib', required=True)
	parser.add_argument('--header', action='append', default=[])
	parser.add_argument('--exactly', action='append', default=[])
	args = parser.parse_args()

	exported = exported_functions(args.nm, args.lib)
	errors = []

	if args.exactly:
		for name in sorted(set(args.exactly) - exported.keys()):
			errors.append(f'{name} is not exported')
		for name in sorted(exported.keys() - set(args.exactly)):
			errors.append(f'{name} is exported but must not be')
	else:
		declared = set()
		for header in args.header:
			found = declared_functions(header)
			if not found:
				errors.append(f'{header}: no function declaration found')
			declared |= found

		for name in sorted(declared):
			if name not in exported:
				errors.append(f'{name} is declared but not exported')
			elif exported[name] and 'PRIVATE' in exported[name]:
				errors.append(f'{name} is declared but exported from'
					      f' the private node {exported[name]}')

		# Only a library with a version script tells its API apart
		# from the rest; without one, there is nothing to check here.
		for name, version in sorted(exported.items()):
			if version and 'PRIVATE' not in version and \
			   name not in declared:
				errors.append(f'{name} is exported as API ({version})'
					      ' but declared by no installed header')

		print(f'{len(declared)} declared functions checked')

	for error in errors:
		print(f'{args.lib}: {error}')
	return 1 if errors else 0

if __name__ == '__main__':
	sys.exit(main())
