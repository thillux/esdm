#!/bin/sh
# Model check the TLA+ models in this directory: <Model>.tla with its
# configurations <Model>/*.cfg, all of them or the ones given. A configuration
# passes when TLC finds no error, or when it finds the one its line
# "\* Expect: <property>" names. Without arguments, configurations with a line
# "\* Slow" are left out unless TLA_ALL=1 is set.
#
# Needs pcal and tlc: nix shell nixpkgs#tlaplus18 -c tests/tla/check.sh
# The flake check "tla" runs it: nix build .#checks.x86_64-linux.tla
set -e
cd "$(dirname "$0")"
# The JVM takes a quarter of the memory by default, too much for several
# runs at once; TLC keeps what does not fit on disk.
export JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS:--Xmx1g}"
skip_slow=
if [ $# -eq 0 ]; then
	set -- */*.cfg
	[ -n "$TLA_ALL" ] || skip_slow=1
fi
meta=$(mktemp -d)
trap 'rm -rf "$meta"' EXIT
fail=0
for cfg; do
	model=${cfg%%/*}
	name=$(basename "$cfg" .cfg)
	if [ -n "$skip_slow" ] && grep -q '^\\\* Slow' "$cfg"; then
		echo "skip  $cfg (slow)"
		continue
	fi
	if grep -q -- "--algorithm" "$model.tla"; then
		pcal -nocfg "$model.tla" >"$meta/pcal.log" 2>&1 || {
			cat "$meta/pcal.log"
			exit 1
		}
		rm -f "$model.old"
	fi
	expect=$(sed -n 's/^\\\* Expect: *//p' "$cfg")
	out="$meta/$model-$name.log"
	tlc -workers "${TLC_WORKERS:-auto}" -noGenerateSpecTE -config "$cfg" \
		-metadir "$meta/$model-$name" "$model.tla" >"$out" 2>&1 || true
	states=$(sed -n 's/.* \([0-9,]*\) distinct states found.*/\1/p' "$out" |
		tail -n 1)
	if [ -z "$expect" ] && grep -q "No error has been found" "$out"; then
		echo "pass  $cfg ($states states)"
	elif [ -n "$expect" ] &&
		grep -Eq "(Invariant|Property|property) $expect is violated|Temporal properties were violated" "$out" &&
		grep -q "$expect" "$out"; then
		echo "pass  $cfg (finds $expect, $states states)"
	else
		echo "FAIL  $cfg"
		grep -E "^Error|violated" "$out" | head -n 5
		fail=1
	fi
done
exit $fail
