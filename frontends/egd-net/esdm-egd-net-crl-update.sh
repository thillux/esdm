#!/bin/sh
#
# esdm-egd-net-crl-update: download the CRLs of the EGD network daemons
#
#   esdm-egd-net-crl-update <file> <url>...
#
# Fetches the CRL behind each URL - DER, as a CRL distribution point serves it,
# or PEM, which may hold several -, checks that each CRL parses, and writes all
# of them in PEM to <file>, atomically: they are written next to it and renamed
# into its place, so that a daemon reading <file> never sees half of it. The
# daemons take up the new file by themselves, see --reload_interval of
# esdm-egd-net-server(8).
#
# A URL that cannot be fetched or holds a CRL that does not parse fails the
# whole update, and <file> stays as it was: a daemon refuses a file with a CRL
# it cannot load and keeps the CRLs it has, until their nextUpdate passes and
# they refuse every peer they cover; a missing CRL would refuse them at once.
#
# Needs curl(1) and openssl(1). Run by esdm-egd-net-crl-update@.service, see
# esdm-egd-net-server(8).

set -eu

if [ $# -lt 2 ]; then
	echo "usage: $0 <file> <url>..." >&2
	exit 2
fi

out="$1"
shift

dir="$(dirname -- "$out")"
tmp="$(mktemp "$dir/.esdm-crl-update.XXXXXX")"
trap 'rm -f -- "$tmp" "$tmp.one" "$tmp".crl.*' EXIT INT TERM

for url in "$@"; do
	curl --fail --silent --show-error --location --proto '=http,https' \
		--retry 5 --retry-delay 10 --retry-all-errors --max-time 120 \
		--max-filesize 67108864 --output "$tmp.one" -- "$url"

	if grep -q -- '-----BEGIN X509 CRL-----' "$tmp.one"; then
		# Each CRL of the file on its own - openssl crl reads the first
		# one only -, written as openssl read it, nothing else of the
		# file along with it
		rm -f -- "$tmp".crl.*
		awk -v base="$tmp.crl." '
			/-----BEGIN X509 CRL-----/ { n++; out = base n; crl = 1 }
			crl { print > out }
			/-----END X509 CRL-----/ { if (crl) close(out); crl = 0 }
		' "$tmp.one"
		for one in "$tmp".crl.*; do
			openssl crl -in "$one" -outform PEM >>"$tmp"
		done
	else
		openssl crl -inform DER -in "$tmp.one" -outform PEM >>"$tmp"
	fi
done

chmod 0644 -- "$tmp"
mv -f -- "$tmp" "$out"
