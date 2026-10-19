#!/bin/sh
#
# esdm-egd-net-crl-update: download the CRLs of the EGD network daemons
#
#   esdm-egd-net-crl-update <file> <url>...
#
# Fetches the CRL behind each URL - DER, as a CRL distribution point serves it,
# or PEM -, checks that it parses, and writes all of them in PEM to <file>,
# atomically: they are written next to it and renamed into its place, so that a
# daemon reading <file> never sees half of it. The daemons take up the new file
# by themselves, see --reload_interval of esdm-egd-net-server(8).
#
# A URL that cannot be fetched or does not hold a CRL fails the whole update,
# and <file> stays as it was: a missing CRL would refuse every client it
# covers, an old one does until its nextUpdate.
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
trap 'rm -f -- "$tmp" "$tmp.one"' EXIT INT TERM

for url in "$@"; do
	curl --fail --silent --show-error --location --proto '=http,https' \
		--retry 5 --retry-delay 10 --retry-all-errors --max-time 120 \
		--max-filesize 67108864 --output "$tmp.one" -- "$url"

	if grep -q -- '-----BEGIN X509 CRL-----' "$tmp.one"; then
		openssl crl -in "$tmp.one" -noout
		cat -- "$tmp.one" >>"$tmp"
	else
		openssl crl -inform DER -in "$tmp.one" -outform PEM >>"$tmp"
	fi
done

chmod 0644 -- "$tmp"
mv -f -- "$tmp" "$out"
