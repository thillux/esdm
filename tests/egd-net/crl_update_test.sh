#!/bin/sh
#
# esdm-egd-net-crl-update, with a curl(1) of the test that copies files: the
# URLs are files of the test PKI and of the test itself.
#
#  - a PEM file with two CRLs: both written, as PEM;
#  - a DER file: written as PEM;
#  - a PEM file with a good CRL and a broken one behind it: the update fails,
#    and the file stays as it was - openssl crl alone reads the first CRL
#    only;
#  - a PEM file whose CRL is not terminated: the same.
#
# Needs openssl(1).
#
#   crl_update_test.sh <esdm-egd-net-crl-update.sh> <test PKI directory>

set -u

update="$1"
pki="$2"

if ! command -v openssl >/dev/null 2>&1; then
	echo "No openssl(1), skipped"
	exit 77
fi

dir="$(mktemp -d "${TMPDIR:-/tmp}/esdm-crl-update-test.XXXXXX")" || exit 1
trap 'rm -rf -- "$dir"' EXIT INT TERM
mkdir "$dir/bin"

# curl as the updater calls it: options, --output <file>, -- <url>
cat >"$dir/bin/curl" <<'EOF'
#!/bin/sh
out=
url=
while [ $# -gt 0 ]; do
	case "$1" in
	--output) out="$2"; shift 2 ;;
	--) url="$2"; shift 2 ;;
	*) shift ;;
	esac
done
exec cp -- "$url" "$out"
EOF
chmod 0755 "$dir/bin/curl"
PATH="$dir/bin:$PATH"
export PATH

failures=0

fail() {
	echo "FAIL: $*"
	failures=$((failures + 1))
}

crls() {
	grep -c -- '-----BEGIN X509 CRL-----' "$1"
}

out="$dir/crls.pem"

cat "$pki/int.crl" "$pki/ca.crl" >"$dir/two.pem"
if ! sh "$update" "$out" "$dir/two.pem" || [ "$(crls "$out")" != 2 ]; then
	fail "a PEM file with two CRLs"
fi

openssl crl -in "$pki/ca.crl" -outform DER -out "$dir/ca.der"
if ! sh "$update" "$out" "$dir/two.pem" "$dir/ca.der" ||
   [ "$(crls "$out")" != 3 ]; then
	fail "a PEM file and a DER file"
fi
cp "$out" "$dir/good.pem"

# A CRL whose body is not one
{
	cat "$pki/int.crl"
	echo '-----BEGIN X509 CRL-----'
	echo 'Tm90IGEgQ1JMIGF0IGFsbAo='
	echo '-----END X509 CRL-----'
} >"$dir/broken.pem"
if sh "$update" "$out" "$dir/broken.pem" 2>/dev/null; then
	fail "a PEM file with a broken second CRL was taken"
fi
cmp -s "$out" "$dir/good.pem" || fail "the file changed on a failed update"

# A CRL cut short
{
	cat "$pki/int.crl"
	sed '$d' "$pki/ca.crl"
} >"$dir/cut.pem"
if sh "$update" "$out" "$dir/cut.pem" 2>/dev/null; then
	fail "a PEM file with a CRL cut short was taken"
fi
cmp -s "$out" "$dir/good.pem" || fail "the file changed on a failed update"

# Nothing left behind next to the file
if [ "$(find "$dir" -maxdepth 1 -name '.esdm-crl-update.*' | wc -l)" != 0 ]; then
	fail "temporary files left behind"
fi

if [ "$failures" != 0 ]; then
	echo "CRL download: FAILED"
	exit 1
fi
echo "CRL download: passed"
exit 0
