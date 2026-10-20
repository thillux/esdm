#!/usr/bin/env bash
#
# Regenerate the test PKI of the EGD network tests: the certificates, keys and
# CRLs next to this script, which are committed so that the test suite needs
# no openssl binary. Needs OpenSSL 3.0 or later (openssl ca -crl_lastupdate).
#
#   tests/egd-net/pki/gen.sh [<output directory>]
#
# The server certificates are issued for localhost, 127.0.0.1 and ::1, or for
# what ESDM_PKI_SERVER_SAN names - a subjectAltName value such as
# "DNS:server,IP:192.168.1.2" -, which is how the NixOS check makes a PKI for
# its hosts.
#
# Root CA "ESDM EGD Test Root CA" (ca.crt)
#  +- server.crt            the server, valid for a century
#  +- server-renewed.crt    the same names with a key of its own, for rotation
#  +- server-wrongname.crt  issued for wrong.example only
#  +- server-wrongusage.crt the names of server.crt, for TLS client
#  |                        authentication only (extended key usage)
#  +- int.crt               intermediate CA "ESDM EGD Test Intermediate CA"
#      +- client1.crt       a client, the intermediate in its file
#      +- client1-leaf.crt  the same certificate, without the intermediate
#      +- client2.crt       another one
#      +- client-revoked.crt  revoked by int.crl
#      +- client-expired.crt  expired in 2021
# Rogue CA (rogue-ca.crt), trusted by nobody
#  +- rogue-client.crt
#
# ML-DSA Root CA "ESDM EGD Test ML-DSA Root CA" (mldsa-ca.crt), on ML-DSA-87 -
# all of which every context of the ESDM refuses, as ML-DSA is post-quantum
# cryptography on its own: the tests check that
#  +- mldsa-server.crt      the server on ML-DSA-87, the names of server.crt
#  +- mldsa-ec-server.crt   the same on ECDSA P-256
#  +- mldsa-int.crt         intermediate CA "ESDM EGD Test ML-DSA Intermediate
#  |   |                    CA", on ML-DSA-87
#  |   +- mldsa-client.crt  a client on ML-DSA-87, the intermediate in its file
#  |   +- mldsa-client-revoked.crt  another one, revoked by mldsa-int.crl
#  |   +- mldsa-ec-client.crt  a client on ECDSA P-256, the intermediate in its
#  |   |                   file
#  |   +- mldsa65-client.crt  a client on ML-DSA-65
#  +- mldsa65-int.crt       intermediate CA on ML-DSA-65
#      +- mldsa65-ec-client.crt  a client on ECDSA P-256, that intermediate in
#                          its file
#
# The ML-DSA part takes OpenSSL 3.5 or later - an older openssl leaves it out.
# ca-mldsa.crt holds the root CA and the ML-DSA root CA, as trust anchors of
# both.
# client-fakeroot.crt is client1.crt followed by a self-signed certificate
# claiming to be the root CA - its name and its key identifier, but a key of
# its own -, the key of which no CRL of the root verifies with. ca-int.crt
# holds the root and the intermediate CA, as trust anchors.
#
# CRLs, all valid for a century unless said otherwise:
#  ca.crl           of the root CA, revoking nothing - it covers the
#                   intermediate CA and the servers
#  ca-revoked-int.crl  of the root CA, revoking the intermediate CA
#  ca-revoked-server.crl  of the root CA, revoking server.crt
#  int.crl          of the intermediate CA, revoking client-revoked
#  int-empty.crl    of the intermediate CA, revoking nothing
#  int-expired.crl  of the intermediate CA, revoking nothing, its nextUpdate
#                   in 2020
#  int-delta.crl    of the intermediate CA, a delta CRL (deltaCRLIndicator)
#  int-idp.crl      of the intermediate CA, limited by an issuing
#                   distribution point
#  mldsa-ca.crl     of the ML-DSA root CA, revoking nothing
#  mldsa-int.crl    of the ML-DSA intermediate CA, revoking
#                   mldsa-client-revoked

set -euo pipefail

OUT="${1:-$(cd "$(dirname "$0")" && pwd)}"
SAN="${ESDM_PKI_SERVER_SAN:-DNS:localhost,IP:127.0.0.1,IP:::1}"
DAYS=36500

mkdir -p "$OUT"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A CA directory for openssl ca: its database, serial and CRL number
ca_dir() {
	mkdir -p "$WORK/$1/certs"
	: >"$WORK/$1/index.txt"
	echo 1000 >"$WORK/$1/serial"
	echo 1000 >"$WORK/$1/crlnumber"
}

cat >"$WORK/ca.cnf" <<EOF
[ ca ]
default_ca = root

[ root ]
dir = $WORK/root
database = \$dir/index.txt
new_certs_dir = \$dir/certs
serial = \$dir/serial
crlnumber = \$dir/crlnumber
certificate = $OUT/ca.crt
private_key = $OUT/ca.key
default_md = sha256
default_days = $DAYS
default_crl_days = $DAYS
policy = policy_any
unique_subject = no
copy_extensions = none

[ int ]
dir = $WORK/int
database = \$dir/index.txt
new_certs_dir = \$dir/certs
serial = \$dir/serial
crlnumber = \$dir/crlnumber
certificate = $OUT/int.crt
private_key = $OUT/int.key
default_md = sha256
default_days = $DAYS
default_crl_days = $DAYS
policy = policy_any
unique_subject = no
copy_extensions = none

[ root_server ]
dir = $WORK/root-server
database = \$dir/index.txt
new_certs_dir = \$dir/certs
serial = \$dir/serial
crlnumber = \$dir/crlnumber
certificate = $OUT/ca.crt
private_key = $OUT/ca.key
default_md = sha256
default_days = $DAYS
default_crl_days = $DAYS
policy = policy_any
unique_subject = no
copy_extensions = none

[ rogue ]
dir = $WORK/rogue
database = \$dir/index.txt
new_certs_dir = \$dir/certs
serial = \$dir/serial
crlnumber = \$dir/crlnumber
certificate = $OUT/rogue-ca.crt
private_key = $WORK/rogue-ca.key
default_md = sha256
default_days = $DAYS
default_crl_days = $DAYS
policy = policy_any
unique_subject = no
copy_extensions = none

[ mldsa_root ]
dir = $WORK/mldsa-root
database = \$dir/index.txt
new_certs_dir = \$dir/certs
serial = \$dir/serial
crlnumber = \$dir/crlnumber
certificate = $OUT/mldsa-ca.crt
private_key = $OUT/mldsa-ca.key
default_md = default
default_days = $DAYS
default_crl_days = $DAYS
policy = policy_any
unique_subject = no
copy_extensions = none

[ mldsa_int ]
dir = $WORK/mldsa-int
database = \$dir/index.txt
new_certs_dir = \$dir/certs
serial = \$dir/serial
crlnumber = \$dir/crlnumber
certificate = $OUT/mldsa-int.crt
private_key = $OUT/mldsa-int.key
default_md = default
default_days = $DAYS
default_crl_days = $DAYS
policy = policy_any
unique_subject = no
copy_extensions = none

[ mldsa65_int ]
dir = $WORK/mldsa65-int
database = \$dir/index.txt
new_certs_dir = \$dir/certs
serial = \$dir/serial
crlnumber = \$dir/crlnumber
certificate = $OUT/mldsa65-int.crt
private_key = $OUT/mldsa65-int.key
default_md = default
default_days = $DAYS
default_crl_days = $DAYS
policy = policy_any
unique_subject = no
copy_extensions = none

[ policy_any ]
commonName = supplied
organizationName = optional

[ req ]
distinguished_name = req_dn
prompt = no

[ req_dn ]
CN = unused

[ v3_root ]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash

[ v3_int ]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always

[ v3_server ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
subjectAltName = $SAN

[ v3_server_wrongname ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
subjectAltName = DNS:wrong.example

[ v3_server_wrongusage ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
subjectAltName = $SAN

[ v3_client ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always

[ crl_delta ]
2.5.29.27 = critical, ASN1:INTEGER:4096

[ crl_idp ]
issuingDistributionPoint = critical, @idp

[ idp ]
fullname = URI:http://crl.example/int.crl
EOF

# A key: <file> [algorithm], ECDSA on P-256 without an algorithm
key() {
	if [ -n "${2:-}" ]; then
		openssl genpkey -algorithm "$2" -out "$1" 2>/dev/null
	else
		openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
			-out "$1" 2>/dev/null
	fi
}

# A self-signed CA: <key> <cert> <CN> [algorithm]
self_signed() {
	key "$1" "${4:-}"
	openssl req -config "$WORK/ca.cnf" -new -x509 -key "$1" -out "$2" \
		-days "$DAYS" -subj "/O=ESDM/CN=$3" -extensions v3_root \
		-set_serial 1
}

# A certificate issued by a CA of ca.cnf, with a key of ECDSA on P-256 - or of
# the algorithm of KEY_ALG:
#   [KEY_ALG=<algorithm>] issue <ca> <extensions> <name> <CN> [openssl ca options...]
issue() {
	local ca="$1" ext="$2" name="$3" cn="$4"

	shift 4
	key "$OUT/$name.key" "${KEY_ALG:-}"
	openssl req -config "$WORK/ca.cnf" -new -key "$OUT/$name.key" \
		-subj "/O=ESDM/CN=$cn" -out "$WORK/$name.csr"
	openssl ca -config "$WORK/ca.cnf" -name "$ca" -batch -notext \
		-extensions "$ext" -in "$WORK/$name.csr" \
		-out "$OUT/$name.crt" "$@" 2>/dev/null
}

# A CRL of a CA of ca.cnf: <ca> <file> [openssl ca options...]
crl() {
	local ca="$1" file="$2"

	shift 2
	openssl ca -config "$WORK/ca.cnf" -name "$ca" -gencrl \
		-out "$OUT/$file" "$@" 2>/dev/null
}

ca_dir root
ca_dir root-server
ca_dir int
ca_dir rogue

self_signed "$OUT/ca.key" "$OUT/ca.crt" "ESDM EGD Test Root CA"
self_signed "$WORK/rogue-ca.key" "$OUT/rogue-ca.crt" "ESDM EGD Rogue CA"

# The fake root: the name and the key identifier of the root CA
root_ski="$(openssl x509 -in "$OUT/ca.crt" -noout -ext subjectKeyIdentifier |
	sed -n 2p | tr -d ' ')"
cat >>"$WORK/ca.cnf" <<EOF

[ v3_fake_root ]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = $root_ski
EOF
key "$WORK/fake-root.key"
openssl req -config "$WORK/ca.cnf" -new -x509 -key "$WORK/fake-root.key" \
	-out "$WORK/fake-root.crt" -days "$DAYS" \
	-subj "/O=ESDM/CN=ESDM EGD Test Root CA" -extensions v3_fake_root \
	-set_serial 1

issue root v3_int int "ESDM EGD Test Intermediate CA"
issue root v3_server server "ESDM EGD Test Server"
issue root v3_server server-renewed "ESDM EGD Test Server (renewed)"
issue root v3_server_wrongname server-wrongname "ESDM EGD Test Server (wrong name)"
issue root v3_server_wrongusage server-wrongusage "ESDM EGD Test Server (client usage)"

issue int v3_client client1 "ESDM EGD Test Client 1"
issue int v3_client client2 "ESDM EGD Test Client 2"
issue int v3_client client-revoked "ESDM EGD Test Client (revoked)"
issue int v3_client client-expired "ESDM EGD Test Client (expired)" \
	-startdate 20200101000000Z -enddate 20210101000000Z

issue rogue v3_client rogue-client "ESDM EGD Rogue Client"

cp "$OUT/client1.crt" "$OUT/client1-leaf.crt"
cat "$OUT/ca.crt" "$OUT/int.crt" >"$OUT/ca-int.crt"

# The clients send the intermediate CA along with their certificate
for c in client1 client2 client-revoked client-expired; do
	cat "$OUT/int.crt" >>"$OUT/$c.crt"
done

cat "$OUT/client1.crt" "$WORK/fake-root.crt" >"$OUT/client-fakeroot.crt"

crl root ca.crl
crl int int-empty.crl
crl int int-expired.crl -crl_lastupdate 20200101000000Z \
	-crl_nextupdate 20200102000000Z
crl int int-delta.crl -crlexts crl_delta
crl int int-idp.crl -crlexts crl_idp

openssl ca -config "$WORK/ca.cnf" -name int -revoke \
	"$WORK/int/certs/$(awk -F'\t' '/Client \(revoked\)/ { print $4 }' \
		"$WORK/int/index.txt").pem" 2>/dev/null
crl int int.crl

openssl ca -config "$WORK/ca.cnf" -name root -revoke "$OUT/int.crt" \
	2>/dev/null
crl root ca-revoked-int.crl

# The root CA revoking the server alone: a database of its own, which knows
# of no other certificate
openssl ca -config "$WORK/ca.cnf" -name root_server -revoke "$OUT/server.crt" \
	2>/dev/null
crl root_server ca-revoked-server.crl

# The ML-DSA PKI, see above: with OpenSSL 3.5 or later only
if openssl list -signature-algorithms 2>/dev/null | grep ML-DSA-87 >/dev/null; then
	ca_dir mldsa-root
	ca_dir mldsa-int
	ca_dir mldsa65-int

	self_signed "$OUT/mldsa-ca.key" "$OUT/mldsa-ca.crt" \
		"ESDM EGD Test ML-DSA Root CA" ML-DSA-87

	KEY_ALG=ML-DSA-87 issue mldsa_root v3_int mldsa-int \
		"ESDM EGD Test ML-DSA Intermediate CA"
	KEY_ALG=ML-DSA-87 issue mldsa_root v3_server mldsa-server \
		"ESDM EGD Test ML-DSA Server"
	issue mldsa_root v3_server mldsa-ec-server \
		"ESDM EGD Test ECDSA Server (ML-DSA CA)"
	KEY_ALG=ML-DSA-65 issue mldsa_root v3_int mldsa65-int \
		"ESDM EGD Test ML-DSA-65 Intermediate CA"

	KEY_ALG=ML-DSA-87 issue mldsa_int v3_client mldsa-client \
		"ESDM EGD Test ML-DSA Client"
	KEY_ALG=ML-DSA-87 issue mldsa_int v3_client mldsa-client-revoked \
		"ESDM EGD Test ML-DSA Client (revoked)"
	issue mldsa_int v3_client mldsa-ec-client \
		"ESDM EGD Test ECDSA Client (ML-DSA CA)"
	KEY_ALG=ML-DSA-65 issue mldsa_int v3_client mldsa65-client \
		"ESDM EGD Test ML-DSA-65 Client"
	issue mldsa65_int v3_client mldsa65-ec-client \
		"ESDM EGD Test ECDSA Client (ML-DSA-65 CA)"

	for c in mldsa-client mldsa-client-revoked mldsa-ec-client \
		mldsa65-client; do
		cat "$OUT/mldsa-int.crt" >>"$OUT/$c.crt"
	done
	cat "$OUT/mldsa65-int.crt" >>"$OUT/mldsa65-ec-client.crt"
	cat "$OUT/ca.crt" "$OUT/mldsa-ca.crt" >"$OUT/ca-mldsa.crt"

	crl mldsa_root mldsa-ca.crl
	openssl ca -config "$WORK/ca.cnf" -name mldsa_int -revoke \
		"$WORK/mldsa-int/certs/$(awk -F'\t' '/ML-DSA Client \(revoked\)/ { print $4 }' \
			"$WORK/mldsa-int/index.txt").pem" 2>/dev/null
	crl mldsa_int mldsa-int.crl
else
	echo "No ML-DSA in this openssl: the ML-DSA PKI is left out"
fi

echo "Test PKI written to $OUT"
