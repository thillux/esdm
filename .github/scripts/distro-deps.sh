#!/bin/bash
#
# Install what building and testing the ESDM needs on the distribution of the
# container a CI job runs in - Arch Linux, Debian, Fedora, openSUSE
# Tumbleweed, SUSE Linux Enterprise Server or Red Hat Enterprise Linux, as
# /etc/os-release names it - and build from source what the distribution does
# not package.
#
# Debian packages no jitter RNG library. The SLES and RHEL images are the
# freely available BCI and UBI ones, whose repositories hold a part of the
# distribution only. What is missing there is built from source: protobuf-c on
# SLES 16, protobuf-c, json-c and the jitter RNG on RHEL. Only the libraries
# are built, protobuf-c without its compiler: the generated sources are part
# of the ESDM tree.
#
# The meson options a distribution needs on top of those of the job are
# written to $GITHUB_ENV as ESDM_DISTRO_OPTS, and so is the compiler where it
# is not the distribution's default one.
#
# usage: distro-deps.sh

set -euo pipefail

JITTERENTROPY_VERSION="${JITTERENTROPY_VERSION:-3.7.0}"
PROTOBUF_C_VERSION="1.5.2"
JSON_C_VERSION="0.18-20240915"

# Into /usr, as the compilers of SLES and RHEL do not search /usr/local -
# Debian's search /usr/local/lib, but not /usr/lib64
PREFIX=/usr
LIBDIR=/usr/lib64

export_env() {
	echo "$1=$2"
	if [ -n "${GITHUB_ENV:-}" ]; then
		echo "$1=$2" >> "${GITHUB_ENV}"
	fi
}

fetch() {
	curl -fsSL --retry 3 -o "$2" "$1"
}

# The mirrors of the distributions drop a download now and then, and a
# package manager gives up on the first one
retry() {
	local i
	for i in 1 2 3; do
		"$@" && return 0
		echo "attempt ${i} of: $* failed"
		sleep 15
	done
	return 1
}

build_jitterentropy() {
	fetch "https://github.com/smuellerDD/jitterentropy-library/archive/refs/tags/v${JITTERENTROPY_VERSION}.tar.gz" jent.tar.gz
	tar xfz jent.tar.gz
	make -C "jitterentropy-library-${JITTERENTROPY_VERSION}" \
	     PREFIX="${PREFIX}" LIBDIR="${LIBDIR#"${PREFIX}"/}"
	make -C "jitterentropy-library-${JITTERENTROPY_VERSION}" \
	     PREFIX="${PREFIX}" LIBDIR="${LIBDIR#"${PREFIX}"/}" install
}

build_protobuf_c() {
	fetch "https://github.com/protobuf-c/protobuf-c/releases/download/v${PROTOBUF_C_VERSION}/protobuf-c-${PROTOBUF_C_VERSION}.tar.gz" protobuf-c.tar.gz
	tar xfz protobuf-c.tar.gz
	(
		cd "protobuf-c-${PROTOBUF_C_VERSION}"
		./configure --prefix="${PREFIX}" --libdir="${LIBDIR}" \
			    --disable-protoc --disable-static
		make -j"$(nproc)"
		make install
	)
}

build_json_c() {
	fetch "https://github.com/json-c/json-c/archive/refs/tags/json-c-${JSON_C_VERSION}.tar.gz" json-c.tar.gz
	tar xfz json-c.tar.gz
	cmake -S "json-c-json-c-${JSON_C_VERSION}" -B json-c-build \
	      -DCMAKE_INSTALL_PREFIX="${PREFIX}" \
	      -DCMAKE_INSTALL_LIBDIR="${LIBDIR}" \
	      -DCMAKE_BUILD_TYPE=Release \
	      -DBUILD_STATIC_LIBS=OFF -DBUILD_TESTING=OFF
	cmake --build json-c-build -j"$(nproc)"
	cmake --install json-c-build
}

# shellcheck source=/dev/null
. /etc/os-release
echo "Installing the dependencies on ${PRETTY_NAME}"

work="$(mktemp -d)"
cd "${work}"

case "${ID}" in
arch)
	# Everything is packaged, the backends without a TLS stack of their
	# own as well: Botan 3 and leancrypto.
	retry pacman -Syu --noconfirm --needed \
		base-devel curl git meson ninja pkgconf python \
		protobuf-c fuse3 json-c openssl jitterentropy \
		libp11 softhsm botan leancrypto
	# Arch has no SELinux
	export_env ESDM_DISTRO_OPTS "-Dselinux=disabled -Des_pkcs11=enabled"
	;;
debian)
	export DEBIAN_FRONTEND=noninteractive
	retry apt-get update
	retry apt-get install -y --no-install-recommends \
		ca-certificates curl gcc libc6-dev make meson ninja-build \
		pkgconf python3 libprotobuf-c-dev libfuse3-dev libssl-dev \
		libjson-c-dev libselinux1-dev libp11-dev softhsm2 \
		linux-libc-dev
	PREFIX=/usr/local
	LIBDIR=/usr/local/lib
	build_jitterentropy
	ldconfig
	export_env ESDM_DISTRO_OPTS "-Des_pkcs11=enabled"
	;;
fedora)
	# Everything is packaged, Botan 3 as well, and a GnuTLS built with its
	# FIPS 140 mode, which exports the DRBG the GnuTLS backend drives
	retry dnf -y install \
		gcc gcc-c++ make meson ninja-build pkgconf-pkg-config \
		diffutils findutils shadow-utils util-linux procps-ng \
		python3 protobuf-c-devel fuse3-devel json-c-devel \
		openssl-devel libselinux-devel jitterentropy-devel \
		libp11-devel softhsm botan3-devel gnutls-devel nettle-devel \
		kernel-headers
	export_env ESDM_DISTRO_OPTS "-Des_pkcs11=enabled"
	;;
opensuse-tumbleweed)
	# Everything is packaged, leancrypto as well, and a GnuTLS built with
	# its FIPS 140 mode, see Fedora
	retry zypper --non-interactive refresh
	retry zypper --non-interactive install --no-recommends \
		curl diffutils findutils gawk gzip tar make gcc meson ninja \
		pkgconf-pkg-config shadow util-linux python313 \
		protobuf-c-devel fuse3-devel json-c-devel libopenssl-3-devel \
		libselinux-devel jitterentropy-devel libp11-devel softhsm \
		libgnutls-devel libnettle-devel leancrypto-devel \
		linux-glibc-devel
	export_env ESDM_DISTRO_OPTS "-Des_pkcs11=enabled"
	;;
sles)
	retry zypper --non-interactive refresh
	pkgs=(curl diffutils findutils gawk gzip tar make git-core meson ninja
	      shadow util-linux
	      python3 fuse3-devel libjson-c-devel libopenssl-3-devel
	      libselinux-devel jitterentropy-devel libp11-devel
	      linux-glibc-devel)
	case "${VERSION_ID}" in
	15.*)
		# The default gcc of SLES 15 is 7, which knows no C17
		pkgs+=(gcc14 pkg-config libprotobuf-c-devel)
		retry zypper --non-interactive install --no-recommends "${pkgs[@]}"
		export_env CC gcc-14
		;;
	*)
		pkgs+=(gcc pkgconf-pkg-config)
		retry zypper --non-interactive install --no-recommends "${pkgs[@]}"
		build_protobuf_c
		;;
	esac
	export_env ESDM_DISTRO_OPTS "-Des_pkcs11=enabled"
	;;
rhel)
	retry dnf -y install \
		gcc make meson ninja-build pkgconf-pkg-config cmake \
		git-core tar gzip diffutils findutils shadow-utils util-linux \
		procps-ng \
		python3 fuse3-devel openssl-devel libselinux-devel \
		kernel-headers
	build_jitterentropy
	build_protobuf_c
	build_json_c
	ldconfig
	# No libp11 in UBI: no esdm-es-pkcs11
	export_env ESDM_DISTRO_OPTS ""
	;;
*)
	echo "::error::no recipe for the distribution ${ID}"
	exit 1
	;;
esac

cd /
rm -rf "${work}"
