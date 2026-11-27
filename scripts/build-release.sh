#!/bin/sh
# Builds the files of a release:
#
#   scripts/build-release.sh v1.2.3 <commit> <outdir>
#
# <outdir> gets one archive per system, VERSION, install.sh and SHA256SUMS.
# The build is reproducible: the same source (the commit), the same Go
# (go.mod names the toolchain) and this script give the same files, byte for
# byte, on any machine. scripts/release.sh signs SHA256SUMS and publishes.
set -eu
[ $# -eq 3 ] || { echo "usage: $0 v1.2.3 <commit> <outdir>" >&2; exit 2; }
V=$1 C=$2 OUT=$3
case "$V" in v[0-9]*.[0-9]*.[0-9]*) ;; *) echo "not a version like v1.2.3: $V" >&2; exit 2 ;; esac
case "$C" in *[!0-9a-f]* | "") echo "not a commit hash: $C" >&2; exit 2 ;; esac
cd "$(dirname "$0")/.."
export CGO_ENABLED=0 GOFLAGS=-mod=readonly LC_ALL=C TZ=UTC
GOTOOLCHAIN=go$(awk '/^go /{print $2}' go.mod) # exactly the Go that go.mod names
export GOTOOLCHAIN
TAR=tar
tar --version 2>/dev/null | grep -q GNU || TAR=gtar
"$TAR" --version 2>/dev/null | grep -q GNU || { echo "needs GNU tar (on a Mac: brew install gnu-tar)" >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then SUM="sha256sum"; else SUM="shasum -a 256"; fi
mkdir -p "$OUT"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
for p in darwin/arm64 darwin/amd64 linux/amd64 linux/arm64; do
	os=${p%/*} arch=${p#*/}
	mkdir -p "$work/$os-$arch"
	GOOS=$os GOARCH=$arch go build -trimpath -buildvcs=false \
		-ldflags "-s -w -buildid= -X main.version=$V -X main.commit=$C" \
		-o "$work/$os-$arch/itter" ./cmd/itter
	"$TAR" --sort=name --owner=0 --group=0 --numeric-owner --mtime='2000-01-01 00:00:00Z' \
		-C "$work/$os-$arch" -cf - itter | gzip -9 -n >"$OUT/itter_${os}_${arch}.tar.gz"
done
printf '%s\n' "$V" >"$OUT/VERSION"
cp install.sh "$OUT/install.sh"
(cd "$OUT" && $SUM itter_*.tar.gz VERSION install.sh | sort -k2 >SHA256SUMS)
echo "built $V ($C) with $(go env GOVERSION) into $OUT:"
cat "$OUT/SHA256SUMS"
