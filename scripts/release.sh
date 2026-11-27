#!/bin/bash
# Publishes a release that scripts/build-release.sh made into _release/<version>/:
# checks it, signs SHA256SUMS with the release key, tags the commit it was
# built from and uploads it all to GitHub.
#
#   scripts/release.sh v1.2.3
#
# Needs gh (logged in as the repository's owner), the release key in
# ~/.itter-release/release-key.json (its passphrase is asked for) and the
# signing tool in _release/tools/itter-release (go build ./cmd/itter-release).
# With Go installed, it builds the program for this computer again and makes
# sure it is the same, byte for byte.
set -euo pipefail
cd "$(dirname "$0")/.."
V=${1:?usage: scripts/release.sh v1.2.3}
REPO=${ITTER_REPO:-rrmn/itter-client}
DIR=_release/$V
KEY=${ITTER_RELEASE_KEY:-$HOME/.itter-release/release-key.json}
TOOL=_release/tools/itter-release
PUB=release-key.pub
say() { printf '\n=== %s\n' "$*"; }
die() { printf '\nSTOPPED: %s\n' "$*" >&2; exit 1; }
git_gh() { git -c credential.helper= -c 'credential.helper=!gh auth git-credential' "$@"; }

say "1. checks"
owner=$(gh api user --jq .login) || die "gh is not logged in"
[ "$owner" = "${REPO%%/*}" ] || die "gh is logged in as $owner, not ${REPO%%/*}"
[ -f "$DIR/SHA256SUMS" ] || die "no $DIR/SHA256SUMS"
[ "$(cat "$DIR/VERSION")" = "$V" ] || die "$DIR/VERSION is not $V"
(cd "$DIR" && shasum -a 256 -c SHA256SUMS) || die "the files do not match SHA256SUMS"
[ -z "$(git status --porcelain --untracked-files=no)" ] || die "there are uncommitted changes"
COMMIT=$(git rev-parse HEAD)
git_gh fetch -q origin main
[ "$(git rev-parse origin/main)" = "$COMMIT" ] || die "this checkout is not at origin/main"
! git rev-parse -q --verify "refs/tags/$V" >/dev/null || die "tag $V exists already"
arch=$(uname -m)
[ "$arch" = x86_64 ] && arch=amd64
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
tar -xzf "$DIR/itter_darwin_$arch.tar.gz" -C "$tmp" itter
"$tmp/itter" version | tee "$tmp/version"
grep -q "^itter $V (commit ${COMMIT:0:12}," "$tmp/version" || die "the release was not built from $COMMIT"
grep -q "release key: $("$TOOL" fingerprint "$PUB")\$" "$tmp/version" || die "the program does not carry the key in $PUB"
if command -v go >/dev/null 2>&1; then
	GOTOOLCHAIN=go$(awk '/^go /{print $2}' go.mod) CGO_ENABLED=0 GOOS=darwin GOARCH=$arch \
		go build -trimpath -buildvcs=false -ldflags "-s -w -buildid= -X main.version=$V -X main.commit=$COMMIT" \
		-o "$tmp/itter-here" ./cmd/itter
	cmp -s "$tmp/itter" "$tmp/itter-here" || die "built again on this computer, the program is different"
	echo "built again on this computer: the same, byte for byte"
else
	echo "(Go is not installed here, so the program was not built again for comparison)"
fi

say "2. sign SHA256SUMS (type the release key's passphrase)"
"$TOOL" sign "$KEY" "$DIR/SHA256SUMS"
"$TOOL" verify "$PUB" "$DIR/SHA256SUMS"

say "3. tag $V and publish"
git tag -a "$V" -m "itter $V" "$COMMIT"
git_gh push -q origin "refs/tags/$V"
gh release create "$V" --repo "$REPO" --verify-tag --title "itter $V" --notes-file "$DIR/NOTES.md" \
	"$DIR"/itter_*.tar.gz "$DIR/VERSION" "$DIR/install.sh" "$DIR/SHA256SUMS" "$DIR/SHA256SUMS.sig"

say "4. what GitHub serves"
for f in SHA256SUMS SHA256SUMS.sig; do
	curl -fsSL "https://github.com/$REPO/releases/download/$V/$f" -o "$tmp/$f" || die "cannot download $f from GitHub"
	cmp -s "$tmp/$f" "$DIR/$f" || die "GitHub serves another $f"
done
echo "published: https://github.com/$REPO/releases/tag/$V"
