#!/bin/sh
# Installs the itter program: itter in your terminal, with private messages.
#
#   curl -fsSL https://github.com/rrmn/itter-client/releases/latest/download/install.sh | sh
#
# It downloads the newest release for this computer from GitHub, checks it
# against the release's SHA256SUMS, and puts `itter` in a folder on your PATH
# (no sudo). Later updates come with `itter update`, which only installs a
# release signed with itter's release key (post-quantum: Ed25519 + ML-DSA-87
# + SLH-DSA). How to check this first download by hand: see the README.
#
# ITTER_VERSION=v1.2.3   install that release instead of the newest
# ITTER_INSTALL_DIR=dir  install into dir
# ITTER_RELEASES=url     download from somewhere else (for tests)
set -eu

REPO="rrmn/itter-client"
FINGERPRINT="6272 705b 6200 d258 80dd 12c9 7db1 911b" # the release key, as `itter version` shows it

say() { printf '%s\n' "$*"; }
fail() { printf 'itter: %s\n' "$*" >&2; exit 1; }

case "$(uname -s)" in
Darwin) os=darwin ;;
Linux) os=linux ;;
*) fail "there is no itter program for $(uname -s) yet (only macOS and Linux)" ;;
esac
case "$(uname -m)" in
arm64 | aarch64) arch=arm64 ;;
x86_64 | amd64) arch=amd64 ;;
*) fail "there is no itter program for $(uname -m) processors yet" ;;
esac

base="${ITTER_RELEASES:-https://github.com/$REPO/releases}"
version="${ITTER_VERSION:-latest}"
if [ "$version" = latest ]; then
	url="$base/latest/download"
else
	url="$base/download/$version"
fi
asset="itter_${os}_${arch}.tar.gz"

tmp=$(mktemp -d 2>/dev/null || mktemp -d -t itter)
trap 'rm -rf "$tmp"' EXIT INT TERM

proto="=https"
[ -z "${ITTER_RELEASES:-}" ] || proto="=https,http"
fetch() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --proto "$proto" --tlsv1.2 -o "$tmp/$1" "$url/$1" || fail "could not download $url/$1"
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O "$tmp/$1" "$url/$1" || fail "could not download $url/$1"
	else
		fail "needs curl or wget"
	fi
}
sha256() {
	if command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | cut -d' ' -f1
	elif command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	else
		fail "needs shasum or sha256sum to check the download"
	fi
}

say "Downloading itter ($os/$arch) from github.com/$REPO ..."
fetch "$asset"
fetch SHA256SUMS
want=$(awk -v f="$asset" '$2 == f || $2 == "*" f { print $1 }' "$tmp/SHA256SUMS")
got=$(sha256 "$tmp/$asset")
[ -n "$want" ] || fail "the release lists no $asset; nothing was installed"
[ "$want" = "$got" ] || fail "the download does not match the release's checksum; nothing was installed"
tar -xzf "$tmp/$asset" -C "$tmp" itter || fail "could not unpack the download"
chmod 755 "$tmp/itter"
"$tmp/itter" version >"$tmp/version" 2>&1 || fail "the downloaded program does not run on this computer"

# Where to put it: a folder on the PATH that this user can write to.
dir="${ITTER_INSTALL_DIR:-}"
if [ -z "$dir" ]; then
	for d in "$HOME/.local/bin" /usr/local/bin /opt/homebrew/bin "$HOME/bin"; do
		case ":$PATH:" in
		*":$d:"*) if [ -d "$d" ] && [ -w "$d" ]; then dir=$d; break; fi ;;
		esac
	done
fi
[ -n "$dir" ] || dir="$HOME/.local/bin"
mkdir -p "$dir" || fail "cannot create $dir"
[ -w "$dir" ] || fail "cannot write to $dir (choose another place with ITTER_INSTALL_DIR=...)"
mv -f "$tmp/itter" "$dir/itter" || fail "cannot write $dir/itter"

say ""
say "Installed: $dir/itter"
sed 's/^/  /' "$tmp/version"
if ! grep -q "$FINGERPRINT" "$tmp/version"; then
	say "  (that release key is not the one this script knows: $FINGERPRINT)"
fi
case ":$PATH:" in
*":$dir:"*) ;;
*)
	shell_rc="$HOME/.profile"
	case "${SHELL:-}" in
	*/zsh) shell_rc="$HOME/.zshrc" ;;
	*/bash) shell_rc="$HOME/.bashrc" ;;
	esac
	say ""
	say "$dir is not on your PATH yet. Add it with:"
	say "  echo 'export PATH=\"$dir:\$PATH\"' >> $shell_rc"
	say "and open a new terminal."
	;;
esac
other=$(command -v itter 2>/dev/null || true)
if [ -n "$other" ] && [ "$other" != "$dir/itter" ]; then
	say ""
	say "Note: another itter comes first on your PATH: $other"
fi
say ""
say "Start it with:  itter"
