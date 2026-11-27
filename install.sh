#!/bin/sh
# Installs the itter program: itter in your terminal, with private messages.
#
#   curl -fsSL https://itter.sh/install | sh
#
# itter.sh/install is this file in the newest release on GitHub. It downloads
# that release for this computer from github.com/rrmn/itter-client, checks it
# against the release's SHA256SUMS, puts `itter` in a folder on your PATH (no
# sudo; if that folder is not on your PATH yet, it adds it in your shell's
# startup file) and starts itter. Later updates come with `itter update`,
# which only installs a release signed with itter's release key
# (post-quantum: Ed25519 + ML-DSA-87 + SLH-DSA). How to check this first
# download by hand: see the README.
#
# ITTER_VERSION=v1.2.3   install that release instead of the newest
# ITTER_INSTALL_DIR=dir  install into dir
# ITTER_PATH=0           leave your shell's startup files alone
# ITTER_START=0          do not start itter afterwards
# ITTER_RELEASES=url     download from somewhere else (for tests)
#
# Everything happens in main(), at the very end: nothing runs before this
# whole file has arrived.
set -eu

REPO="rrmn/itter-client"
FINGERPRINT="6272 705b 6200 d258 80dd 12c9 7db1 911b" # the release key, as `itter version` shows it

say() { printf '%s\n' "$*"; }
fail() {
	printf 'Error: %s\n' "$*" >&2
	exit 1
}

# tilde PATH: PATH with ~ for the home folder, to keep messages short.
tilde() {
	case "$1" in
	"$HOME") printf '%s' '~' ;;
	"$HOME"/*) printf '~%s' "${1#"$HOME"}" ;;
	*) printf '%s' "$1" ;;
	esac
}

on_path() {
	case ":${PATH:-}:" in
	*":$1:"*) return 0 ;;
	esac
	return 1
}

fetch() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --proto "$proto" --tlsv1.2 -o "$tmp/$1" "$url/$1" || fail "Couldn't download $url/$1. Is the internet there?"
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O "$tmp/$1" "$url/$1" || fail "Couldn't download $url/$1. Is the internet there?"
	else
		fail "This needs curl or wget."
	fi
}

sha256() {
	if command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | cut -d' ' -f1
	elif command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	else
		fail "This needs shasum or sha256sum, to check the download."
	fi
}

# add_to_path DIR: puts DIR on the PATH in the startup file of the user's
# shell. Sets rc to that file ("" if that did not work) and added=yes if the
# line was not there before.
add_to_path() {
	added=no
	case "$1" in
	"$HOME"/*) p="\$HOME${1#"$HOME"}" ;;
	*) p=$1 ;;
	esac
	line="export PATH=\"$p:\$PATH\""
	case "${SHELL:-}" in
	*/zsh) rc="${ZDOTDIR:-$HOME}/.zshrc" ;;
	*/bash)
		rc="$HOME/.bashrc"
		if [ "$os" = darwin ]; then
			# Terminal windows on a Mac start login shells: bash reads only the
			# first of these that exists.
			rc="$HOME/.bash_profile"
			for f in "$HOME/.bash_profile" "$HOME/.bash_login" "$HOME/.profile"; do
				if [ -f "$f" ]; then
					rc=$f
					break
				fi
			done
		fi
		;;
	*/fish)
		rc="${XDG_CONFIG_HOME:-$HOME/.config}/fish/conf.d/itter.fish"
		line="fish_add_path -g \"$p\""
		;;
	*) rc="$HOME/.profile" ;;
	esac
	if [ -f "$rc" ] && grep -qxF "$line" "$rc"; then
		return 0
	fi
	if mkdir -p "$(dirname "$rc")" 2>/dev/null &&
		printf '\n# itter (https://itter.sh)\n%s\n' "$line" >>"$rc" 2>/dev/null; then
		added=yes
	else
		rc=""
	fi
}

main() {
	case "$(uname -s)" in
	Darwin) os=darwin ;;
	Linux) os=linux ;;
	*) fail "Sorry... no itter for $(uname -s) yet. Only macOS and Linux (for now)." ;;
	esac
	case "$(uname -m)" in
	arm64 | aarch64) arch=arm64 ;;
	x86_64 | amd64) arch=amd64 ;;
	*) fail "Sorry... no itter for $(uname -m) processors yet." ;;
	esac
	# A terminal that runs under Rosetta says x86_64 on an Apple silicon Mac.
	if [ "$os/$arch" = darwin/amd64 ] && [ "$(sysctl -n hw.optional.arm64 2>/dev/null || true)" = 1 ]; then
		arch=arm64
	fi
	case "$os/$arch" in
	darwin/arm64) system="macOS (Apple silicon)" ;;
	darwin/amd64) system="macOS (Intel)" ;;
	linux/arm64) system="Linux (ARM)" ;;
	*) system="Linux (x86-64)" ;;
	esac

	base="${ITTER_RELEASES:-https://github.com/$REPO/releases}"
	version="${ITTER_VERSION:-latest}"
	if [ "$version" = latest ]; then
		url="$base/latest/download"
	else
		url="$base/download/$version"
	fi
	asset="itter_${os}_${arch}.tar.gz"
	from="github.com/$REPO"
	proto="=https"
	if [ -n "${ITTER_RELEASES:-}" ]; then
		from=$base
		proto="=https,http"
	fi

	tmp=$(mktemp -d 2>/dev/null || mktemp -d -t itter)
	trap 'rm -rf "$tmp"' EXIT
	trap 'rm -rf "$tmp"; exit 130' INT
	trap 'rm -rf "$tmp"; exit 143' TERM

	say "Getting itter for $system from $from..."
	fetch "$asset"
	fetch SHA256SUMS
	want=$(awk -v f="$asset" '$2 == f || $2 == "*" f { print $1 }' "$tmp/SHA256SUMS")
	got=$(sha256 "$tmp/$asset")
	[ -n "$want" ] || fail "Whoa: the release lists no $asset. Nothing was installed."
	[ "$want" = "$got" ] || fail "Whoa: the download doesn't match the release's checksum. Nothing was installed."
	tar -xzf "$tmp/$asset" -C "$tmp" itter || fail "Couldn't unpack the download."
	chmod 755 "$tmp/itter"
	"$tmp/itter" version >"$tmp/version" 2>&1 || fail "The downloaded itter doesn't run on this computer. That is... unusual."
	new=$(sed -n '1s/^itter \([^ ]*\).*/\1/p' "$tmp/version")

	# Where to put it: a folder on the PATH that this user can write to.
	dir="${ITTER_INSTALL_DIR:-}"
	if [ -z "$dir" ]; then
		for d in "$HOME/.local/bin" /usr/local/bin /opt/homebrew/bin "$HOME/bin"; do
			if on_path "$d" && [ -d "$d" ] && [ -w "$d" ]; then
				dir=$d
				break
			fi
		done
	fi
	[ -n "$dir" ] || dir="$HOME/.local/bin"
	mkdir -p "$dir" 2>/dev/null || fail "Can't create $dir. Pick another folder: ... | ITTER_INSTALL_DIR=/some/dir sh"
	[ -w "$dir" ] || fail "Can't write to $dir. Pick another folder: ... | ITTER_INSTALL_DIR=/some/dir sh"
	# A copy next to the old program, then a rename: this works while itter runs.
	if ! { cp "$tmp/itter" "$dir/.itter.new" && mv -f "$dir/.itter.new" "$dir/itter"; }; then
		rm -f "$dir/.itter.new"
		fail "Can't write $dir/itter."
	fi
	say "Got itter${new:+ $new}! It lives in $(tilde "$dir") now."
	if ! grep -qF "$FINGERPRINT" "$tmp/version"; then
		say "Heads up: this release has another release key than the one this script knows ($FINGERPRINT). That is... unusual. Tell us: contact@itter.sh"
	fi

	if on_path "$dir"; then
		next="Next time, just type: itter"
		now="Start it with: itter"
	else
		rc=""
		added=no
		[ "${ITTER_PATH:-1}" = 0 ] || add_to_path "$dir"
		if [ -n "$rc" ]; then
			[ "$added" = no ] || say "Added $(tilde "$dir") to your PATH (in $(tilde "$rc"))."
			next="Next time, open a new terminal and type: itter"
			now="Open a new terminal and type: itter"
		else
			say "$(tilde "$dir") isn't on your PATH."
			next="Next time, type: $dir/itter"
			now="Start it with: $dir/itter"
		fi
	fi
	other=$(command -v itter 2>/dev/null || true)
	if [ -n "$other" ] && [ "$other" != "$dir/itter" ]; then
		say "Heads up: another itter comes first on your PATH: $other"
	fi

	# Start it, if there is someone at a terminal to use it.
	if [ "${ITTER_START:-1}" != 0 ] && [ -t 1 ] && (exec </dev/tty) 2>/dev/null; then
		say ""
		say "Here we go! $next"
		say ""
		rm -rf "$tmp"
		trap - EXIT INT TERM
		exec "$dir/itter" </dev/tty
	fi
	say ""
	say "$now"
}

main "$@"
