#!/bin/bash
# itter: run the test suite, a native build and an end-to-end check on this Mac.
# Double-click it in Finder, or run it from a terminal.
#
# It works only inside this folder and a temporary directory. Your real
# ~/.itter-cli, your SSH keys and the real itter are never touched. The
# end-to-end part creates two throwaway accounts (one of them with a second,
# linked device) on a relay that runs on this machine only, stores their vault
# keys in your login keychain like the real client does, and removes them
# again at the end.
#
# If the itter app is found next to this folder (../itter/itterapp, with its
# .venv), the entrance it offers the DM client is checked as well, with the
# app's own Python: its tests, and then the whole way for real (this client ->
# the app's SSH server -> the relay). The app's .env is not read and no
# database is touched. That part expects the app's asyncssh to offer the
# post-quantum key exchange; upgrade-itter-venv.command, next to this file,
# brings an older environment up to that.
#
# Results: _run/status (one line per step, 0 = ok) and _run/*.log.

cd "$(dirname "$0")" || exit 1
ROOT=$(pwd)
mkdir -p _run
rm -f _run/done _run/status
exec > >(tee _run/run.log) 2>&1

for d in /usr/local/go/bin /opt/homebrew/bin "$HOME/.homebrew/bin" "$HOME/go/bin" /usr/local/bin; do
	[ -d "$d" ] && PATH="$PATH:$d"
done

echo "itter check started $(date)"
sw_vers 2>/dev/null | tr '\n' ' '; uname -m
if ! command -v go >/dev/null; then
	echo "Go is not installed (or not on PATH). Install it from https://go.dev/dl/ and run this again."
	echo "go=missing" > _run/status
	date > _run/done
	exit 1
fi
go version

step() {
	local name=$1
	shift
	echo
	echo "=== $name: $*"
	"$@" > "_run/$name.log" 2>&1
	local rc=$?
	echo "$name=$rc" >> _run/status
	tail -n 12 "_run/$name.log"
	return $rc
}

step vet go vet ./...
if [ -n "$QUICK" ]; then # QUICK=1 ./run-on-mac.command skips the test suite (a few minutes)
	echo "test=skipped" >> _run/status
else
	step test go test ./... -count=1
fi
step build_itter go build -o _run/bin/itter ./cmd/itter
step build_relay go build -o _run/bin/itter-relay ./cmd/itter-relay

# The client binary that was delivered ready-made (built on another machine).
echo
echo "=== delivered ./itter"
if [ ! -x ./itter ]; then
	echo "delivered=absent" >> _run/status
elif xattr -p com.apple.quarantine ./itter >/dev/null 2>&1; then
	echo "It carries the macOS quarantine mark, so it was not started. Use _run/bin/itter (built here) instead."
	echo "delivered=quarantined" >> _run/status
else
	./itter help > _run/delivered.log 2>&1
	rc=$?
	echo "delivered=$rc" >> _run/status
	head -n 3 _run/delivered.log
fi

# has_key <state dir> [<vault id>]: does the vault key of that throwaway
# account (still) exist? On a Mac that is an entry in the login keychain.
if [ "$(uname)" = Darwin ]; then
	has_key() { security find-generic-password -s itter-cli -a "${2:-$(cat "$T/$1/vault.id")}" >/dev/null 2>&1; }
	WHERE="the login keychain"
else
	has_key() { [ -f "$T/$1/vault.key" ]; }
	WHERE="a key file"
fi

# forget_keys removes whatever the throwaway accounts under $T still have in
# the keychain, so that a check that fails halfway leaves nothing behind.
forget_keys() {
	[ "$(uname)" = Darwin ] || return 0
	for f in "$T"/*/vault.id; do
		[ -f "$f" ] && security delete-generic-password -s itter-cli -a "$(cat "$f")" >/dev/null 2>&1
	done
	return 0
}

smoke() (
	set -e -o pipefail
	BIN="$ROOT/_run/bin"
	T=$(mktemp -d /tmp/itter-check.XXXXXX)
	RELAY_PID=
	cleanup() {
		[ -n "$RELAY_PID" ] && kill "$RELAY_PID" 2>/dev/null
		[ -n "$SSH_AGENT_PID" ] && kill "$SSH_AGENT_PID" 2>/dev/null
		forget_keys
		rm -rf "$T"
	}
	trap cleanup EXIT

	ssh-keygen -q -t ed25519 -N '' -C itter-check-alice -f "$T/alice_key"
	ssh-keygen -q -t ed25519 -N '' -C itter-check-bob -f "$T/bob_key"
	# alice's key is in an ssh-agent of its own; bob's is only a file.
	eval "$(ssh-agent -a "$T/agent.sock" -s)" >/dev/null
	ssh-add -q "$T/alice_key"
	printf 'alice %s\nbob %s\n' "$(cat "$T/alice_key.pub")" "$(cat "$T/bob_key.pub")" > "$T/users.txt"

	"$BIN/itter-relay" -mem -users "$T/users.txt" -addr 127.0.0.1:18099 > "$ROOT/_run/relay.log" 2>&1 &
	RELAY_PID=$!
	sleep 1
	export ITTER_RELAY=http://127.0.0.1:18099
	# With ITTER_KEY set the client looks at that file and nowhere else, so
	# the keys in your real ~/.ssh are not even read.
	export ITTER_KEY="$T/alice_key"
	unset ITTER_KEYFILE NO_COLOR ITTER_HOST
	[ "$(uname)" = Darwin ] || export ITTER_KEYFILE=1 # no login keychain here: the key is a file next to the vault

	as() {
		local u=$1
		shift
		echo
		echo "\$ [$u] itter $*"
		ITTER_DIR="$T/$u" "$BIN/itter" "$@"
	}
	expect() { # expect <text> : the previous command's output (in $T/out) must contain it
		grep -q -- "$1" "$T/out" || { echo "MISSING: $1"; return 1; }
	}
	burn() { # burn <state dir>: wipe it; its vault key must be gone afterwards
		local id
		id=$(cat "$T/$1/vault.id")
		echo
		echo "\$ [$1] itter burn"
		echo BURN | ITTER_DIR="$T/$1" "$BIN/itter" burn
		if has_key "$1" "$id"; then
			echo "VAULT KEY LEFT BEHIND: $1 ($id)"; return 1
		fi
	}

	as alice setup alice
	SSH_AUTH_SOCK= ITTER_KEY="$T/bob_key" as bob setup bob # no agent: the key file is enough
	if has_key alice && has_key bob; then
		echo "vault keys are in $WHERE"
	else
		echo "MISSING: vault key in $WHERE"; return 1
	fi

	as alice dm @bob "hello from macOS"
	as bob read | tee "$T/out"; expect "hello from macOS"
	as bob dm @alice "hi back"
	as alice read | tee "$T/out"; expect "hi back"
	as alice status | tee "$T/out"; expect "connected, it knows this device"
	as alice sn @bob
	echo YES | ITTER_DIR="$T/alice" "$BIN/itter" verify @bob | tee "$T/out"; expect "marked as verified"

	echo; echo "--- six itter processes at once on one vault (file locking)"
	pids=
	for i in 1 2 3 4 5 6; do
		ITTER_DIR="$T/alice" "$BIN/itter" dm @bob "parallel $i" >/dev/null &
		pids="$pids $!"
	done
	wait $pids
	as bob read | tee "$T/out"
	[ "$(grep -c "parallel" "$T/out")" = 6 ] || { echo "MISSING: six parallel messages"; return 1; }

	echo; echo "--- a second device for alice: link on the new one, approve on the first"
	ITTER_DIR="$T/alice2" "$BIN/itter" link alice > "$T/link.out" 2>&1 &
	LINK_PID=$!
	CODE=
	for i in $(seq 1 100); do
		CODE=$(sed -n 's/^ *itter approve \([A-Z2-7-]*\) *$/\1/p' "$T/link.out" | head -n 1)
		[ -n "$CODE" ] && break
		sleep 0.3
	done
	[ -n "$CODE" ] || { cat "$T/link.out"; echo "MISSING: the new device showed no link code"; return 1; }
	echo; echo "\$ [alice] itter approve <the code>   (answering LINK when asked)"
	echo LINK | ITTER_DIR="$T/alice" "$BIN/itter" approve "$CODE" | tee "$T/out"; expect "Linked device"
	wait $LINK_PID || { cat "$T/link.out"; echo "MISSING: the new device did not finish linking"; return 1; }
	cat "$T/link.out"
	cp "$T/link.out" "$T/out"; expect "Linked. This device is @alice now"
	has_key alice2 || { echo "MISSING: the linked device's vault key in $WHERE"; return 1; }
	as alice devices | tee "$T/out"; expect "linked device"
	LAPTOP=$(sed -n 's/^ *[0-9]*\. \([0-9a-f]*\)  linked device.*/\1/p' "$T/out" | head -n 1)
	[ -n "$LAPTOP" ] || { echo "MISSING: the linked device's id"; return 1; }

	as bob dm @alice "to all of you"
	as alice read | tee "$T/out"; expect "to all of you"
	as alice2 read | tee "$T/out"; expect "to all of you"
	as alice2 dm @bob "sent from the second device"
	as bob read | tee "$T/out"; expect "sent from the second device"
	as alice read @bob 10 | tee "$T/out"; expect "sent from the second device"
	as alice2 sn @bob | tee "$T/out"
	SN2=$(grep -E '^ *([0-9]{5} ){3,}' "$T/out" | tr -d ' \n')
	as alice sn @bob > "$T/out"
	SN1=$(grep -E '^ *([0-9]{5} ){3,}' "$T/out" | tr -d ' \n')
	if [ -z "$SN1" ] || [ "$SN1" != "$SN2" ]; then
		echo "MISSING: the same safety number on both of alice's devices"; return 1
	fi
	echo "same safety number on both devices"

	echo; echo "--- bob ignores alice: her messages vanish, and she is not told"
	as bob ignore @alice | tee "$T/out"; expect "Ignoring @alice"
	as alice dm @bob "you should not see this" | tee "$T/out"; expect "Sent"
	as bob read | tee "$T/out"
	if grep -q "you should not see this" "$T/out"; then echo "MISSING: the ignore list did not hold"; return 1; fi
	as bob unignore @alice
	as alice dm @bob "and now you can"
	as bob read | tee "$T/out"; expect "and now you can"

	echo; echo "--- alice unlinks the second device: it is out"
	as alice unlink "$LAPTOP" | tee "$T/out"; expect "is unlinked"
	if as alice2 read > "$T/out" 2>&1; then cat "$T/out"; echo "MISSING: an unlinked device was still served"; return 1; fi
	cat "$T/out"; expect "unlinked"
	as bob dm @alice "only one device again"
	as alice read | tee "$T/out"; expect "only one device again"
	burn alice2

	echo; echo "--- bob reinstalls: alice must be asked before anything goes to the new identity"
	burn bob
	SSH_AUTH_SOCK= ITTER_KEY="$T/bob_key" as bob setup bob >/dev/null
	as bob dm @alice "new device"
	as alice read | tee "$T/out"; expect "IDENTITY CHANGED"
	if as alice dm @bob "should not go out" > "$T/out" 2>&1; then echo "MISSING: refusal to send"; return 1; fi
	cat "$T/out"; expect "accept @bob"
	as alice accept @bob | tee "$T/out"; expect "held message"
	as alice dm @bob "welcome back"
	as bob read | tee "$T/out"; expect "welcome back"

	echo; echo "--- alice loses her device: the recovery code frees the account, a second setup alone does not"
	as alice recovery-code > "$T/out"
	RCODE=$(grep -E -o '[A-Z2-7]{4}(-[A-Z2-7]{1,4}){8,}' "$T/out" | head -n 1)
	[ -n "$RCODE" ] || { echo "MISSING: the recovery code"; return 1; }
	mv "$T/alice" "$T/alice_lost" # out of reach from here on
	if as alice setup alice > "$T/out" 2>&1; then cat "$T/out"; echo "MISSING: refusal of a second identity"; return 1; fi
	cat "$T/out"; expect "itter recover"
	echo; echo "\$ [alice] itter recover alice   (typing the recovery code when asked)"
	echo "$RCODE" | ITTER_DIR="$T/alice" "$BIN/itter" recover alice | tee "$T/out"; expect "Released"
	as alice setup alice | tee "$T/out"; expect "Done. This device is @alice"
	as alice dm @bob "on a new device"
	as bob read | tee "$T/out"; expect "IDENTITY CHANGED"
	if as alice_lost read > "$T/out" 2>&1; then cat "$T/out"; echo "MISSING: the lost device was still served"; return 1; fi
	cat "$T/out"; expect "no longer knows this device"

	echo; echo "--- clean up: burn them all, the vault keys must be gone"
	burn alice
	burn alice_lost
	burn bob
	echo
	echo "END-TO-END OK"
)

# The itter app's side: the entrance its SSH server offers the DM client.
ITTERAPP="${ITTERAPP:-$ROOT/../itter/itterapp}"
PY="$ITTERAPP/.venv/bin/python"

gate_tests() (
	cd "$ITTERAPP" && PYTHONDONTWRITEBYTECODE=1 "$PY" -m unittest tests.test_dm_gate -v
)

# The whole way for real: this client -> itter's SSH server (the app's own
# class, with only the DM entrance and no database) -> the relay.
gate_chain() (
	set -e -o pipefail
	BIN="$ROOT/_run/bin"
	T=$(mktemp -d /tmp/itter-check.XXXXXX)
	RELAY_PID=
	GATE_PID=
	cleanup() {
		[ -n "$RELAY_PID" ] && kill "$RELAY_PID" 2>/dev/null
		[ -n "$GATE_PID" ] && kill "$GATE_PID" 2>/dev/null
		forget_keys
		rm -rf "$T"
	}
	trap cleanup EXIT

	ssh-keygen -q -t ed25519 -N '' -C itter-check-alice -f "$T/alice_key"
	ssh-keygen -q -t ed25519 -N '' -C itter-check-bob -f "$T/bob_key"
	printf 'alice %s\nbob %s\n' "$(cat "$T/alice_key.pub")" "$(cat "$T/bob_key.pub")" > "$T/users.txt"
	"$BIN/itter-relay" -mem -users "$T/users.txt" -addr 127.0.0.1:18098 -proxy-protocol > "$ROOT/_run/gate_relay.log" 2>&1 &
	RELAY_PID=$!
	(cd "$ITTERAPP" && PYTHONDONTWRITEBYTECODE=1 exec "$PY" -m tests.dm_gate_server --port 18022 --relay 127.0.0.1:18098) > "$ROOT/_run/gate_app.log" 2>&1 &
	GATE_PID=$!
	for i in $(seq 1 100); do
		grep -q "DM entrance" "$ROOT/_run/gate_app.log" 2>/dev/null && break
		sleep 0.2
	done
	cat "$ROOT/_run/gate_app.log"
	grep -q "DM entrance" "$ROOT/_run/gate_app.log" || { echo "MISSING: the app's SSH server did not start"; return 1; }

	unset ITTER_RELAY SSH_AUTH_SOCK NO_COLOR
	export ITTER_HOST=127.0.0.1:18022
	[ "$(uname)" = Darwin ] || export ITTER_KEYFILE=1
	as() {
		local u=$1
		shift
		echo
		echo "\$ [$u] itter $*"
		ITTER_DIR="$T/$u" ITTER_KEY="$T/${u}_key" "$BIN/itter" "$@"
	}
	expect() { grep -q -- "$1" "$T/out" || { echo "MISSING: $1"; return 1; }; }

	as alice setup alice | tee "$T/out"; expect "Done. This device is @alice"
	as bob setup bob > "$T/out"; expect "Done. This device is @bob"
	as alice dm @bob "through itter's SSH port"
	as bob read | tee "$T/out"; expect "through itter's SSH port"
	as bob dm @alice "and back"
	as alice read | tee "$T/out"; expect "and back"
	as alice status | tee "$T/out"; expect "itter (ssh 127.0.0.1:18022) — connected"
	if grep -q "Connection:   SSH, classical" "$T/out"; then
		echo "MISSING: the post-quantum key exchange. The asyncssh of the itter app is too old for it:"
		echo "         double-click upgrade-itter-venv.command, then this again."
		return 1
	fi
	expect "Connection:   SSH, post-quantum key exchange (mlkem768x25519-sha256)"

	echo; echo "--- eight clients at once"
	pids=
	for i in 1 2 3 4 5 6 7 8; do
		ITTER_DIR="$T/alice" ITTER_KEY="$T/alice_key" "$BIN/itter" dm @bob "burst $i" >/dev/null &
		pids="$pids $!"
	done
	wait $pids
	as bob read | tee "$T/out"
	[ "$(grep -c "burst" "$T/out")" = 8 ] || { echo "MISSING: eight messages"; return 1; }

	echo; echo "--- a person who tries the entrance with ssh gets no shell"
	ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none -F /dev/null \
		-p 18022 dm@127.0.0.1 true > "$T/out" 2>&1 || true
	cat "$T/out"; expect "not for a terminal"
	if grep -q "not using a post-quantum key exchange" "$T/out"; then
		echo "MISSING: an SSH server that ssh does not warn about"; return 1
	fi

	echo; echo "--- the relay stops: the client says so, and keeps the message"
	kill "$RELAY_PID"; wait "$RELAY_PID" 2>/dev/null || true
	RELAY_PID=
	as alice dm @bob "while the relay is down" > "$T/out" 2>&1 || true
	cat "$T/out"; expect "not running right now"

	echo; echo "--- clean up: the vault keys must be gone"
	for u in alice bob; do
		id=$(cat "$T/$u/vault.id")
		echo BURN | ITTER_DIR="$T/$u" "$BIN/itter" burn --force > /dev/null 2>&1 || true
		if has_key "$u" "$id"; then
			echo "VAULT KEY LEFT BEHIND: $u ($id)"; return 1
		fi
	done
	echo
	echo "THROUGH THE REAL APP OK"
)

if grep -q '^build_itter=0' _run/status && grep -q '^build_relay=0' _run/status; then
	step smoke smoke
	if [ -x "$PY" ] && [ -f "$ITTERAPP/tests/test_dm_gate.py" ]; then
		if ! step gate_tests gate_tests && grep -q "cannot do mlkem768x25519" _run/gate_tests.log; then
			echo "The asyncssh of the itter app is too old for the post-quantum key exchange:"
			echo "double-click upgrade-itter-venv.command, then this again."
		fi
		step gate_chain gate_chain
	else
		echo
		echo "=== the itter app's side: skipped (no $ITTERAPP/.venv, or no tests/test_dm_gate.py in it)"
		echo "gate=skipped" >> _run/status
	fi
else
	echo "smoke=skipped" >> _run/status
fi

echo
echo "=== summary"
cat _run/status
if grep -v '=0$' _run/status | grep -v '^delivered=' | grep -v '^test=skipped$' | grep -v '^gate=skipped$' | grep -q .; then
	echo "RESULT: something failed, see the logs in $ROOT/_run"
else
	echo "RESULT: all good"
fi
echo "finished $(date)"
date > _run/done
