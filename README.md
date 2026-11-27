> PRs very welcome!

# itter-client - itter.sh in your terminal, now with DMs

The itter client is itter.sh as you know it from ssh, plus direct messages
that only you and the people you write to can read.

```sh
curl -fsSL https://itter.sh/install | sh
```

That's it. It installs itter and starts it. Next time, just type `itter`.

## Features

*   **Same itter**: everything you know from `ssh app.itter.sh`. It logs in
    with your SSH key, wherever ssh finds it (1Password, ssh-agent, `~/.ssh`).
*   **DMs**: type `dm` (or press Ctrl-]) in itter. Esc brings you back. New
    DMs show in the terminal's title.
*   **End-to-end encrypted**: only you and the people you write to can read
    your DMs. Not itter, not us, not anyone else.
*   **Post-quantum**: a Triple Ratchet that holds even if RSA, elliptic
    curves and structured lattices are all broken. No RSA anywhere. The
    nerdy details: [PROTOCOL.md](PROTOCOL.md).
*   **Several devices**: up to five per account.
*   **Signed updates**: `itter update` only installs releases signed with
    itter's release key (post-quantum, too).
*   **macOS and Linux**: Apple silicon / ARM and Intel / AMD. No sudo.

## Install

```sh
curl -fsSL https://itter.sh/install | sh
```

*   It puts `itter` in a folder on your PATH (and adds the folder to your
    shell's startup file, if it has to). Then it starts itter.
*   Want to read it first? `curl -fsSL https://itter.sh/install | less`
*   `... | ITTER_START=0 sh` installs without starting itter.
*   `... | ITTER_PATH=0 sh` leaves your startup files alone.
*   Updates: `itter update`.

## Using it

*   **First time**: `itter` asks for your itter username. A new one signs
    you up.
*   **DMs**: type `dm` (or `dm @user`) in itter. The first time, it sets
    this computer up and shows a **recovery code**. Write it down! Lose this
    computer, and it's the only way to set up DMs for your account again.
*   **In the DMs**: `@user hello` writes to someone, `/chat @user` opens a
    chat, Tab completes, `/help` shows the rest.
*   **Safety numbers**: compare `itter sn @user` with the other person,
    somewhere you trust, then `itter verify @user`. That's how you know it's
    really them.
*   **More devices**: run `itter` on the new one and type `dm`. It shows a
    code: type `itter approve <code>` on your first device. Both get
    everything from then on (not the old messages).
*   **Why not in plain ssh?** Anything you type into an SSH session passes
    the server in the clear. The keys have to stay on your computer.

Commands, for scripts and quick use:

| | |
|---|---|
| `itter dm @user <msg>` | send one message |
| `itter read` | what's new (`itter read @user 50` for history) |
| `itter status` | account, relay, unread and unsent messages |
| `itter contacts` | who you talk to, and who's verified |
| `itter ignore @user` | no more DMs from someone (`itter unignore @user` takes it back) |
| `itter sn @user` | your safety number with someone |
| `itter verify @user` | you compared it, and it matched |
| `itter accept @user` | someone has a new identity: accept it |
| `itter reset @user` | chat stuck? start a fresh session |
| `itter devices` | your devices (`itter unlink <id>` removes one) |
| `itter recovery-code` | your recovery code again (first device) |
| `itter recover <username>` | first device lost? free the account with the code |
| `itter burn` | wipe this device (on the first device, also your DM identity) |
| `itter dms` | just the DMs |
| `itter version` | this program's version and release key |
| `itter update` | get the newest release (`--check` only looks) |

`itter setup <username>` and `itter link <username>` do by hand what the
first `dm` does, for scripts.

**Someone's identity changed?** (They started over, or it's an attack.) The
chat stops: nothing is sent, their new messages wait unread, and you see the
new safety number. `itter accept @user` goes on with it. Someone who just
adds a device keeps their identity: you get a one-line note.

**Ignoring**: `itter ignore @user` uses itter's own ignore list. Their DMs
are dropped at the relay, and they aren't told.

**Settings** (environment):

*   `ITTER_HOST`: itter's SSH server (default `app.itter.sh:22`).
*   `ITTER_KEY`: your itter SSH key, if itter doesn't find it by itself. A
    `.pub` file works too: then only that key is used, from your agent.
*   `ITTER_DIR`: where itter keeps its stuff (default `~/.itter`).
*   `ITTER_KEYFILE=1`: the vault key in a file, for machines without a
    keychain.
*   `ITTER_BELL=0`: no bell on new DMs. `NO_COLOR` works too.
*   `ITTER_RELAY`: talk to a relay directly, at an http(s) address (plain
    http only for localhost).

## Checking a release

Every release has `SHA256SUMS`, signed in `SHA256SUMS.sig` with the release
key. Its public half is [`release-key.pub`](release-key.pub) (also built into
the program). Its fingerprint, which `itter version` shows:

    6272 705b 6200 d258 80dd 12c9 7db1 911b

To check a release without trusting the program you downloaded (Go 1.27.1,
this repo at the release's tag):

```sh
go run ./cmd/itter-release verify release-key.pub SHA256SUMS   # next to SHA256SUMS.sig
scripts/build-release.sh v1.2.3 <the tag's commit> out/        # builds it again
diff out/SHA256SUMS SHA256SUMS                                 # same files, byte for byte
```

Builds are reproducible: same source, same Go, same files. Only the very
first download is taken on trust. `itter.sh/install` is a redirect on itter's
website to the newest release's `install.sh`. To leave the website out:
`curl -fsSL https://github.com/rrmn/itter-client/releases/latest/download/install.sh | sh`

## Running a relay

**Next to itter (production).** The relay runs on the machine with itter's
SSH app, for that app only:

1. Run `supabase/dm_relay.sql` (SQL editor of itter's Supabase project). It
   only adds `dm_*` tables and functions, for the service role only (the
   relay also uses itter's `ignored_users`). Safe to run again. Over the
   tables of an earlier version (one device per account) it replaces them
   if they're empty, and stops with an error if they hold data.
2. Check the store against the real project before going live:
   ```sh
   ITTER_TEST_POSTGREST_URL=https://<project>.supabase.co/rest/v1 \
   ITTER_TEST_POSTGREST_KEY=<service role key> \
   go test ./internal/server -run TestStoreConformance -v
   ```
   (It creates and removes two `dmtest_…` users, nothing else. **Not run
   against a real Supabase project yet.**)
3. Start the relay where the itter app runs:
   ```sh
   itter-relay -proxy-protocol            # listens on 127.0.0.1:8080
   ```
   It needs `SUPABASE_URL` and `SUPABASE_KEY` (the service role key), from
   the environment or a `.env` in the folder it starts from (the itter app's
   `.env` has both). Add `ITTER_TOKEN_KEY` (once: `openssl rand -hex 32`), so
   sessions survive a restart; without it, clients just prove themselves
   again. One instance only. With systemd, for example:
   ```ini
   # /etc/systemd/system/itter-relay.service
   [Unit]
   Description=itter DM relay
   After=network-online.target

   [Service]
   # the folder with the .env, and the user the itter app runs as
   WorkingDirectory=/path/to/itterapp
   User=itter
   ExecStart=/usr/local/bin/itter-relay -proxy-protocol
   Restart=always
   RestartSec=2

   [Install]
   WantedBy=multi-user.target
   ```
4. Tell the itter app where the relay is, and restart it:
   ```sh
   DM_RELAY_ADDR=127.0.0.1:8080           # in the itter app's .env
   ```
   That opens the entrance: SSH user `dm`, no login, no shell, nothing to
   reach but the relay (`itter/ssh/dm_gate.py` in the itter app). The relay
   checks every request itself, as it would on a public address.
   `-proxy-protocol` makes it take each client's real address from the
   app, so rate limits count real clients. In that mode, nothing but the app
   may reach it.
5. itter's SSH server isn't `app.itter.sh:22`? Set `defaultHost` in
   `cmd/itter/main.go` and build the client.
6. Optional, and good for itter in general: asyncssh 2.24.1+ in the app
   (`pip install -U "asyncssh>=2.24.1,<3.0.0"`). Its SSH server then offers
   the post-quantum key exchange, and recent OpenSSH clients stop warning.
   `itter status` shows which key exchange a connection got. DMs don't
   depend on it.

**On a public address of its own** (no SSH in between): run it behind TLS
without `-proxy-protocol`, with `-client-ip-header <the header your proxy
sets>`, and give users `ITTER_RELAY=https://…`.

**Local, no database, no SSH:**

```sh
# users.txt: one "username <authorized_keys line>" per line
echo "alice $(cat ~/.ssh/id_ed25519.pub)" > users.txt
go run ./cmd/itter-relay -mem -users users.txt          # listens on 127.0.0.1:8080
ITTER_RELAY=http://127.0.0.1:8080 go run ./cmd/itter
```

To try the way through the SSH app without a database, the itter app has
`python -m tests.dm_gate_server` (see its Readme).

`itter-relay -release <username>` frees an account whose owner lost both the
device and the recovery code.

## Building and testing

```sh
go build -o bin/ ./cmd/...                  # Go 1.27+: bin/itter, bin/itter-relay, bin/itter-release
go test ./...                               # a few minutes, FrodoKEM KATs included
go test ./internal/pqc -run '^$' -fuzz FuzzDecrypt -fuzztime 60s -fuzzminimizetime 2s
python3 scripts/installtest.py              # install.sh against a fake release
python3 scripts/viewtest.py <itter app> bin # the itter view in a terminal, against the app
```

On a Mac, double-click `run-on-mac.command`: vet, tests, a build, and an
end-to-end check with the built binaries against a local relay (two
accounts, a linked device, the real login keychain; it cleans up after
itself). If the itter app is in `../itter/itterapp`, it also runs the app's
DM entrance tests and sends messages the whole way: client, the app's SSH
server, relay. That part wants the app's SSH server to offer the
post-quantum key exchange; `upgrade-itter-venv.command` gets an older app
environment there. Results land in `_run/`.

Layout: `internal/pqc` (crypto and ratchets; `frodo/` is FrodoKEM),
`internal/vault` (encrypted local state), `internal/api` (wire contract),
`internal/server` (relay), `internal/relay` (relay client, and the way
through itter's SSH port), `internal/gatetest` (a stand-in for the SSH app's
entrance, for tests), `cmd/itter`, `cmd/itter-relay`.
