# itter-client — itter in your terminal, with private messages

`itter` is [itter](https://github.com/rrmn/itter) as you know it from `ssh`,
plus **direct messages that only you and the people you write to can read**:
end-to-end encrypted on your own computer, and post-quantum. Messages are
protected by a Triple Ratchet (Signal's Double Ratchet plus two sparse
post-quantum ratchets) built so that it still holds if RSA, elliptic curves
**and** structured lattices are all broken: the load-bearing parts are
FrodoKEM, SLH-DSA and symmetric crypto. No RSA anywhere.
[PROTOCOL.md](PROTOCOL.md) has the details and the known limits.

## Install

```sh
curl -fsSL https://itter.sh/install | sh
```

macOS and Linux, Apple silicon / ARM and Intel / AMD. It puts `itter` in a
folder on your PATH, without sudo (if that folder is not on your PATH yet, it
adds it in your shell's startup file and says so), and starts it.
`itter.sh/install` leads to [install.sh](install.sh) in the newest release:
read it first with `curl -fsSL https://itter.sh/install | less`. Settings go
after the `|`: `| ITTER_START=0 sh` installs without starting itter,
`| ITTER_PATH=0 sh` leaves your startup files alone.

Later updates: `itter update`. It installs a release only if it is signed
with itter's **release key**, which is post-quantum too (Ed25519 + ML-DSA-87 +
SLH-DSA): not GitHub, not HTTPS, nobody in between can slip in another
program. `itter version` shows the key's fingerprint; it must be

    6272 705b 6200 d258 80dd 12c9 7db1 911b

Only the very first download is taken on trust. To check it yourself, see
[Checking a release](#checking-a-release).

## Using it

```sh
itter
```

The first time (the installer starts it for you), it asks for your itter
username (a new one signs you up) and logs in with the SSH key you use for
itter: from ssh-agent, or `~/.ssh/id_ed25519` / `id_ecdsa` (RSA keys are
refused). From then on it *is* itter: everything works as over `ssh`.

**Your DMs:** type `dm` (or `dm @user`), or press **Ctrl-]**. **Esc** brings
you back to itter, which kept going meanwhile. New DMs show in the terminal's
title. The first time, `dm` sets this computer up for DMs, with one more
signature from your SSH key, which shows the DM relay that the account is
yours. Setup prints a **recovery code**. Write it down: it is the only way to
free your account if this computer is lost.

`itter dms` opens just the DMs. With plain `ssh`, itter's `dm` tells you how
to get this program: DMs cannot live inside the SSH app itself, because
whatever is typed into an SSH session passes through the server in the clear.
The keys have to stay on your computer, which is what this program is for.

**More devices.** Run `itter` on the new device, log in, and type `dm`. It
notices that the account already uses DMs, offers to add the device, and shows
a one-time code. Type that code on your first device:

```sh
itter approve <code>                # in the shell: /approve <code>
```

From then on both devices receive everything and see what the other one
sent. Nothing secret is copied between them, and your contacts' safety number
for you stays the same. Up to five devices. `itter devices` lists them,
`itter unlink <id>` (on the first device) removes one, `itter burn` on a linked
device takes just that device out. Earlier messages are not copied to a new
device, and contacts you verified have to be verified there again. Unlink
devices you no longer use: as long as a device is listed, everything is also
encrypted for it.

In the DMs, `@user hello` writes to someone, `/chat @user` opens a chat
(then everything you type is sent), Tab completes commands and names, `/help`
lists the rest. One-shot commands for scripts and quick use:

| | |
|---|---|
| `itter dm @user <msg>` | send one message |
| `itter read` | show what is new (`itter read @user 50` for history) |
| `itter status` | account, relay connection, unread and unsent messages |
| `itter contacts` | who you talk to, and whether they are verified |
| `itter ignore @user` | stop getting DMs from someone; `itter unignore @user` undoes it |
| `itter sn @user` | safety number to compare with that person |
| `itter verify @user` | you compared it and it matched |
| `itter accept @user` | a contact shows a new identity: accept it |
| `itter reset @user` | drop a stuck session, start a fresh one |
| `itter devices` | the devices of your account |
| `itter recovery-code` | show the recovery code again (first device) |
| `itter recover <username>` | first device lost: free the account with the code |
| `itter burn` | wipe this device; on the first device this also releases your identity |
| `itter dms` | open just the DMs |
| `itter version` | this program's version and release key |
| `itter update` | install the newest release (`--check` only looks) |

**Safety numbers.** The relay tells you which identity belongs to an account;
the first one is taken on trust. To be sure nobody sits in the middle, compare
the number from `itter sn @user` with the other person over a channel you
trust, then `itter verify @user`.

**When a contact's identity changes** (they set up from scratch — or an
attack), the chat stops: nothing is sent, their new messages are held unread,
and you are shown the new safety number. `itter accept @user` continues with
the new identity; until then nothing changes. A contact who merely *links*
another device keeps their identity: you get a one-line note and nothing else
changes.

**Ignoring.** `itter ignore @user` uses itter's own ignore list (the same one
as `ignore` on itter). Their DMs are dropped at the relay and they are not
told.

Environment: `ITTER_HOST` (itter's SSH server, default `app.itter.sh:22`),
`ITTER_KEY` (the SSH key of your itter account, if it is neither in ssh-agent
nor in the usual files), `ITTER_DIR` (state directory, default
`~/.itter`), `ITTER_KEYFILE=1` (keep the vault key in a file — for
machines without a system keychain), `ITTER_BELL=0` (no bell when a DM
arrives), `NO_COLOR`. `ITTER_RELAY` makes the
client talk to a relay directly at an http(s) address instead of going
through itter (plain http is refused except for localhost).

`itter setup <username>` and `itter link <username>` do by hand what the first
`dm` does by itself; scripts use them.

## Checking a release

Every release has `SHA256SUMS`, signed in `SHA256SUMS.sig` with the release
key, whose public half is [`release-key.pub`](release-key.pub) here (and built
into the program). To check a release without trusting the program you
downloaded, with Go 1.27.1 and this repository at the release's tag:

```sh
go run ./cmd/itter-release verify release-key.pub SHA256SUMS   # next to SHA256SUMS.sig
scripts/build-release.sh v1.2.3 <the tag's commit> out/        # builds it again
diff out/SHA256SUMS SHA256SUMS                                 # same files, byte for byte
```

Builds are reproducible: the same source and Go version give the same files.
The fingerprint above, compared with what someone else sees (on the itter
website, from a friend), makes sure `release-key.pub` is the right key.

`https://itter.sh/install` is a redirect on itter's website to `install.sh` of
the newest release. To leave the website out of the first download, take it
from GitHub directly:
`curl -fsSL https://github.com/rrmn/itter-client/releases/latest/download/install.sh | sh`.


## Running a relay

**Next to itter (production).** The relay listens on the machine that runs
itter's SSH app, for that app only:

1. Run `supabase/dm_relay.sql` (SQL editor of itter's Supabase project). It
   only adds `dm_*` tables and functions, readable by the service role only;
   the relay also reads and writes itter's `ignored_users`. Running it again is
   safe. Over the tables of an earlier version (one device per account) it
   replaces them if they are empty and stops with an error if they hold data.
2. Check the store against the real project before going live:
   ```sh
   ITTER_TEST_POSTGREST_URL=https://<project>.supabase.co/rest/v1 \
   ITTER_TEST_POSTGREST_KEY=<service role key> \
   go test ./internal/server -run TestStoreConformance -v
   ```
   (It creates and removes two `dmtest_…` users and touches nothing else.
   **This has not been run against a real Supabase project yet.**)
3. Start the relay where the itter app runs:
   ```sh
   itter-relay -proxy-protocol            # listens on 127.0.0.1:8080
   ```
   It needs `SUPABASE_URL` and `SUPABASE_KEY` (the service role key), from the
   environment or from a `.env` file in the folder it starts from; the itter
   app's own `.env` already has both. Add `ITTER_TOKEN_KEY` (make it once with
   `openssl rand -hex 32`) so that sessions survive a restart; without it
   every client has to prove itself again afterwards, which it does by
   itself. Run a single instance. With systemd, for example:
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
   That opens the entrance: SSH user `dm`, which needs no login, gets no
   shell and can reach nothing but the relay (`itter/ssh/dm_gate.py` in the
   itter app). The relay authenticates every request itself, as it would on a
   public address. `-proxy-protocol` makes it take each client's real address
   from the line the app sends first, so rate limits count real clients; in
   that mode it must not be reachable by anything but the app.
5. If itter's SSH server is not `app.itter.sh:22`, set `defaultHost` in
   `cmd/itter/main.go` and build the client.
6. Optional, and good for itter as a whole: bring the app's asyncssh to
   2.24.1 or newer (`pip install -U "asyncssh>=2.24.1,<3.0.0"` in its
   environment; its `requirements.txt` asks for that now). Its SSH server then
   offers the post-quantum key exchange that recent OpenSSH clients warn
   about when it is missing, and the DM client takes it by itself:
   `itter status` says which key exchange the connection got. DMs do not
   depend on it either way.

**On a public address of its own** (no SSH in between) the relay works as
well: start it behind TLS without `-proxy-protocol`, with
`-client-ip-header <the header your proxy sets>`, and give users
`ITTER_RELAY=https://…`.

**Local, self-contained** (no database, no SSH):

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
go build -o bin/ ./cmd/...                  # Go 1.27+; bin/itter, bin/itter-relay, bin/itter-release
go test ./...                               # a few minutes; includes the FrodoKEM KATs
go test ./internal/pqc -run '^$' -fuzz FuzzDecrypt -fuzztime 60s -fuzzminimizetime 2s
```

On a Mac, double-click `run-on-mac.command`: it runs vet, the tests and a
build, then an end-to-end check with the built binaries against a local
relay (two accounts, a linked device, the real login keychain; everything it
creates is removed again). If the itter app is found in `../itter/itterapp`,
it also runs that app's tests for the DM entrance and sends messages the
whole way: this client, the app's SSH server, the relay. That part expects
the app's SSH server to offer the post-quantum key exchange;
`upgrade-itter-venv.command` brings an older Python environment of the app
up to that. Results are in `_run/`.

Layout: `internal/pqc` (crypto and ratchets, `frodo/` is FrodoKEM),
`internal/vault` (encrypted local state), `internal/api` (wire contract),
`internal/server` (relay), `internal/relay` (relay client, and the way
through itter's SSH port), `internal/gatetest` (a stand-in for the SSH app's
entrance, for tests), `cmd/itter`, `cmd/itter-relay`.
