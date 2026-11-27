package main

import (
	"bufio"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/rrmn/itter-client/internal/api"
	"github.com/rrmn/itter-client/internal/pqc"
	"github.com/rrmn/itter-client/internal/relay"
	"github.com/rrmn/itter-client/internal/vault"
)

const usage = `itter — itter in your terminal, with private messages

` + "`itter`" + ` shows itter the way ssh would, logged in with your SSH key. In there,
type dm (or press Ctrl-]) for your direct messages, and Esc to come back.

DMs are end-to-end encrypted on this device, and post-quantum: a Triple
Ratchet (Signal's Double Ratchet with X25519, plus ML-KEM-768 and FrodoKEM-976
ratchets), identities signed with Ed25519 + ML-DSA-87 + SLH-DSA. No RSA.

everyday:
  itter                        open itter (dm inside opens your DMs)
  itter dms                    open just your DMs (type /help inside)
  itter dm @<user> <msg>       send one message and exit
  itter read [@<user>] [n]     fetch new messages; with @user show the last n
  itter contacts               who you talk to, and whether they are verified
  itter status                 account, relay connection, unread and unsent messages
  itter ignore [@<user>]       stop getting DMs from someone (itter's ignore list)
  itter unignore @<user>       undo that

trust:
  itter sn [@<user>]           your fingerprint, or the safety number with a contact
  itter verify @<user>         mark a contact as verified (you compared safety numbers)
  itter unverify @<user>       remove that mark
  itter accept @<user>         a contact shows a new identity: accept it
  itter reset @<user>          drop a stuck session and start a fresh one

account and devices:
  itter setup <username>       make this the account's first device (what the
                               first run does; RSA keys are refused)
  itter link <username>        add this device to an account that is already
                               set up elsewhere; shows a code for...
  itter approve <code>         ...the first device, which lets the new one in
  itter devices                the account's devices
  itter unlink <device id>     remove a linked device (on the first device)
  itter recovery-code          show the code that frees your account if the
                               first device is lost
  itter recover <username>     first device lost: release the account with that code
  itter burn [--force]         wipe this device; on the first device this also
                               releases the account's identity

The first time you open your DMs, itter sets this device up for them, with
the SSH key you log in to itter with. DMs travel through itter's own SSH port.

this program:
  itter version                its version, and the release key it trusts
  itter update [--check]       install the newest release (only if it is
                               signed with that key)

env:
  ITTER_HOST    itter's SSH server (default app.itter.sh:22)
  ITTER_KEY     the SSH key of your itter account, if it is not in ssh-agent
                or ~/.ssh/id_ed25519
  ITTER_DIR     state directory (default ~/.itter)
  ITTER_RELAY   talk to a relay directly at this http(s) address instead
`

func main() {
	if len(os.Args) < 2 {
		os.Exit(report(cmdItter()))
	}
	args := os.Args[2:]
	var err error
	switch os.Args[1] {
	case "dms":
		err = cmdShell()
	case "version", "--version", "-v":
		err = cmdVersion()
	case "update":
		err = cmdUpdate(args)
	case "setup":
		err = cmdSetup(args)
	case "burn":
		err = cmdBurn(args)
	case "recover":
		err = cmdRecover(args)
	case "recovery-code":
		err = cmdRecoveryCode()
	case "dm":
		err = cmdDM(args)
	case "read":
		err = cmdRead(args)
	case "contacts":
		err = cmdContacts()
	case "status":
		err = cmdStatus()
	case "link":
		err = cmdLink(args)
	case "approve":
		err = cmdApprove(args)
	case "devices":
		err = cmdDevices()
	case "unlink":
		err = cmdUnlink(args)
	case "ignore":
		err = cmdIgnore(args, true)
	case "unignore":
		err = cmdIgnore(args, false)
	case "safety-number", "sn":
		err = cmdSafetyNumber(args)
	case "verify", "pin":
		err = cmdTrust(args, "verify")
	case "unverify", "unpin":
		err = cmdTrust(args, "unverify")
	case "accept":
		err = cmdTrust(args, "accept")
	case "reset":
		err = cmdTrust(args, "reset")
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	os.Exit(report(err))
}

func report(err error) int {
	if err == nil {
		return 0
	}
	fmt.Fprintf(os.Stderr, "error: %s\n", explainLocal(err))
	return 1
}

// explainLocal is explain for errors that may not involve the relay at all.
func explainLocal(err error) string {
	var he *relay.HTTPError
	var ue *userErr
	var ne net.Error
	if errors.As(err, &he) || errors.As(err, &ue) || errors.As(err, &ne) {
		return explain(err)
	}
	return err.Error()
}

func configDir() string {
	if d := os.Getenv("ITTER_DIR"); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, ".itter")
	// Devices set up before the program was called itter-client keep their
	// state where it was.
	if old := filepath.Join(home, ".itter-cli"); !exists(dir) && exists(old) {
		return old
	}
	return dir
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// defaultHost is where itter's SSH server is found when ITTER_HOST does not
// say otherwise. DMs travel through that same port (see relay.Tunnel), so
// users need no second address.
const defaultHost = "app.itter.sh:22"

// hostKeyFile, in the state directory, remembers the SSH host key of itter's
// server.
const hostKeyFile = "itter_host_key"

// itterHost returns the address of itter's SSH server.
func itterHost() (string, error) {
	raw := strings.TrimSpace(os.Getenv("ITTER_HOST"))
	if raw == "" {
		raw = defaultHost
	}
	addr := raw
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(strings.Trim(addr, "[]"), "22")
	}
	host, port, err := net.SplitHostPort(addr)
	if n, perr := strconv.Atoi(port); err != nil || host == "" || perr != nil || n < 1 || n > 65535 {
		return "", userErrf("ITTER_HOST %q is not a host or host:port", raw)
	}
	return addr, nil
}

// newRelay returns the way to the DM relay. Normally that is itter's own SSH
// port. ITTER_RELAY names a relay to talk to directly instead, by its
// http(s) address: for a relay on this machine, and for the tests.
func newRelay() (*relay.Client, error) {
	if os.Getenv("ITTER_RELAY") != "" {
		base, err := relayURL()
		if err != nil {
			return nil, err
		}
		return relay.New(base), nil
	}
	t, err := itterTunnel()
	if err != nil {
		return nil, err
	}
	return relay.NewSSH(t), nil
}

// itterTunnel is the way to itter's SSH server, with its host key check:
// the one on record for this device, else the user's own known_hosts, else
// trust on first use.
func itterTunnel() (*relay.Tunnel, error) {
	addr, err := itterHost()
	if err != nil {
		return nil, err
	}
	t := &relay.Tunnel{Addr: addr, PinFile: filepath.Join(configDir(), hostKeyFile)}
	if home, err := os.UserHomeDir(); err == nil {
		t.KnownHosts = []string{filepath.Join(home, ".ssh", "known_hosts")}
	}
	return t, nil
}

// relayURL returns the relay ITTER_RELAY names. Plain http is only accepted
// for this machine: anywhere else it would show every passer-by who writes
// to whom, and let them meddle with the answers.
func relayURL() (string, error) {
	raw := strings.TrimRight(os.Getenv("ITTER_RELAY"), "/")
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", userErrf("ITTER_RELAY %q is not a valid http(s) URL", raw)
	}
	if u.Scheme == "http" && os.Getenv("ITTER_ALLOW_HTTP") != "1" {
		host := u.Hostname()
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return "", userErrf("refusing to talk to %s over plain http — use https (or set ITTER_ALLOW_HTTP=1 if you really mean it)", u.Host)
		}
	}
	return raw, nil
}

// open loads the vault and connects it to the relay.
func open() (*app, error) {
	rc, err := newRelay()
	if err != nil {
		return nil, err
	}
	v, err := vault.Open(configDir())
	if err != nil {
		return nil, err
	}
	if reg, keys := v.SetupState(); !reg || !keys {
		me, _ := v.Me()
		if v.IsLinked() {
			return nil, userErrf("linking this device to @%s did not finish — run `itter link %s` again", me, me)
		}
		return nil, userErrf("setup for @%s did not finish — run `itter setup %s` again", me, me)
	}
	linkedDevice.Store(v.IsLinked())
	return newApp(v, rc), nil
}

func randID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// --- setup, burn, recover ---

func printRecovery(code []byte) {
	fmt.Println()
	fmt.Println("  RECOVERY CODE — write it down and keep it away from this computer:")
	fmt.Println()
	fmt.Println("    " + api.FormatRecovery(code))
	fmt.Println()
	fmt.Println("  If this device is lost, `itter recover` with this code is the only way to")
	fmt.Println("  set up DMs for your account again. `itter recovery-code` shows it again.")
	fmt.Println()
}

// alreadySetUp is what setup reports when the account has a DM identity on
// another device.
type alreadySetUp struct{ msg string }

func (e *alreadySetUp) Error() string { return e.msg }
func (e *alreadySetUp) Unwrap() error { return &userErr{e.msg} }

func errAlreadySetUp(username string) error {
	return &alreadySetUp{fmt.Sprintf("@%s is already set up on another device. To use this one as well: `itter link %s`. To move the account here instead: `itter burn` on the other device (or, if it is gone, `itter recover %s` with your recovery code), then run setup again", username, username, username)}
}

func errNoSuchUser(username string) error {
	return userErrf("there is no itter user @%s — register on itter first (ssh register:%s@app.itter.sh)", username, username)
}

func cmdSetup(args []string) error {
	if len(args) < 1 {
		return userErrf("usage: itter setup <username>")
	}
	username := stripAt(args[0])
	if !api.ValidUsername(username) {
		return userErrf("%q is not a valid itter username", username)
	}
	done, err := setupDevice(username)
	if err != nil || !done {
		return err
	}
	fmt.Println("Run `itter` to chat. When you talk to someone, compare safety numbers")
	fmt.Println("(`itter sn @user`) over a channel you trust: that comparison is what")
	fmt.Println("proves who you are talking to, whatever else gets broken.")
	return nil
}

// setupDevice makes this the first device of an account, or finishes a
// setup that was interrupted. done is false if there was nothing to do.
func setupDevice(username string) (done bool, err error) {
	rc, err := newRelay()
	if err != nil {
		return false, err
	}
	dir := configDir()

	var v *vault.Vault
	if vault.Exists(dir) {
		if v, err = vault.Open(dir); err != nil {
			return false, err
		}
		me, _ := v.Me()
		if !strings.EqualFold(me, username) {
			return false, userErrf("this device is set up for @%s — `itter burn` first if you want to switch accounts", me)
		}
		if v.IsLinked() {
			return false, userErrf("this device is linked (or being linked) to @%s — finish with `itter link %s`, or `itter burn` first to start over", me, me)
		}
		if reg, keys := v.SetupState(); reg && keys {
			fmt.Printf("Already set up as @%s. Nothing to do.\n", me)
			return false, nil
		}
		fmt.Printf("Resuming setup for @%s...\n", me)
	}
	a := newApp(v, rc)
	if v == nil || !registered(v) {
		keys, err := findAccountKeys()
		if err != nil {
			return false, err
		}
		if v == nil {
			// Before anything is generated (and a recovery code shown that
			// would be worth nothing): is there something to set up?
			switch _, err := rc.Directory(username); {
			case err == nil:
				return false, errAlreadySetUp(username)
			case relay.Status(err) == http.StatusNotFound:
				return false, errNoSuchUser(username)
			case relay.Status(err) != http.StatusGone:
				return false, userErrf("%s. Nothing was set up", explain(err))
			}
			fmt.Println("Generating identity (Ed25519 + ML-DSA-87 + SLH-DSA-SHA2-256s, X25519)...")
			if v, err = vault.Create(dir, username); err != nil {
				return false, err
			}
			a.setVault(v)
		}
		if err := a.register(username, keys); err != nil {
			return false, err
		}
	}
	name, id := v.Me()

	fmt.Println("Generating prekeys (X25519 + ML-KEM-1024 + FrodoKEM-1344)...")
	if err := a.publishPreKeys(v.LatestSPK() == nil, otpkBatch); err != nil {
		return false, userErrf("could not publish prekeys: %s. Run `itter setup %s` again to finish", explainLocal(err), name)
	}
	err = v.Update(func() error {
		v.SetSetupState(true, true)
		v.SetKeyCheck(time.Now().Unix())
		return nil
	})
	if err != nil {
		return false, err
	}
	fmt.Printf("\nDone. This device is @%s.\nFingerprint: %s\n\n", name, pqc.Fingerprint(id.Pub.Encode()))
	return true, nil
}

// register binds this device's new identity to the itter account: a
// signature from an SSH key of the account, and the identity's own.
func (a *app) register(username string, keys *accountKeys) error {
	v := a.v
	_, id := v.Me()
	var code []byte
	if err := v.Update(func() (err error) { code, err = v.RecoveryCode(); return }); err != nil {
		return err
	}
	// Shown BEFORE registering: once the relay has the identity, this code is
	// the only way back in without this vault.
	printRecovery(code)

	idEnc := id.Pub.Encode()
	recKey, err := pqc.RecoveryPublic(code)
	if err != nil {
		return err
	}
	var name string
	fmt.Println("Registering...")
	err = keys.withAccountKeys(func(signers []ssh.Signer) error {
		ts := time.Now().Unix()
		payload := api.RegPayload(username, idEnc, recKey, ts)
		sigs, err := sshSigs(signers, payload, rand.Reader)
		if err != nil {
			return err
		}
		if len(sigs) == 0 {
			return userErrf("the SSH key refused to sign")
		}
		idSig, err := id.Sign.SignFull(payload, "dm-binding")
		if err != nil {
			return err
		}
		name, err = a.rc.Register(&api.RegReq{Username: username, Identity: idEnc, SSHSigs: sigs, IDSig: idSig, RecoveryKey: recKey, TS: ts})
		return err
	})
	if err != nil {
		if relay.Status(err) == 0 && isUserErr(err) {
			// A key that would not sign, a wrong passphrase: nothing reached the relay.
			return userErrf("%s. Your new identity is kept; run `itter setup %s` again", explain(err), username)
		}
		if retryable(err) || relay.Status(err) == http.StatusUnauthorized { // 401 here means: wrong clock
			// The relay may or may not have stored the identity. Keep it, so
			// that running setup again completes instead of locking us out.
			return userErrf("%s. Nothing is lost: run `itter setup %s` again to finish", explain(err), username)
		}
		_ = v.Burn() // definitively refused: this identity was never registered
		switch relay.Status(err) {
		case http.StatusConflict:
			return errAlreadySetUp(username)
		case http.StatusNotFound:
			return errNoSuchUser(username)
		case http.StatusForbidden:
			return userErrf("none of your SSH keys belongs to @%s on itter (RSA keys do not count). Looked in: %s. If the right key is somewhere else: ITTER_KEY=/path/to/key", username, strings.Join(keys.looked, ", "))
		}
		return userErrf("registration failed: %s", explain(err))
	}
	if !api.ValidUsername(name) || !strings.EqualFold(name, username) {
		name = username
	}
	return v.Update(func() error {
		v.SetSetupState(true, false)
		if me, _ := v.Me(); me != name {
			return v.SetUsername(name)
		}
		return nil
	})
}

func confirm(prompt, word string) bool {
	fmt.Print(prompt)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(line) == word
}

func cmdBurn(args []string) error {
	force := len(args) > 0 && args[0] == "--force"
	rc, err := newRelay()
	if err != nil {
		return err
	}
	v, err := vault.Open(configDir())
	legacy := errors.Is(err, vault.ErrLegacy)
	if err != nil && !legacy {
		return err
	}
	me, id := v.Me()
	if !legacy && v.IsLinked() {
		// A linked device only takes itself out; the account stays.
		if !confirm(fmt.Sprintf("This wipes all local messages and keys of @%s on THIS device. Your other devices keep working.\nType BURN to confirm: ", me), "BURN") {
			return userErrf("aborted, nothing was deleted")
		}
		if reg, _ := v.SetupState(); reg {
			err := rc.RetireDevice(relay.Auth{Username: me, ID: id})
			switch {
			case relay.Status(err) == http.StatusUnauthorized:
				// Unlinked already (or the account was set up from scratch).
			case err != nil && !force:
				return userErrf("could not tell the relay that this device is going away (%s). Nothing was deleted. Try again when the relay is reachable, or `itter burn --force`", explain(err))
			default:
				fmt.Println("Take it off your list too: `itter unlink " + short(v.DeviceID()) + "` on your first device.")
			}
		}
		if err := v.Burn(); err != nil {
			return err
		}
		fmt.Println("Local data shredded, keychain entry removed.")
		return nil
	}
	if !confirm(fmt.Sprintf("This releases @%s's DM identity and wipes all local messages and keys. Linked devices stop working too.\nType BURN to confirm: ", me), "BURN") {
		return userErrf("aborted, nothing was deleted")
	}
	if registered, _ := v.SetupState(); registered && !legacy {
		err := rc.Release(relay.Auth{Username: me, ID: id})
		if relay.Status(err) == http.StatusForbidden {
			// The relay refused our signature. If it holds a different identity
			// for the account by now (a recovery, the operator), there is
			// nothing of ours left to release.
			if d, derr := rc.Directory(me); derr == nil && !pqc.IdentityEqual(d.Identity, id.Pub.Encode()) {
				fmt.Printf("@%s has a different DM identity by now; this device's was no longer in use.\n", me)
				err = nil
			}
		}
		if err != nil {
			if !force {
				return userErrf("could not release @%s on the relay (%s). Nothing was deleted. Try again when the relay is reachable — or `itter burn --force`, after which only your recovery code can free the account", me, explain(err))
			}
			fmt.Printf("Warning: @%s is still registered on the relay (%s).\n", me, explain(err))
			if code, _ := v.RecoveryCode(); len(code) == 32 {
				fmt.Printf("To free the account later: `itter recover %s` with this code:\n  %s\n", me, api.FormatRecovery(code))
			}
		}
	}
	if err := v.Burn(); err != nil {
		return err
	}
	fmt.Println("Local data shredded, keychain entry removed.")
	return nil
}

func cmdRecoveryCode() error {
	v, err := vault.Open(configDir())
	if err != nil {
		return err
	}
	if v.IsLinked() {
		return userErrf("the recovery code belongs to the account's first device — run this there")
	}
	if reg, keys := v.SetupState(); !reg || !keys {
		return userErrf("setup did not finish — run `itter setup <username>` again; it shows the recovery code")
	}
	var code []byte
	if err := v.Update(func() (err error) { code, err = v.RecoveryCode(); return }); err != nil {
		return err
	}
	printRecovery(code)
	return nil
}

func cmdRecover(args []string) error {
	if len(args) < 1 {
		return userErrf("usage: itter recover <username>")
	}
	username := stripAt(args[0])
	if !api.ValidUsername(username) {
		return userErrf("%q is not a valid itter username", username)
	}
	rc, err := newRelay()
	if err != nil {
		return err
	}
	if vault.Exists(configDir()) {
		if name, err := vault.ReadUsername(configDir()); err == nil && strings.EqualFold(name, username) {
			return userErrf("this device still holds @%s's identity — use `itter burn` instead", name)
		}
	}
	fmt.Printf("This releases @%s's DM identity on the relay. The device that holds it\nstops working for DMs, and messages still waiting for it are deleted.\n", username)
	fmt.Print("Recovery code: ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	code, err := api.ParseRecovery(line)
	if err != nil {
		return &userErr{err.Error()}
	}
	// The code itself goes nowhere: it makes a signature, which is sent.
	err = rc.ReleaseWithCode(username, code)
	switch {
	case relay.Status(err) == http.StatusForbidden:
		return userErrf("that is not the recovery code for @%s", username)
	case relay.Status(err) == http.StatusNotFound:
		return userErrf("there is no itter user @%s", username)
	case err != nil:
		return err
	}
	fmt.Printf("Released. Now run `itter` on the device you want to use @%s on: it sets it up.\n", username)
	return nil
}

// --- trust ---

func cmdSafetyNumber(args []string) error {
	if len(args) == 0 {
		v, err := vault.Open(configDir())
		if err != nil {
			return err
		}
		me, _ := v.Me()
		if len(v.AccountIdentity()) == 0 {
			return userErrf("linking this device to @%s did not finish — run `itter link %s` again", me, me)
		}
		fmt.Printf("Fingerprint of @%s (the same on all your devices):\n  %s\n", me, pqc.Fingerprint(v.AccountIdentity()))
		return nil
	}
	a, err := open()
	if err != nil {
		return err
	}
	for _, line := range a.safetyReport(args[0]) {
		fmt.Println(line)
	}
	return nil
}

// safetyReport describes the identity situation with one contact.
func (a *app) safetyReport(who string) []string {
	peer := a.resolve(who)
	if !api.ValidUsername(peer) {
		return []string{fmt.Sprintf("%q is not a valid itter username", peer)}
	}
	info, known := a.v.ContactInfo(peer)
	dir, berr := a.directory(peer)
	var out []string
	if !known {
		switch {
		case berr != nil:
			return []string{fmt.Sprintf("No conversation with @%s yet, and %s.", peer, explain(berr))}
		case dir == nil:
			return []string{fmt.Sprintf("@%s has not set up DMs (or is not an itter user).", peer)}
		}
		return []string{
			fmt.Sprintf("No conversation with @%s yet. If you start one now, the safety number will be:", dir.name),
			"  " + a.safetyNumber(dir.identity),
		}
	}
	state := "NOT verified"
	if info.Verified {
		state = "verified"
	}
	out = append(out,
		fmt.Sprintf("Safety number with @%s (%s):", peer, state),
		"  "+a.safetyNumber(info.Identity),
		fmt.Sprintf("Compare it with @%s in person or over a channel you trust; if it matches: verify @%s", peer, peer))
	if info.Devices > 1 {
		out = append(out, fmt.Sprintf("@%s uses %d devices; the number above covers all of them.", peer, info.Devices))
	}
	if info.HasSession {
		out = append(out, fmt.Sprintf("Post-quantum ratchet steps so far: ML-KEM %d, FrodoKEM %d", info.MLKEM, info.Frodo))
		if info.Stalled != "" {
			out = append(out, fmt.Sprintf("Warning: a post-quantum ratchet is stalled (%s). `reset @%s` starts a fresh session.", info.Stalled, peer))
		}
	}
	if len(info.Pending) > 0 {
		out = append(out,
			fmt.Sprintf("A DIFFERENT identity claims to be @%s (%d message(s) held). Its safety number would be:", peer, info.Held),
			"  "+a.safetyNumber(info.Pending),
			fmt.Sprintf("Only if that matches what @%s shows: accept @%s", peer, peer))
	} else if berr == nil && dir != nil && !pqc.IdentityEqual(dir.identity, info.Identity) {
		out = append(out,
			fmt.Sprintf("Note: the relay now lists a different identity for @%s. Its safety number would be:", peer),
			"  "+a.safetyNumber(dir.identity))
	}
	return out
}

func cmdTrust(args []string, what string) error {
	if len(args) < 1 {
		return userErrf("usage: itter %s @<user>", what)
	}
	a, err := open()
	if err != nil {
		return err
	}
	var msg string
	switch what {
	case "verify":
		peer := a.resolve(args[0])
		info, known := a.v.ContactInfo(peer)
		if !known {
			return userErrf("no conversation with @%s yet — exchange a message first", peer)
		}
		if !(len(args) > 1 && args[1] == "--yes") {
			// Verifying means: this exact number was compared. Show it.
			fmt.Printf("Safety number with @%s:\n  %s\n", peer, a.safetyNumber(info.Identity))
			if !confirm(fmt.Sprintf("Does @%s see exactly the same number on their device? Type YES: ", peer), "YES") {
				return userErrf("not marked as verified")
			}
		}
		msg, err = a.setVerified(peer, true)
	case "unverify":
		msg, err = a.setVerified(args[0], false)
	case "reset":
		msg, err = a.reset(args[0])
	case "accept":
		msg, err = a.accept(args[0])
	}
	if err != nil {
		return err
	}
	fmt.Println(msg)
	return nil
}

func contactLine(c vault.ContactInfo) string {
	state := "unverified"
	switch {
	case len(c.Pending) > 0:
		state = "IDENTITY CHANGE PENDING"
	case c.Verified:
		state = "verified"
	case len(c.Identity) == 0:
		state = "no session"
	}
	last := "-"
	if c.LastTS > 0 {
		last = timeAgo(c.LastTS)
	}
	return fmt.Sprintf("@%-20s  %-24s  last message: %s", c.Name, state, last)
}

func cmdContacts() error {
	v, err := vault.Open(configDir())
	if err != nil {
		return err
	}
	list := v.ContactList()
	if len(list) == 0 {
		fmt.Println("No conversations yet. Start one: itter dm @user hello")
		return nil
	}
	for _, c := range list {
		fmt.Println(contactLine(c))
	}
	return nil
}

// cmdStatus answers "is everything all right?" in a few lines.
func cmdStatus() error {
	a, err := open()
	if err != nil {
		return err
	}
	me, _ := a.v.Me()
	fmt.Printf("Account:      @%s\n", me)
	fmt.Printf("Fingerprint:  %s\n", pqc.Fingerprint(a.v.AccountIdentity()))
	role, others := "first device (holds the account identity)", 0
	if a.v.IsLinked() {
		role = "linked device"
	}
	if l := a.v.OwnDevices(); l != nil {
		others = len(l.Keys)
	}
	fmt.Printf("This device:  %s, %s", short(a.v.DeviceID()), role)
	if others > 0 {
		fmt.Printf(" — %d devices on the account (itter devices)", others+1)
	}
	fmt.Println()
	fmt.Printf("State:        %s\n", a.v.Dir())
	fmt.Printf("Relay:        %s — ", a.rc.Where())
	var ferr error
	if left, err := a.rc.KeyCount(a.auth()); err != nil {
		ferr = err
		fmt.Printf("PROBLEM: %s\n", explain(err))
	} else {
		fmt.Printf("connected, it knows this device (%d one-time prekeys left)\n", left)
		if t := a.rc.Tunnel; t != nil && t.KeyExchange() != "" {
			// For the curious. DMs are protected end to end either way.
			kind := "classical"
			if t.KeyExchange() == relay.PostQuantumKex {
				kind = "post-quantum"
			}
			fmt.Printf("Connection:   SSH, %s key exchange (%s)\n", kind, t.KeyExchange())
		}
		ferr = a.flush() // anything still waiting goes out now
	}
	var unverified, pending []string
	list := a.v.ContactList()
	for _, c := range list {
		switch {
		case len(c.Pending) > 0:
			pending = append(pending, "@"+c.Name)
		case len(c.Identity) > 0 && !c.Verified:
			unverified = append(unverified, "@"+c.Name)
		}
	}
	fmt.Printf("Contacts:     %d", len(list))
	if len(unverified) > 0 {
		fmt.Printf(", %d not verified", len(unverified))
	}
	fmt.Println()
	for _, name := range pending {
		fmt.Printf("DECISION NEEDED: %s shows a new identity — compare `itter sn %s`, then `itter accept %s`\n", name, name, name)
	}
	read, unread := a.v.ReadCounts(), 0
	for name, msgs := range a.v.GetAllMessages() {
		for i := min(read[name], len(msgs)); i < len(msgs); i++ {
			if !msgs[i].IsOut {
				unread++
			}
		}
	}
	if unread > 0 {
		fmt.Printf("Unread:       %d — itter read\n", unread)
	}
	unsent := 0
	for _, q := range a.v.OutboxSnapshot() {
		if q.Target != me { // copies for one's own devices do not count
			unsent++
		}
	}
	if unsent > 0 {
		why := ""
		if ferr != nil {
			why = " (" + explain(ferr) + ")"
		}
		fmt.Printf("Not sent yet: %d message(s)%s — they go out the next time itter reaches the relay (read, dm, status or the open shell)\n", unsent, why)
	}
	return nil
}

// --- one-shot messaging ---

func cmdDM(args []string) error {
	if len(args) < 2 {
		return userErrf("usage: itter dm @<user> <msg>")
	}
	a, err := open()
	if err != nil {
		return err
	}
	// Catch up first: replies move the ratchets forward (and end the phase in
	// which every message has to carry the 120 KB handshake).
	if n, perr := a.pull(0); perr == nil {
		_ = a.maintain()
		if n > 0 {
			defer fmt.Println("You have new messages: itter read")
		}
	}
	out, err := a.send(args[0], strings.Join(args[1:], " "))
	if err != nil {
		return err
	}
	switch out.Status {
	case vault.StatusSent:
		fmt.Printf("Sent to @%s.\n", out.Target)
	case vault.StatusQueued:
		fmt.Printf("Queued for @%s — %s. It is sent the next time itter runs.\n", out.Target, out.Note)
	default:
		// The notices that came with the failure say why and what to do.
		msgs := a.v.GetMessages(out.Target)
		i := len(msgs)
		for i > 0 && msgs[i-1].IsSystem {
			i--
		}
		for _, m := range msgs[i:] {
			fmt.Println(clean(m.Text))
		}
		return userErrf("NOT delivered to @%s", out.Target)
	}
	return nil
}

func termWidth() int {
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 20 {
		return w
	}
	return 100
}

// say prints a line of one-shot output: coloured on a terminal, plain when
// piped (itter read | grep …) or when NO_COLOR is set.
func say(line string) {
	if !term.IsTerminal(int(os.Stdout.Fd())) || os.Getenv("NO_COLOR") != "" {
		line = plain(line)
	}
	fmt.Println(line)
}

func cmdRead(args []string) error {
	a, err := open()
	if err != nil {
		return err
	}
	me, _ := a.v.Me()
	perr := a.flush()
	if perr == nil || relay.Status(perr) != 0 { // unless the relay cannot be reached at all
		if _, perr = a.pull(0); perr == nil {
			_ = a.maintain()
		}
	}
	width := termWidth()
	show := func(peer string, msgs []vault.ChatMsg) {
		userW := labelWidth("@"+peer, "@"+me)
		for _, m := range msgs {
			label := "@" + peer
			if m.IsOut {
				label = "@" + me
			}
			for _, line := range formatEetLines(label, m.IsOut, m, userW, width) {
				say(line)
			}
		}
	}
	all := a.v.GetAllMessages()
	read := a.v.ReadCounts()
	seen := map[string]int{}
	if len(args) > 0 {
		peer := a.resolve(args[0])
		n := 20
		if len(args) > 1 {
			if v, err := strconv.Atoi(args[1]); err == nil && v > 0 {
				n = v
			}
		}
		msgs := all[peer]
		if len(msgs) == 0 {
			fmt.Printf("No messages with @%s.\n", peer)
		}
		seen[peer] = len(msgs)
		if unread := len(msgs) - read[peer]; unread > n {
			n = unread // never hide something new
		}
		if len(msgs) > n {
			msgs = msgs[len(msgs)-n:]
		}
		show(peer, msgs)
	} else {
		var names []string
		for name, msgs := range all {
			news := false
			for _, m := range msgs[min(read[name], len(msgs)):] {
				news = news || !m.IsOut // what I sent myself is not news
			}
			if news {
				names = append(names, name)
			} else if len(msgs) > read[name] {
				seen[name] = len(msgs)
			}
		}
		sort.Strings(names)
		for _, name := range names {
			say(fmt.Sprintf("%s--- @%s ---%s", Bold, clean(name), Reset))
			show(name, all[name][min(read[name], len(all[name])):])
			seen[name] = len(all[name])
		}
		if len(names) == 0 && perr == nil {
			fmt.Println("No new messages.")
		}
	}
	if len(seen) > 0 {
		if err := a.v.Update(func() error { a.v.MarkRead(seen); return nil }); err != nil {
			return err
		}
	}
	if perr != nil {
		return userErrf("could not check for new messages: %s", explain(perr))
	}
	return nil
}
