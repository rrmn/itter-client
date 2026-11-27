package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"itter-cli/internal/api"
	"itter-cli/internal/pqc"
	"itter-cli/internal/relay"
	"itter-cli/internal/vault"
)

// An account's first device holds the account identity. Further devices are
// linked to it: each has a key of its own, and the first device signs the
// list that names them. Linking moves nothing secret between devices; what
// the user carries over is a one-time code that lets each side check that
// the relay showed it the other's real key.

var (
	linkPoll    = 3 * time.Second
	linkTimeout = 10 * time.Minute
)

func short(deviceID string) string {
	if len(deviceID) > 8 {
		return deviceID[:8]
	}
	return deviceID
}

// cmdLink runs on the NEW device.
func cmdLink(args []string) error {
	if len(args) < 1 {
		return userErrf("usage: itter link <username>   (on a new device; the account must already be set up on another one)")
	}
	username := stripAt(args[0])
	if !api.ValidUsername(username) {
		return userErrf("%q is not a valid itter username", username)
	}
	rc, err := newRelay()
	if err != nil {
		return err
	}
	return linkDevice(configDir(), rc, username)
}

func linkDevice(dir string, rc *relay.Client, username string) error {
	var v *vault.Vault
	var err error
	if vault.Exists(dir) {
		if v, err = vault.Open(dir); err != nil {
			return err
		}
		me, _ := v.Me()
		switch reg, keys := v.SetupState(); {
		case !v.IsLinked():
			return userErrf("this device is already set up as the first device of @%s — `itter burn` first if you want to link it to an account instead", me)
		case !strings.EqualFold(me, username):
			return userErrf("this device is being linked to @%s — `itter burn` first if you want to switch accounts", me)
		case reg && keys:
			fmt.Printf("Already linked as @%s. Nothing to do.\n", me)
			return nil
		}
	}
	a := newApp(nil, rc)
	if v == nil || !registered(v) {
		// The request needs a signature from an SSH key of the itter account,
		// like a setup does.
		keys, err := findAccountKeys()
		if err != nil {
			return err
		}
		if v == nil {
			fmt.Println("Generating this device's key (Ed25519 + ML-DSA-87 + SLH-DSA-SHA2-256s, X25519)...")
			if v, err = vault.CreateLinked(dir, username); err != nil {
				return err
			}
		}
		a.setVault(v)
		if err := a.requestLink(username, keys); err != nil {
			return err
		}
	}
	a.setVault(v)
	name, _ := v.Me()
	if _, keys := v.SetupState(); !keys {
		fmt.Println("Generating prekeys (X25519 + ML-KEM-1024 + FrodoKEM-1344)...")
		if err := a.publishPreKeys(v.LatestSPK() == nil, otpkBatch); err != nil {
			return userErrf("could not publish prekeys: %s. Run `itter link %s` again to finish", explainLocal(err), name)
		}
		err := v.Update(func() error {
			v.SetSetupState(true, true)
			v.SetKeyCheck(time.Now().Unix())
			return nil
		})
		if err != nil {
			return err
		}
	}
	fmt.Printf("\nLinked. This device is @%s now, next to your other device(s).\n", name)
	fmt.Printf("Account fingerprint: %s\n\n", pqc.Fingerprint(v.AccountIdentity()))
	fmt.Println("Messages from now on arrive on all your devices; earlier ones stay where they were read.")
	fmt.Println("Contacts you verified on another device are not marked as verified here yet.")
	return nil
}

func registered(v *vault.Vault) bool {
	reg, _ := v.SetupState()
	return reg
}

// requestLink files the request, shows the code and waits for the first
// device's answer.
func (a *app) requestLink(username string, keys *accountKeys) error {
	v := a.v
	_, id := v.Me()
	var secret []byte
	if err := v.Update(func() (err error) { secret, err = v.LinkCode(); return }); err != nil {
		return err
	}
	key, linkID := id.Pub.Encode(), pqc.LinkID(secret)
	err := keys.withAccountKeys(func(signers []ssh.Signer) error {
		ts := time.Now().Unix()
		req := &api.LinkReq{LinkID: linkID, DeviceKey: key, Tag: pqc.LinkRequestTag(secret, username, key), TS: ts}
		sigs, err := sshSigs(signers, api.LinkPayload(username, linkID, key, ts), rand.Reader)
		if err != nil {
			return err
		}
		if len(sigs) == 0 {
			return userErrf("the SSH key refused to sign")
		}
		req.SSHSigs = sigs
		return a.rc.LinkRequest(username, req)
	})
	if err != nil {
		switch relay.Status(err) {
		case http.StatusNotFound:
			_ = v.Burn()
			return userErrf("there is no itter user @%s", username)
		case http.StatusGone:
			_ = v.Burn()
			return userErrf("@%s has no DM identity yet, so there is nothing to link to. Run `itter` here instead: this device becomes the first one", username)
		case http.StatusForbidden:
			return userErrf("none of your SSH keys belongs to @%s on itter (RSA keys do not count). Looked in: %s. If the right key is somewhere else: ITTER_KEY=/path/to/key", username, strings.Join(keys.looked, ", "))
		}
		return userErrf("%s. Run `itter link %s` again", explain(err), username)
	}

	fmt.Println()
	fmt.Println("  LINK CODE — type it on a device that is already set up:")
	fmt.Println()
	fmt.Println("    itter approve " + api.FormatRecovery(secret))
	fmt.Println()
	fmt.Println("  (in the itter shell: /approve <code>). The code is used once and is")
	fmt.Println("  worthless afterwards. Do not send it through anything you do not trust:")
	fmt.Println("  whoever has it while this device waits could link a device of their own.")
	fmt.Println()
	fmt.Println("Waiting for the other device...")

	deadline := time.Now().Add(linkTimeout)
	for {
		raw, err := a.rc.LinkResult(username, linkID)
		switch {
		case relay.Status(err) == http.StatusNotFound:
			return userErrf("the request expired. Run `itter link %s` again for a new waiting period (the code stays the same)", username)
		case err == nil && len(raw) > 0:
			return a.finishLink(username, secret, raw)
		}
		if time.Now().After(deadline) {
			return userErrf("nobody answered yet. Run `itter link %s` again to keep waiting (the code stays the same)", username)
		}
		time.Sleep(linkPoll)
	}
}

// finishLink checks the first device's answer with the one-time code. Only
// an answer made by someone who knows the code is believed, so the relay
// cannot slip in an account identity of its own.
func (a *app) finishLink(username string, secret, raw []byte) error {
	v := a.v
	_, id := v.Me()
	key := id.Pub.Encode()
	var res api.LinkResult
	bad := func(why string) error {
		return userErrf("the answer did not check out (%s). Nothing was linked. If this happens again, someone is interfering with the relay", why)
	}
	if json.Unmarshal(raw, &res) != nil || res.List == nil {
		return bad("it is malformed")
	}
	if !pqc.TagEqual(res.Tag, pqc.LinkResultTag(secret, username, res.Identity, key, res.List.V)) {
		return bad("it was not made with this code")
	}
	if !api.ValidUsername(res.Username) || !strings.EqualFold(res.Username, username) {
		return bad("it is for a different account")
	}
	if err := res.List.Verify(res.Identity, res.Username); err != nil || !res.List.Has(key) {
		return bad("the device list is not valid or does not name this device")
	}
	return v.Update(func() error {
		if me, _ := v.Me(); me != res.Username {
			if err := v.SetUsername(res.Username); err != nil {
				return err
			}
		}
		v.SetOwnDevices(res.Identity, res.List, nil)
		v.SetSetupState(true, false)
		return nil
	})
}

// approve runs on the FIRST device: it checks the request with the code,
// puts the new device on the signed list and answers.
func (a *app) approve(secret []byte) (string, error) {
	me, id := a.v.Me()
	if a.v.IsLinked() {
		return "", userErrf("devices are approved on the account's first device (this one was linked itself)")
	}
	linkID := pqc.LinkID(secret)
	info, err := a.rc.LinkInfo(a.auth(), linkID)
	switch {
	case relay.Status(err) == http.StatusNotFound:
		return "", userErrf("no device is waiting with that code. Check it, or run `itter link %s` on the new device again (a request waits 15 minutes)", me)
	case err != nil:
		return "", err
	}
	if _, err := pqc.DecodeIdentityKey(info.DeviceKey); err != nil || !pqc.TagEqual(info.Tag, pqc.LinkRequestTag(secret, me, info.DeviceKey)) {
		return "", userErrf("the request the relay shows was not made with this code. Nothing was linked")
	}
	account := id.Pub.Encode()
	var list *pqc.DeviceList
	err = a.v.Update(func() error {
		cur := a.v.OwnDevices()
		if cur.Has(info.DeviceKey) {
			list = cur // approved before; the answer may not have arrived
			return nil
		}
		var keys [][]byte
		if cur != nil {
			keys = append(keys, cur.Keys...)
		}
		if len(keys) >= pqc.MaxLinkedDevices {
			return userErrf("@%s already has %d devices, the most an account can have. `itter unlink` one first", me, len(keys)+1)
		}
		l, err := pqc.SignDeviceList(id, me, cur.Version()+1, append(keys, info.DeviceKey))
		if err != nil {
			return err
		}
		a.v.SetOwnDevices(account, l, a.v.Reach(me))
		a.v.SetListUploaded(false)
		list = l
		return nil
	})
	if err != nil {
		return "", err
	}
	again := "The device is on your list already; run the same command again to finish"
	if err := a.rc.SetDevices(a.auth(), list); err != nil {
		return "", userErrf("%s. %s", explain(err), again)
	}
	if err := a.v.Update(func() error { a.v.SetListUploaded(true); return nil }); err != nil {
		return "", err
	}
	res, _ := json.Marshal(api.LinkResult{Username: me, Identity: account, List: list,
		Tag: pqc.LinkResultTag(secret, me, account, info.DeviceKey, list.V)})
	if err := a.rc.LinkAnswer(a.auth(), linkID, res); err != nil {
		return "", userErrf("%s. %s", explain(err), again)
	}
	return fmt.Sprintf("Linked device %s. It can read and send as @%s from now on (%d devices in total). `devices` lists them, `unlink` removes one.",
		short(pqc.IdentityID(info.DeviceKey)), me, len(list.Keys)+1), nil
}

// deviceLines describes the account's devices.
func (a *app) deviceLines() ([]string, error) {
	me, _ := a.v.Me()
	r, err := a.rc.Devices(a.auth())
	if err != nil {
		return nil, err
	}
	self := a.v.DeviceID()
	out := []string{fmt.Sprintf("Devices of @%s:", me)}
	for i, d := range r.Devices {
		kind := "linked device"
		if d.Primary {
			kind = "first device (holds the account identity)"
		}
		state := ""
		if !d.Ready {
			state = " · not receiving (no prekeys published)"
		}
		this := ""
		if d.ID == self {
			this = " · this one"
		}
		out = append(out, fmt.Sprintf("  %d. %s  %s%s%s", i+1, short(d.ID), kind, this, state))
	}
	if len(r.Devices) == 1 {
		out = append(out, "To add one: run `itter link "+me+"` on the new device.")
	}
	return out, nil
}

// unlink takes a linked device off the account's list. From then on nobody
// who has seen the new list accepts it, and the relay drops what it held
// for it.
func (a *app) unlink(prefix string) (string, error) {
	me, id := a.v.Me()
	if a.v.IsLinked() {
		return "", userErrf("devices are removed on the account's first device. To take this device out, run `itter burn` here")
	}
	prefix = strings.ToLower(strings.TrimSpace(prefix))
	var list *pqc.DeviceList
	var gone string
	err := a.v.Update(func() error {
		cur := a.v.OwnDevices()
		var keep [][]byte
		matches := 0
		if cur != nil {
			for _, k := range cur.Keys {
				if dev := pqc.IdentityID(k); prefix != "" && strings.HasPrefix(dev, prefix) {
					matches++
					gone = dev
				} else {
					keep = append(keep, k)
				}
			}
		}
		switch {
		case matches == 0:
			return userErrf("no linked device starts with %q — `itter devices` shows them", prefix)
		case matches > 1:
			return userErrf("%q matches %d devices — give more of the id", prefix, matches)
		}
		l, err := pqc.SignDeviceList(id, me, cur.Version()+1, keep)
		if err != nil {
			return err
		}
		var reach []string
		for _, dev := range a.v.Reach(me) {
			if dev != gone {
				reach = append(reach, dev)
			}
		}
		a.v.SetOwnDevices(id.Pub.Encode(), l, reach)
		a.v.SetListUploaded(false)
		list = l
		return nil
	})
	if err != nil {
		return "", err
	}
	if err := a.rc.SetDevices(a.auth(), list); err != nil {
		return fmt.Sprintf("Device %s is off your list. The relay could not be told yet (%s); that is retried the next time itter runs.", short(gone), explain(err)), nil
	}
	if err := a.v.Update(func() error { a.v.SetListUploaded(true); return nil }); err != nil {
		return "", err
	}
	return fmt.Sprintf("Device %s is unlinked: it no longer receives your messages, and nobody accepts messages from it. If it was lost or stolen, what it had already received stays readable on it.", short(gone)), nil
}

// setIgnore changes itter's ignore list for this account.
func (a *app) setIgnore(peer string, ignore bool) (string, error) {
	peer = a.resolve(peer)
	if !api.ValidUsername(peer) {
		return "", userErrf("%q is not a valid itter username", peer)
	}
	err := a.rc.SetIgnore(a.auth(), peer, ignore)
	switch {
	case relay.Status(err) == http.StatusNotFound:
		return "", userErrf("there is no itter user @%s", peer)
	case relay.Status(err) == http.StatusBadRequest:
		return "", userErrf("you cannot ignore yourself")
	case err != nil:
		return "", err
	}
	names, lerr := a.rc.Ignored(a.auth())
	for _, n := range names {
		if strings.EqualFold(n, peer) {
			peer = n // the way itter spells it
		}
	}
	uerr := a.v.Update(func() error {
		if lerr == nil {
			a.v.SetIgnoreList(names)
		}
		if _, known := a.v.ContactInfo(peer); known || len(a.v.GetMessages(peer)) > 0 {
			if ignore {
				a.v.AddSystem(peer, fmt.Sprintf("You ignore @%s now. Their messages no longer reach you.", peer))
			} else {
				a.v.AddSystem(peer, fmt.Sprintf("You stopped ignoring @%s.", peer))
			}
		}
		return nil
	})
	if uerr != nil {
		return "", uerr
	}
	if ignore {
		return fmt.Sprintf("Ignoring @%s: their DMs no longer reach you, and they are not told. (It is the same list as `ignore` on itter.) Undo: unignore @%s", peer, peer), nil
	}
	return fmt.Sprintf("No longer ignoring @%s.", peer), nil
}

// Approving hands over the whole account, so it asks first: talking someone
// into typing a code is the classic way to get a device of one's own linked.
const approveWord = "LINK"

func approveWarning(me string) []string {
	return []string{
		fmt.Sprintf("This lets another device read and send @%s's DMs from now on.", me),
		"Go on only if the code is from the screen of a device of YOUR OWN, where you just ran `itter link` yourself.",
		"Nobody else ever needs you to type a code here.",
	}
}

func cmdApprove(args []string) error {
	sure := len(args) > 1 && args[len(args)-1] == "--yes"
	if sure {
		args = args[:len(args)-1]
	}
	if len(args) < 1 {
		return userErrf("usage: itter approve <link code>   (the code `itter link` shows on the new device)")
	}
	secret, err := api.ParseRecovery(strings.Join(args, ""))
	if err != nil {
		return userErrf("that is not a valid link code — copy it exactly as the new device shows it")
	}
	a, err := open()
	if err != nil {
		return err
	}
	if a.v.IsLinked() {
		return userErrf("devices are approved on the account's first device (this one was linked itself)")
	}
	if !sure {
		me, _ := a.v.Me()
		for _, l := range approveWarning(me) {
			fmt.Println(l)
		}
		if !confirm("Type "+approveWord+" to confirm: ", approveWord) {
			return userErrf("nothing was linked")
		}
	}
	msg, err := a.approve(secret)
	if err != nil {
		return err
	}
	fmt.Println(msg)
	return nil
}

func cmdDevices() error {
	a, err := open()
	if err != nil {
		return err
	}
	lines, err := a.deviceLines()
	if err != nil {
		return err
	}
	for _, l := range lines {
		fmt.Println(l)
	}
	return nil
}

func cmdUnlink(args []string) error {
	if len(args) < 1 {
		return userErrf("usage: itter unlink <device id>   (`itter devices` shows the ids; the first characters are enough)")
	}
	a, err := open()
	if err != nil {
		return err
	}
	msg, err := a.unlink(args[0])
	if err != nil {
		return err
	}
	fmt.Println(msg)
	return nil
}

func cmdIgnore(args []string, ignore bool) error {
	a, err := open()
	if err != nil {
		return err
	}
	if len(args) < 1 {
		names, err := a.rc.Ignored(a.auth())
		if err != nil {
			return err
		}
		if len(names) == 0 {
			fmt.Println("You ignore nobody.")
		}
		for _, n := range names {
			fmt.Println("@" + n)
		}
		return nil
	}
	msg, err := a.setIgnore(args[0], ignore)
	if err != nil {
		return err
	}
	fmt.Println(msg)
	return nil
}
