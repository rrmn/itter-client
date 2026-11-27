package pqc

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"strings"
)

// An account can use several devices. The account identity (the key the
// relay lists for the account, and the one safety numbers are made of) stays
// on the first device. Every further device has a key of its own, and the
// account identity vouches for it by signing the list of device keys.
//
// Nothing secret ever moves between devices, a contact's safety number does
// not change when devices come and go, and a device that is taken off the
// list is out: its key is no longer accepted by anyone who has seen the newer
// list.

// MaxLinkedDevices bounds how many devices an account can have besides the first.
const MaxLinkedDevices = 4

// DeviceList is the signed list of an account's linked devices.
type DeviceList struct {
	// V counts up with every change. Whoever has seen version n never
	// accepts a lower one again, so a removed device cannot be brought back
	// by replaying an old list.
	V    uint64   `json:"v"`
	Keys [][]byte `json:"keys"` // device keys (IdentityKey encodings), without the first device
	Sig  []byte   `json:"sig"`  // full signature by the account identity
}

func deviceListPayload(identity []byte, username string, v uint64, keys [][]byte) []byte {
	e := &encoder{}
	e.str(labelPrefix + "device-list").bytes(identity).str(strings.ToLower(username)).u64(v).u32(uint32(len(keys)))
	for _, k := range keys {
		e.bytes(k)
	}
	return e.b
}

// SignDeviceList makes version v of the account's device list.
func SignDeviceList(account *Identity, username string, v uint64, keys [][]byte) (*DeviceList, error) {
	l := &DeviceList{V: v, Keys: keys}
	if err := l.check(account.Pub.Encode()); err != nil {
		return nil, err
	}
	sig, err := account.Sign.SignFull(deviceListPayload(account.Pub.Encode(), username, v, keys), "device-list")
	if err != nil {
		return nil, err
	}
	l.Sig = sig
	return l, nil
}

func (l *DeviceList) check(identity []byte) error {
	if l.V == 0 || len(l.Keys) > MaxLinkedDevices {
		return errors.New("pqc: malformed device list")
	}
	for i, k := range l.Keys {
		if _, err := DecodeIdentityKey(k); err != nil || bytes.Equal(k, identity) {
			return errors.New("pqc: malformed device list")
		}
		for _, other := range l.Keys[:i] {
			if bytes.Equal(k, other) {
				return errors.New("pqc: malformed device list")
			}
		}
	}
	return nil
}

// Verify checks that the list is well formed and signed by the account
// identity for this account name.
func (l *DeviceList) Verify(identity []byte, username string) error {
	if l == nil {
		return errors.New("pqc: no device list")
	}
	ik, err := DecodeIdentityKey(identity)
	if err != nil {
		return err
	}
	if err := l.check(identity); err != nil {
		return err
	}
	if ik.VerifyFull(deviceListPayload(identity, username, l.V, l.Keys), l.Sig, "device-list") != nil {
		return errors.New("pqc: invalid device list signature")
	}
	return nil
}

// Has reports whether key is one of the listed devices. A nil list has none.
func (l *DeviceList) Has(key []byte) bool {
	if l == nil {
		return false
	}
	for _, k := range l.Keys {
		if IdentityEqual(k, key) {
			return true
		}
	}
	return false
}

// Version returns the list's version; 0 for no list.
func (l *DeviceList) Version() uint64 {
	if l == nil {
		return 0
	}
	return l.V
}

// --- linking a device ---
//
// The new device shows a one-time code: 256 random bits. The user types it
// into the first device. Both sides use it only as a MAC key: the new device
// proves which device key is its own, the first device proves which account
// identity is the real one. The relay carries both messages and can forge
// neither. Nothing but hash functions is involved.

// LinkSecretSize is the size of the one-time link code in bytes.
const LinkSecretSize = 32

// LinkID is the name under which the relay files a link request. It reveals
// nothing about the code.
func LinkID(secret []byte) string {
	return hex.EncodeToString(kdf(nil, secret, "link/id", 16))
}

func linkTag(secret []byte, what, username string, parts ...[]byte) []byte {
	e := &encoder{}
	e.str(labelPrefix + "link/" + what).str(strings.ToLower(username))
	for _, p := range parts {
		e.bytes(p)
	}
	m := hmac.New(sha512.New, kdf(nil, secret, "link/mac", 64))
	m.Write(e.b)
	return m.Sum(nil)
}

// LinkRequestTag authenticates the new device's key to the first device.
func LinkRequestTag(secret []byte, username string, deviceKey []byte) []byte {
	return linkTag(secret, "request", username, deviceKey)
}

// LinkResultTag authenticates the account identity, and the list version
// that includes the new device, to the new device.
func LinkResultTag(secret []byte, username string, identity, deviceKey []byte, listV uint64) []byte {
	e := &encoder{}
	return linkTag(secret, "result", username, identity, deviceKey, e.u64(listV).b)
}

// TagEqual compares two tags in constant time.
func TagEqual(a, b []byte) bool { return len(a) > 0 && hmac.Equal(a, b) }
