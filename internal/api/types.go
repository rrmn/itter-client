// Package api defines the wire contract between the itter client and relay.
//
//	PUT    /v1/register                     bind a DM identity to an itter account
//	DELETE /v1/register                     release it (signed by the identity, or with the recovery code)
//	POST   /v1/session/{user}               a device opens a session (full signature, key agreement)
//	PUT    /v1/keys/{user}              [A] publish this device's signed + one-time prekeys
//	GET    /v1/keys/{user}                  identity, device list, signed prekeys (public)
//	POST   /v1/keys/{user}/claim        [A] the same plus one one-time prekey per device
//	GET    /v1/keys/{user}/count        [A] this device's one-time prekeys left on the relay
//	POST   /v1/msg/{user}               [A] send: one message for each of the user's devices
//	GET    /v1/inbox/{user}?wait=25     [A] who has messages waiting for this device (long-poll)
//	GET    /v1/inbox/{user}/from/{peer} [A] fetch (does not delete)
//	POST   /v1/inbox/{user}/ack         [A] delete after the client saved them
//	GET    /v1/devices/{user}           [A] the account's devices
//	PUT    /v1/devices/{user}           [A] a newer device list, signed by the account identity
//	DELETE /v1/devices/{user}           [A] a linked device takes itself out of service
//	POST   /v1/link/{user}                  a new device asks to be linked (needs an SSH signature)
//	GET    /v1/link/{user}/{id}         [A] the first device looks at the request
//	PUT    /v1/link/{user}/{id}         [A] ...and answers it
//	GET    /v1/link/{user}/{id}/result      the new device picks the answer up
//	GET    /v1/ignore/{user}            [A] who this account ignores (itter's own list)
//	PUT    /v1/ignore/{user}/{peer}     [A] ignore someone
//	DELETE /v1/ignore/{user}/{peer}     [A] stop ignoring them
//
// [A] needs a session: the request names its ticket and carries a MAC made
// with the session key, over method, path and query, time, a single-use
// nonce and the body. The key never travels: it is agreed when the session is
// opened, in an exchange the device signs with its full signature. Nothing
// that a request carries can be used to make another request.
//
// It is plain HTTP. Normally it travels through a channel of itter's SSH
// port (see relay.Tunnel); a relay with an address of its own is spoken to
// over https.
package api

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/rrmn/itter-client/internal/pqc"
)

const (
	SessionHeader = "X-Itter-Session" // the ticket of the session a request belongs to
	TimeHeader    = "X-Itter-Time"    // unix seconds (also sent by the relay on clock errors)
	NonceHeader   = "X-Itter-Nonce"   // 32 hex chars, single use
	AuthHeader    = "X-Itter-Auth"    // base64 RequestMAC

	// MaxDevices is how many devices an account can have.
	MaxDevices = pqc.MaxLinkedDevices + 1

	// MaxMessageSize bounds one stored message (initial messages carrying the
	// handshake are ~120 KB).
	MaxMessageSize = 256 << 10
	// MaxTextLen bounds the text of one DM, in bytes.
	MaxTextLen = 4000
	// MaxWait is the longest long-poll the relay honours, in seconds.
	MaxWait = 30
)

var usernameRE = regexp.MustCompile(`^[a-zA-Z0-9_]{3,20}$`)

// ValidUsername is checked by the relay AND by the client: the client must
// not trust names it gets from the relay.
func ValidUsername(u string) bool { return usernameRE.MatchString(u) }

// SSHSig carries an SSH-agent signature. Format must be preserved; Rest holds
// the extra data FIDO (sk-…) keys need for verification.
type SSHSig struct {
	Format string `json:"format"`
	Blob   []byte `json:"blob"`
	Rest   []byte `json:"rest,omitempty"`
}

// AllowedSSHKeyType reports whether an SSH key type may bind a DM identity.
// RSA is refused outright: the threat model assumes it is broken. (Elliptic
// curve SSH keys are classical too; the binding is only a gate against casual
// abuse, and safety numbers remain the real root of trust.)
func AllowedSSHKeyType(t string) bool {
	switch t {
	case "ssh-ed25519", "sk-ssh-ed25519@openssh.com",
		"ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
		"sk-ecdsa-sha2-nistp256@openssh.com":
		return true
	}
	return false
}

// AllowedSSHSigFormat rejects every RSA signature format.
func AllowedSSHSigFormat(f string) bool {
	return f != "" && !strings.Contains(f, "rsa") && AllowedSSHKeyType(f)
}

func lp(out []byte, b []byte) []byte {
	out = binary.BigEndian.AppendUint32(out, uint32(len(b)))
	return append(out, b...)
}

// RegReq binds a DM identity to an itter account. An account has at most one
// identity; it can only be replaced after its owner released it.
type RegReq struct {
	Username string   `json:"username"`
	Identity []byte   `json:"identity"` // pqc.IdentityKey encoding
	SSHSigs  []SSHSig `json:"ssh_sigs"` // over RegPayload; non-RSA keys only
	// IDSig: the identity's full composite signature over RegPayload
	// (proof of possession).
	IDSig []byte `json:"id_sig"`
	// RecoveryKey lets the owner release the identity without the device:
	// the public key their recovery code stands for (pqc.RecoveryPublic).
	RecoveryKey []byte `json:"recovery_key"`
	// TS (unix seconds) is signed too, so a recorded registration cannot be
	// replayed later to re-bind an identity its owner has released.
	TS int64 `json:"ts"`
}

// RegResp returns the account name as itter spells it.
type RegResp struct {
	Username string `json:"username"`
}

// RegPayload is what both the SSH key and the new identity sign.
func RegPayload(username string, identity, recoveryKey []byte, ts int64) []byte {
	out := []byte("itter/v2/dm-binding")
	out = lp(out, []byte(strings.ToLower(username)))
	out = lp(out, identity)
	out = lp(out, recoveryKey)
	return binary.BigEndian.AppendUint64(out, uint64(ts))
}

// ReleaseReq removes an identity from the relay. Either the identity signs
// ReleasePayload itself (`itter burn`), or the key its owner's recovery code
// stands for signs RecoverPayload (`itter recover`, when the device and with
// it the identity are gone). Both name the account and the time, so a
// recorded request is good for nothing else and for nothing later.
type ReleaseReq struct {
	Username    string `json:"username"`
	TS          int64  `json:"ts"`
	Sig         []byte `json:"sig,omitempty"`          // the identity's full composite signature
	RecoverySig []byte `json:"recovery_sig,omitempty"` // or: pqc.RecoverySign with the recovery code
}

func ReleasePayload(username string, identity []byte, ts int64) []byte {
	out := []byte("itter/v2/dm-release")
	out = lp(out, []byte(strings.ToLower(username)))
	out = lp(out, identity)
	return binary.BigEndian.AppendUint64(out, uint64(ts))
}

// RecoverPayload is what a recovery code signs to release its account's
// identity. The relay checks the signature against the key stored with the
// identity that is there now: an identity registered later has another code,
// so an old signature does nothing to it.
func RecoverPayload(username string, ts int64) []byte {
	out := []byte("itter/v2/dm-recover")
	out = lp(out, []byte(strings.ToLower(username)))
	return binary.BigEndian.AppendUint64(out, uint64(ts))
}

// Recovery codes are 32 random bytes. A code is never sent anywhere: it is
// the seed of a hash-based signature key (pqc.RecoveryPublic). The relay
// stores the public half and takes a signature as proof.

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// FormatRecovery renders a recovery code as dash-separated groups.
func FormatRecovery(code []byte) string {
	s := b32.EncodeToString(code)
	var groups []string
	for len(s) > 4 {
		groups = append(groups, s[:4])
		s = s[4:]
	}
	return strings.Join(append(groups, s), "-")
}

// ParseRecovery accepts what FormatRecovery prints, forgiving case, spaces
// and dashes.
func ParseRecovery(s string) ([]byte, error) {
	s = strings.ToUpper(strings.NewReplacer("-", "", " ", "", "\t", "", "\n", "", "\r", "").Replace(s))
	code, err := b32.DecodeString(s)
	if err != nil || len(code) != pqc.RecoveryCodeSize {
		return nil, errors.New("that is not a valid recovery code")
	}
	return code, nil
}

// SessionReq opens a session for one device of an account. Offer holds
// one-time public keys (pqc.SessionOffer); Sig is the device key's full
// signature over SessionPayload, so only that device can ask and nobody in
// between can put keys of their own into the request.
type SessionReq struct {
	Device string `json:"device"` // pqc.IdentityID of the calling device's key
	TS     int64  `json:"ts"`
	Nonce  string `json:"nonce"` // 32 hex chars, single use
	Offer  []byte `json:"offer"`
	Sig    []byte `json:"sig"`
}

// SessionPayload is what the device signs to open a session.
func SessionPayload(username, device string, ts int64, nonce string, offer []byte) []byte {
	out := []byte("itter/v2/relay-session")
	out = lp(out, []byte(strings.ToLower(username)))
	out = lp(out, []byte(device))
	out = binary.BigEndian.AppendUint64(out, uint64(ts))
	out = lp(out, []byte(nonce))
	return lp(out, offer)
}

// SessionResp is the relay's half. Ticket names the session and goes into
// every request. Answer completes the key agreement (pqc.SessionOffer.Open,
// bound to the ticket); Box holds the session key, encrypted under the secret
// the agreement gave (pqc.UnwrapSessionKey, with the ticket as its
// associated data). Only the device that made the offer can open it.
type SessionResp struct {
	Ticket  string `json:"ticket"`
	Answer  []byte `json:"answer"`
	Box     []byte `json:"box"`
	Expires int64  `json:"expires"` // unix seconds
}

// RequestMAC authenticates one request of a session. uri is the path with
// its query, as sent.
func RequestMAC(key []byte, method, uri string, ts int64, nonce string, bodyHash []byte) []byte {
	msg := []byte("itter/v2/relay-request")
	msg = lp(msg, []byte(method))
	msg = lp(msg, []byte(uri))
	msg = binary.BigEndian.AppendUint64(msg, uint64(ts))
	msg = lp(msg, []byte(nonce))
	msg = lp(msg, bodyHash)
	mac := hmac.New(sha512.New512_256, key)
	mac.Write(msg)
	return mac.Sum(nil)
}

// KeysUpload publishes a signed prekey and a batch of one-time prekeys.
type KeysUpload struct {
	SPK    *pqc.PreKeyPublic   `json:"spk"`
	SPKSig []byte              `json:"spk_sig"`
	OTPKs  []*pqc.PreKeyPublic `json:"otpks"`
}

type KeyCountResp struct {
	OTPKs int `json:"otpks"`
}

// Directory is what the relay lists for an account: its identity, the
// signed list of its linked devices, and for every device that can be written
// to right now a bundle whose Identity is that device's key. Clients verify
// all of it: the list against the identity, each bundle against the list.
type Directory struct {
	Username string              `json:"username"`
	Identity []byte              `json:"identity"`
	List     *pqc.DeviceList     `json:"list,omitempty"`
	Devices  []*pqc.PublicBundle `json:"devices"`
}

// ClaimReq asks for one-time prekeys of some of an account's devices (all, if
// none are named).
type ClaimReq struct {
	Devices []string `json:"devices,omitempty"`
}

// SendReq carries one message per device of the recipient. ToID is the
// account identity the sender believes the recipient has. The relay refuses
// the lot if that identity, or the set of devices, is out of date, so nothing
// is ever sent into the void or past a device.
type SendReq struct {
	ToID string                     `json:"to_id"`
	Msgs map[string]json.RawMessage `json:"msgs"` // device id -> pqc.WireMsg
}

// DevicesResp describes an account's devices to their owner.
type DevicesResp struct {
	IdentityID string          `json:"identity_id"`
	List       *pqc.DeviceList `json:"list,omitempty"`
	Devices    []DeviceInfo    `json:"devices"`
}

type DeviceInfo struct {
	ID      string `json:"id"`
	Primary bool   `json:"primary"`
	Ready   bool   `json:"ready"` // has published prekeys: messages go to it
}

// LinkReq is a new device asking to be linked. Like a registration it needs
// a signature from an SSH key on the itter account; what makes the first
// device accept it is Tag, made with the one-time code the user carries over.
type LinkReq struct {
	LinkID    string   `json:"link_id"`
	DeviceKey []byte   `json:"device_key"`
	Tag       []byte   `json:"tag"`
	SSHSigs   []SSHSig `json:"ssh_sigs"`
	TS        int64    `json:"ts"`
}

// LinkPayload is what the SSH key signs for a link request.
func LinkPayload(username, linkID string, deviceKey []byte, ts int64) []byte {
	out := []byte("itter/v2/dm-link")
	out = lp(out, []byte(strings.ToLower(username)))
	out = lp(out, []byte(linkID))
	out = lp(out, deviceKey)
	return binary.BigEndian.AppendUint64(out, uint64(ts))
}

// LinkInfo is what the first device gets to see of a request.
type LinkInfo struct {
	DeviceKey []byte `json:"device_key"`
	Tag       []byte `json:"tag"`
}

// LinkResult is the first device's answer, relayed as an opaque blob.
type LinkResult struct {
	Username string          `json:"username"` // the account name as itter spells it
	Identity []byte          `json:"identity"` // the account identity
	List     *pqc.DeviceList `json:"list"`     // includes the new device
	Tag      []byte          `json:"tag"`      // pqc.LinkResultTag
}

type LinkAnswer struct {
	Result []byte `json:"result,omitempty"` // a LinkResult as JSON; empty: not answered yet
}

// IgnoreResp lists who an account ignores.
type IgnoreResp struct {
	Ignored []string `json:"ignored"`
}

// InboxResp says who has messages waiting, and how many.
type InboxResp struct {
	Senders map[string]int `json:"senders"`
}

// InboxItem is one stored message. ID is only meaningful for acking.
type InboxItem struct {
	ID  int64       `json:"id"`
	Msg pqc.WireMsg `json:"msg"`
}

type AckReq struct {
	IDs []int64 `json:"ids"`
}

// Error bodies the client recognises (sent as text/plain with the status).
const (
	ErrIdentityChanged = "recipient identity changed"   // 409 on send
	ErrDevicesChanged  = "recipient devices changed"    // 409 on send
	ErrNoIdentity      = "recipient has no DM identity" // 410 on send
	ErrInboxFull       = "inbox full"                   // 429 on send
	ErrClockSkew       = "clock skew"                   // 401
	ErrUnknownIdentity = "unknown identity"             // 401
	ErrSessionGone     = "no such session"              // 401: open a new one
)
