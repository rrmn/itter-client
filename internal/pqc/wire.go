package pqc

import (
	"encoding/json"
	"errors"
	"time"
)

// Wire message types (the relay only stores and forwards these).
const (
	WireInitial  = 1 // InitialPayload: handshake + envelope
	WireEnvelope = 2 // EnvelopePayload
)

// WireMsg is what the relay stores. From is self-declared and only used to
// route; authenticity comes from the session.
type WireMsg struct {
	Type int    `json:"t"`
	From string `json:"from"`
	// Dev names the sending device (IdentityID of its key). It is a routing
	// hint that tells the receiver which session to try; nothing is trusted
	// because of it.
	Dev     string          `json:"dev,omitempty"`
	Payload json.RawMessage `json:"p"`
}

type InitialPayload struct {
	V   int            `json:"v"`
	HS  *InitHandshake `json:"hs"`
	Env []byte         `json:"env"`
}

type EnvelopePayload struct {
	V   int    `json:"v"`
	Env []byte `json:"env"`
}

// Seal encrypts plaintext for the session and wraps it for the relay. While
// the peer has not answered, the handshake rides along: on every message
// until the caller reports that the relay took one (HandshakeDelivered), and
// now and then after that (see handshakeDue).
func (s *Session) Seal(from string, plaintext []byte) (*WireMsg, error) {
	env, err := s.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}
	var typ int
	var p []byte
	if s.handshakeDue() {
		typ = WireInitial
		p, err = json.Marshal(InitialPayload{V: ProtocolVersion, HS: s.PendingInit, Env: env})
	} else {
		typ = WireEnvelope
		p, err = json.Marshal(EnvelopePayload{V: ProtocolVersion, Env: env})
	}
	if err != nil {
		return nil, err
	}
	return &WireMsg{Type: typ, From: from, Payload: p}, nil
}

// ParseInitial and ParseEnvelope decode wire payloads, rejecting other versions.
func ParseInitial(w *WireMsg) (*InitialPayload, error) {
	var ip InitialPayload
	if w.Type != WireInitial || json.Unmarshal(w.Payload, &ip) != nil || ip.V != ProtocolVersion || ip.HS == nil {
		return nil, errors.New("pqc: unsupported or malformed initial message")
	}
	return &ip, nil
}

func ParseEnvelope(w *WireMsg) (*EnvelopePayload, error) {
	var ep EnvelopePayload
	if w.Type != WireEnvelope || json.Unmarshal(w.Payload, &ep) != nil || ep.V != ProtocolVersion {
		return nil, errors.New("pqc: unsupported or malformed message")
	}
	return &ep, nil
}

// InnerMsg is the plaintext inside every envelope.
type InnerMsg struct {
	TS   int64  `json:"ts"`
	Text string `json:"text"`
	// Kind is empty for a chat message. KindReset announces that the sender
	// deliberately started a fresh session. KindSync comes from another
	// device of one's own account and reports a message it sent to Peer.
	Kind string `json:"kind,omitempty"`
	Peer string `json:"peer,omitempty"`
}

const (
	KindReset = "reset"
	KindSync  = "sync"
)

// PackSync tells one's other devices about a message sent to peer.
func PackSync(peer, text string, ts int64) []byte {
	b, _ := json.Marshal(InnerMsg{TS: ts, Text: text, Kind: KindSync, Peer: peer})
	return b
}

func PackInner(text string) []byte {
	b, _ := json.Marshal(InnerMsg{TS: time.Now().Unix(), Text: text})
	return b
}

func PackControl(kind string) []byte {
	b, _ := json.Marshal(InnerMsg{TS: time.Now().Unix(), Kind: kind})
	return b
}

func UnpackInner(b []byte) (InnerMsg, error) {
	var im InnerMsg
	err := json.Unmarshal(b, &im)
	return im, err
}
