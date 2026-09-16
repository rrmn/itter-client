package pqc

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"
)

const (
	WireInitial  = 1
	WireEnvelope = 2
)

type WireMsg struct {
	Type    int             `json:"t"`
	From    string          `json:"from"`
	Payload json.RawMessage `json:"p"`
}

type InnerMsg struct {
	TS   int64  `json:"ts"`
	Text string `json:"text"`
}

func PackInner(text string) []byte {
	b, _ := json.Marshal(InnerMsg{TS: time.Now().Unix(), Text: text})
	return b
}

func UnpackInner(b []byte) (InnerMsg, error) {
	var im InnerMsg
	err := json.Unmarshal(b, &im)
	return im, err
}

func Fingerprint(signPub []byte) string {
	sum := sha256.Sum256(signPub)
	h := hex.EncodeToString(sum[:16])
	return strings.Join([]string{h[0:8], h[8:16], h[16:24], h[24:32]}, " ")
}

func SafetyNumber(a, b []byte) string {
	if bytes.Compare(a, b) > 0 {
		a, b = b, a
	}
	sum := sha256.Sum256(append(a, b...))
	n := new(big.Int).SetBytes(sum[:])
	mod, _ := new(big.Int).SetString("1"+"000000000000000000000000000000000000000000000000000000000000", 10)
	n.Mod(n, mod)
	s := fmt.Sprintf("%060d", n)
	var groups []string
	for i := 0; i < 60; i += 5 {
		groups = append(groups, s[i:i+5])
	}
	return strings.Join(groups, " ")
}