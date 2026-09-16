package api

import "fmt"

const (
	UserHeader   = "X-Itter-User"
	AuthHeader   = "X-Itter-Auth"
	MinuteHeader = "X-Itter-Minute"
)

type RegReq struct {
	Username string `json:"username"`
	SignPub  []byte `json:"sign_pub"`
	DHPub    []byte `json:"dh_pub"`
	Sig      []byte `json:"sig"`
}

func RegPayload(username string, signPub, dhPub []byte) []byte {
	out := append([]byte("ITTER-REG-V1"), []byte(username)...)
	out = append(out, signPub...)
	out = append(out, dhPub...)
	return out
}

func AuthPayload(method, path string, minute int64) []byte {
	return []byte(fmt.Sprintf("ITTER-AUTH-V1|%s|%s|%d", method, path, minute))
}

type OTPKPub struct {
	ID     uint32 `json:"id"`
	DHPub  []byte `json:"dh_pub"`
	KEMPub []byte `json:"kem_pub"`
}

type KeysUpload struct {
	SPKID     uint32    `json:"spk_id"`
	SPKDHPub  []byte    `json:"spk_dh_pub"`
	SPKKEMPub []byte    `json:"spk_kem_pub"`
	SPKSig    []byte    `json:"spk_sig"`
	OTPKs     []OTPKPub `json:"otpks"`
}

type SendersResp map[string]int