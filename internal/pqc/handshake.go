package pqc

import (
	"crypto/sha512"
	"errors"
	"strings"
)

// PQXDH-max: an X3DH/PQXDH-style handshake in which every secret is hybrid.
//
//	DH1 = X25519(IK_A, SPK_B)   DH2 = X25519(EK_A, IK_B)
//	DH3 = X25519(EK_A, SPK_B)   DH4 = X25519(EK_A, OPK_B)           (optional)
//	SS1 = ML-KEM-1024 -> SPK_B  SS2 = FrodoKEM-1344 -> SPK_B
//	SS3 = ML-KEM-1024 -> OPK_B  SS4 = FrodoKEM-1344 -> OPK_B        (optional)
//	TH  = SHA-512(account names, identities, prekeys, EK, all ciphertexts)
//	SK  = HKDF(salt = TH, 0xFF*32 || DH1..4 || SS1..4)
//
// Unlike Signal's PQXDH, the initiator signs TH with the full composite
// signature (SLH-DSA included), so the responder gets post-quantum
// authentication of who started the conversation, not just confidentiality.
// The responder is authenticated by the composite signature on SPK_B.

// InitHandshake is the initiator's handshake. It is attached unchanged to
// every message until the responder answers, so losing the first message
// does not lose the conversation.
type InitHandshake struct {
	V int `json:"v"`
	// From and To are the account names of initiator and responder. They are
	// part of the signed transcript, so a handshake cannot be re-labelled as
	// coming from, or re-addressed to, another account.
	From     string `json:"from"`
	To       string `json:"to"`
	Identity []byte `json:"identity"`
	EK       []byte `json:"ek"`
	SPKID    uint32 `json:"spk_id"`
	OTPKID   uint32 `json:"otpk_id,omitempty"`
	CTMLKEM  []byte `json:"ct_mlkem"`
	CTFrodo  []byte `json:"ct_frodo"`
	OTMLKEM  []byte `json:"ot_mlkem,omitempty"`
	OTFrodo  []byte `json:"ot_frodo,omitempty"`
	Sig      []byte `json:"sig"`
}

var (
	errNoSPK  = errors.New("pqc: signed prekey not found")
	errNoOTPK = errors.New("pqc: one-time prekey not found")
	errHS     = errors.New("pqc: malformed handshake")
)

// HandshakeID identifies a handshake (the ephemeral key is unique).
func (hs *InitHandshake) HandshakeID() []byte {
	e := &encoder{}
	e.raw([]byte(labelPrefix + "handshake-id")).bytes(hs.Identity).bytes(hs.EK).bytes(hs.CTMLKEM)
	sum := sha512.Sum512(e.b)
	return sum[:32]
}

func transcript(ikA, ikB []byte, spk, otpk *PreKeyPublic, hs *InitHandshake) []byte {
	e := &encoder{}
	e.raw([]byte(labelPrefix + "pqxdh-transcript"))
	e.str(strings.ToLower(hs.From)).str(strings.ToLower(hs.To)).bytes(ikA).bytes(ikB)
	e.u32(spk.ID).bytes(spk.DH).bytes(spk.MLKEM).bytes(spk.Frodo)
	if otpk != nil {
		e.u8(1).u32(otpk.ID).bytes(otpk.DH).bytes(otpk.MLKEM).bytes(otpk.Frodo)
	} else {
		e.u8(0)
	}
	e.bytes(hs.EK).bytes(hs.CTMLKEM).bytes(hs.CTFrodo).bytes(hs.OTMLKEM).bytes(hs.OTFrodo)
	sum := sha512.Sum512(e.b)
	return sum[:]
}

func sessionAD(ikA, ikB []byte) []byte {
	a := sha512.Sum512(ikA)
	b := sha512.Sum512(ikB)
	ad := append([]byte("ITR2"), a[:32]...)
	return append(ad, b[:32]...)
}

func newSession(initiator bool, th, ikm, ikA, ikB []byte) *Session {
	sk := kdf(th, ikm, "pqxdh/sk", 96)
	skDR, sk1, sk2 := sk[:32], sk[32:64], sk[64:96]
	return &Session{
		V:         ProtocolVersion,
		Initiator: initiator,
		AD:        sessionAD(ikA, ikB),
		PQ1:       newBraid(braidMLKEM, sk1, initiator),
		PQ1Chain:  newPQChain(braidMLKEM, sk1, initiator),
		PQ2:       newBraid(braidFrodo, sk2, initiator),
		PQ2Chain:  newPQChain(braidFrodo, sk2, initiator),
		DR:        &DR{RK: append([]byte(nil), skDR...)},
	}
}

// Initiate starts a session between account me and the owner of bundle b.
func Initiate(id *Identity, me string, b *PublicBundle) (*Session, error) {
	ikB, err := b.Verify()
	if err != nil {
		return nil, err
	}
	ekPriv, ekPub, err := x25519Generate()
	if err != nil {
		return nil, err
	}
	defer zero(ekPriv)

	var secrets [][]byte
	defer func() {
		for _, s := range secrets {
			zero(s)
		}
	}()
	dh := func(priv, pub []byte) error {
		out, err := x25519(priv, pub)
		if err == nil {
			secrets = append(secrets, out)
		}
		return err
	}
	if err := dh(id.DHPriv, b.SPK.DH); err != nil {
		return nil, err
	}
	if err := dh(ekPriv, ikB.X25519); err != nil {
		return nil, err
	}
	if err := dh(ekPriv, b.SPK.DH); err != nil {
		return nil, err
	}
	if b.OTPK != nil {
		if err := dh(ekPriv, b.OTPK.DH); err != nil {
			return nil, err
		}
	}

	hs := &InitHandshake{V: ProtocolVersion, From: me, To: b.Username, Identity: id.Pub.Encode(), EK: ekPub, SPKID: b.SPK.ID}
	var kemSS [][]byte
	encap := func(k kemScheme, ek []byte) ([]byte, error) {
		ss, ct, err := k.encapsulate(ek)
		if err == nil {
			kemSS = append(kemSS, ss)
		}
		return ct, err
	}
	if hs.CTMLKEM, err = encap(kemMLKEM1024, b.SPK.MLKEM); err != nil {
		return nil, err
	}
	if hs.CTFrodo, err = encap(kemFrodo1344, b.SPK.Frodo); err != nil {
		return nil, err
	}
	if b.OTPK != nil {
		hs.OTPKID = b.OTPK.ID
		if hs.OTMLKEM, err = encap(kemMLKEM1024, b.OTPK.MLKEM); err != nil {
			return nil, err
		}
		if hs.OTFrodo, err = encap(kemFrodo1344, b.OTPK.Frodo); err != nil {
			return nil, err
		}
	}
	secrets = append(secrets, kemSS...)

	th := transcript(hs.Identity, b.Identity, b.SPK, b.OTPK, hs)
	if hs.Sig, err = id.Sign.SignFull(th, "pqxdh-init"); err != nil {
		return nil, err
	}

	s := newSession(true, th, handshakeIKM(secrets), hs.Identity, b.Identity)
	if s.DR, err = drInitAlice(s.DR.RK, b.SPK.DH); err != nil {
		return nil, err
	}
	s.PendingInit = hs
	s.HandshakeID = hs.HandshakeID()
	s.TheirIdentity = append([]byte(nil), b.Identity...)
	s.TheirUsername = b.Username
	return s, nil
}

func handshakeIKM(secrets [][]byte) []byte {
	ikm := make([]byte, 32)
	for i := range ikm {
		ikm[i] = 0xFF
	}
	for _, s := range secrets {
		ikm = append(ikm, s...)
	}
	return ikm
}

// Respond answers a handshake addressed to account me with identity id. spk
// and otpk are the prekeys the handshake names (otpk may be nil when none was
// used). The initiator's composite signature is verified before any key is
// derived. The returned session's TheirUsername is the name the initiator
// signed; the caller must check it against where the message came from.
func Respond(id *Identity, me string, spk, otpk *PreKey, hs *InitHandshake) (*Session, error) {
	if hs.V != ProtocolVersion {
		return nil, errHS
	}
	if hs.From == "" || !strings.EqualFold(hs.To, me) {
		return nil, errors.New("pqc: handshake is addressed to another account")
	}
	ikA, err := DecodeIdentityKey(hs.Identity)
	if err != nil {
		return nil, err
	}
	if spk == nil || spk.ID != hs.SPKID {
		return nil, errNoSPK
	}
	if len(hs.EK) != 32 || len(hs.CTMLKEM) != kemMLKEM1024.ctSize() || len(hs.CTFrodo) != kemFrodo1344.ctSize() ||
		len(hs.Sig) != FullSigSize {
		return nil, errHS
	}
	if hs.OTPKID != 0 {
		if otpk == nil || otpk.ID != hs.OTPKID {
			return nil, errNoOTPK
		}
		if len(hs.OTMLKEM) != kemMLKEM1024.ctSize() || len(hs.OTFrodo) != kemFrodo1344.ctSize() {
			return nil, errHS
		}
	} else if len(hs.OTMLKEM) != 0 || len(hs.OTFrodo) != 0 {
		return nil, errHS
	}

	spkPub, err := spk.Public()
	if err != nil {
		return nil, err
	}
	var otpkPub *PreKeyPublic
	if hs.OTPKID != 0 {
		if otpkPub, err = otpk.Public(); err != nil {
			return nil, err
		}
	}
	myID := id.Pub.Encode()
	th := transcript(hs.Identity, myID, spkPub, otpkPub, hs)
	if err := ikA.VerifyFull(th, hs.Sig, "pqxdh-init"); err != nil {
		return nil, errors.New("pqc: handshake signature invalid")
	}

	var secrets [][]byte
	defer func() {
		for _, s := range secrets {
			zero(s)
		}
	}()
	dh := func(priv, pub []byte) error {
		out, err := x25519(priv, pub)
		if err == nil {
			secrets = append(secrets, out)
		}
		return err
	}
	if err := dh(spk.DHPriv, ikA.X25519); err != nil {
		return nil, err
	}
	if err := dh(id.DHPriv, hs.EK); err != nil {
		return nil, err
	}
	if err := dh(spk.DHPriv, hs.EK); err != nil {
		return nil, err
	}
	if otpk != nil && hs.OTPKID != 0 {
		if err := dh(otpk.DHPriv, hs.EK); err != nil {
			return nil, err
		}
	}
	decap := func(k kemScheme, seed, ct []byte) error {
		ss, err := k.decapsulate(seed, ct)
		if err == nil {
			secrets = append(secrets, ss)
		}
		return err
	}
	if err := decap(kemMLKEM1024, spk.MLKEMSeed, hs.CTMLKEM); err != nil {
		return nil, err
	}
	if err := decap(kemFrodo1344, spk.FrodoSeed, hs.CTFrodo); err != nil {
		return nil, err
	}
	if hs.OTPKID != 0 {
		if err := decap(kemMLKEM1024, otpk.MLKEMSeed, hs.OTMLKEM); err != nil {
			return nil, err
		}
		if err := decap(kemFrodo1344, otpk.FrodoSeed, hs.OTFrodo); err != nil {
			return nil, err
		}
	}

	s := newSession(false, th, handshakeIKM(secrets), hs.Identity, myID)
	s.DR = drInitBob(s.DR.RK, spk.DHPriv, spkPub.DH)
	s.HandshakeID = hs.HandshakeID()
	s.TheirIdentity = append([]byte(nil), hs.Identity...)
	s.TheirUsername = hs.From
	return s, nil
}
