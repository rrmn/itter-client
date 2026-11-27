package pqc

import (
	"crypto/mlkem"
	"errors"

	"github.com/rrmn/itter-client/internal/pqc/frodo"
)

// kemScheme abstracts the post-quantum KEMs. Decapsulation keys are kept in
// their compact seed form (64-80 bytes) so stored state stays small;
// FrodoKEM re-derives the full key from the seed when it is needed.
type kemScheme interface {
	name() string
	ekSize() int
	ctSize() int
	generate() (dkSeed, ek []byte, err error)
	encapsulate(ek []byte) (ss, ct []byte, err error)
	decapsulate(dkSeed, ct []byte) ([]byte, error)
	publicFromSeed(dkSeed []byte) ([]byte, error)
	checkEK(ek []byte) error // is ek a well-formed encapsulation key?
}

var errKEM = errors.New("pqc: KEM failure")

type mlkem768 struct{}

func (mlkem768) name() string { return "ML-KEM-768" }
func (mlkem768) ekSize() int  { return mlkem.EncapsulationKeySize768 }
func (mlkem768) ctSize() int  { return mlkem.CiphertextSize768 }
func (mlkem768) generate() ([]byte, []byte, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, nil, err
	}
	return dk.Bytes(), dk.EncapsulationKey().Bytes(), nil
}
func (mlkem768) encapsulate(ek []byte) ([]byte, []byte, error) {
	k, err := mlkem.NewEncapsulationKey768(ek)
	if err != nil {
		return nil, nil, errKEM
	}
	ss, ct := k.Encapsulate()
	return ss, ct, nil
}
func (mlkem768) decapsulate(seed, ct []byte) ([]byte, error) {
	dk, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		return nil, errKEM
	}
	return dk.Decapsulate(ct)
}
func (mlkem768) publicFromSeed(seed []byte) ([]byte, error) {
	dk, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		return nil, errKEM
	}
	return dk.EncapsulationKey().Bytes(), nil
}

func (mlkem768) checkEK(ek []byte) error {
	if _, err := mlkem.NewEncapsulationKey768(ek); err != nil {
		return errKEM
	}
	return nil
}

type mlkem1024 struct{}

func (mlkem1024) name() string { return "ML-KEM-1024" }
func (mlkem1024) ekSize() int  { return mlkem.EncapsulationKeySize1024 }
func (mlkem1024) ctSize() int  { return mlkem.CiphertextSize1024 }
func (mlkem1024) generate() ([]byte, []byte, error) {
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, nil, err
	}
	return dk.Bytes(), dk.EncapsulationKey().Bytes(), nil
}
func (mlkem1024) encapsulate(ek []byte) ([]byte, []byte, error) {
	k, err := mlkem.NewEncapsulationKey1024(ek)
	if err != nil {
		return nil, nil, errKEM
	}
	ss, ct := k.Encapsulate()
	return ss, ct, nil
}
func (mlkem1024) decapsulate(seed, ct []byte) ([]byte, error) {
	dk, err := mlkem.NewDecapsulationKey1024(seed)
	if err != nil {
		return nil, errKEM
	}
	return dk.Decapsulate(ct)
}
func (mlkem1024) publicFromSeed(seed []byte) ([]byte, error) {
	dk, err := mlkem.NewDecapsulationKey1024(seed)
	if err != nil {
		return nil, errKEM
	}
	return dk.EncapsulationKey().Bytes(), nil
}

func (mlkem1024) checkEK(ek []byte) error {
	if _, err := mlkem.NewEncapsulationKey1024(ek); err != nil {
		return errKEM
	}
	return nil
}

type frodoKEM struct{ p *frodo.Params }

func (f frodoKEM) name() string { return f.p.Name() }
func (f frodoKEM) ekSize() int  { return f.p.PublicKeySize() }
func (f frodoKEM) ctSize() int  { return f.p.CiphertextSize() }
func (f frodoKEM) generate() ([]byte, []byte, error) {
	seed := make([]byte, f.p.KeySeedSize())
	if _, err := randRead(seed); err != nil {
		return nil, nil, err
	}
	pk, sk := f.p.NewKeyFromSeed(seed)
	zero(sk)
	return seed, pk, nil
}
func (f frodoKEM) encapsulate(ek []byte) ([]byte, []byte, error) {
	if len(ek) != f.p.PublicKeySize() {
		return nil, nil, errKEM
	}
	ct, ss, err := f.p.Encapsulate(ek)
	return ss, ct, err
}
func (f frodoKEM) decapsulate(seed, ct []byte) ([]byte, error) {
	if len(seed) != f.p.KeySeedSize() || len(ct) != f.p.CiphertextSize() {
		return nil, errKEM
	}
	_, sk := f.p.NewKeyFromSeed(seed)
	defer zero(sk)
	return f.p.Decapsulate(sk, ct)
}
func (f frodoKEM) publicFromSeed(seed []byte) ([]byte, error) {
	if len(seed) != f.p.KeySeedSize() {
		return nil, errKEM
	}
	pk, sk := f.p.NewKeyFromSeed(seed)
	zero(sk)
	return pk, nil
}

func (f frodoKEM) checkEK(ek []byte) error {
	if len(ek) != f.p.PublicKeySize() { // every byte string of the right size is a FrodoKEM key
		return errKEM
	}
	return nil
}

var (
	kemMLKEM768  kemScheme = mlkem768{}
	kemMLKEM1024 kemScheme = mlkem1024{}
	kemFrodo976  kemScheme = frodoKEM{frodo.FrodoKEM976}
	kemFrodo1344 kemScheme = frodoKEM{frodo.FrodoKEM1344}
)
