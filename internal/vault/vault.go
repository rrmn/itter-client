package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"itter-cli/internal/pqc"
)

const (
	pbkdf2Iter = 600_000
	fileName   = "vault.enc"
)

type ChatMsg struct {
	IsOut bool   `json:"is_out"`
	TS    int64  `json:"ts"`
	Text  string `json:"text"`
}

type Vault struct {
	Username     string                  `json:"username"`
	Identity     *pqc.Identity           `json:"identity"`
	SPKs         []*pqc.SignedPreKey     `json:"spks"`
	OTPKs        []*pqc.OneTimePreKey    `json:"otpks"`
	NextPreKeyID uint32                  `json:"next_prekey_id"`
	Sessions     map[string]*pqc.Session `json:"sessions"`
	Messages     map[string][]ChatMsg    `json:"messages"`

	Mu sync.Mutex `json:"-"`
}

func FilePath(dir string) string { return filepath.Join(dir, fileName) }

func Exists(dir string) bool {
	_, err := os.Stat(FilePath(dir))
	return err == nil
}

func Create(dir, username, passphrase string) (*Vault, error) {
	id, err := pqc.GenerateIdentity()
	if err != nil {
		return nil, err
	}
	v := &Vault{
		Username:     username,
		Identity:     id,
		NextPreKeyID: 1,
		Sessions:     map[string]*pqc.Session{},
		Messages:     map[string][]ChatMsg{},
	}
	return v, v.Save(dir, passphrase)
}

func Unlock(dir, passphrase string) (*Vault, error) {
	raw, err := os.ReadFile(FilePath(dir))
	if err != nil {
		return nil, err
	}
	if len(raw) < 16+12+16 {
		return nil, errors.New("vault: file too short / corrupted")
	}
	salt, nonce, ct := raw[:16], raw[16:28], raw[28:]
	key, err := pbkdf2.Key(sha256.New, passphrase, salt, pbkdf2Iter, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	pt, err := g.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, errors.New("vault: wrong passphrase or corrupted file")
	}
	var v Vault
	if err := json.Unmarshal(pt, &v); err != nil {
		return nil, err
	}
	if v.Sessions == nil {
		v.Sessions = map[string]*pqc.Session{}
	}
	if v.Messages == nil {
		v.Messages = map[string][]ChatMsg{}
	}
	return &v, nil
}

func (v *Vault) Save(dir, passphrase string) error {
	v.Mu.Lock()
	defer v.Mu.Unlock()

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	pt, err := json.Marshal(v)
	if err != nil {
		return err
	}
	salt := make([]byte, 16)
	nonce := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	key, err := pbkdf2.Key(sha256.New, passphrase, salt, pbkdf2Iter, 32)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	out := append(salt, nonce...)
	out = append(out, g.Seal(nil, nonce, pt, nil)...)
	tmp := FilePath(dir) + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, FilePath(dir))
}

func (v *Vault) AddMessage(contact string, msg ChatMsg) {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	v.Messages[contact] = append(v.Messages[contact], msg)
}

func (v *Vault) GetMessages(contact string) []ChatMsg {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	return append([]ChatMsg(nil), v.Messages[contact]...)
}

func (v *Vault) GetAllMessages() map[string][]ChatMsg {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	out := map[string][]ChatMsg{}
	for k, msgs := range v.Messages {
		out[k] = append([]ChatMsg(nil), msgs...)
	}
	return out
}

func (v *Vault) GetKnownContacts() []string {
	v.Mu.Lock()
	defer v.Mu.Unlock()
	var out []string
	for k := range v.Sessions {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (v *Vault) CurrentSPK() *pqc.SignedPreKey {
	if len(v.SPKs) == 0 {
		return nil
	}
	return v.SPKs[0]
}

func (v *Vault) FindSPK(id uint32) *pqc.SignedPreKey {
	for _, k := range v.SPKs {
		if k.ID == id {
			return k
		}
	}
	return nil
}

func (v *Vault) FindOTPK(id uint32) *pqc.OneTimePreKey {
	for _, k := range v.OTPKs {
		if k.ID == id {
			return k
		}
	}
	return nil
}

func (v *Vault) ConsumeOTPK(id uint32) {
	for i, k := range v.OTPKs {
		if k.ID == id {
			v.OTPKs = append(v.OTPKs[:i], v.OTPKs[i+1:]...)
			return
		}
	}
}