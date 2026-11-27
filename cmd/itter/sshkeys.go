package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"

	"itter-cli/internal/api"
	"itter-cli/internal/relay"
)

// Setting up (or linking) a device takes one signature from an SSH key of
// the itter account: it shows the relay that the account is yours. The key is
// looked for where ssh itself would find it, so nothing has to be prepared:
// in ssh-agent if one is running, and in the usual files in ~/.ssh. A key
// file with a passphrase is only opened, and the passphrase only asked for,
// if the keys that are free to use were not enough.

// defaultKeyFiles are tried in ~/.ssh when ITTER_KEY does not name a file.
// RSA keys are left out on purpose: they are not accepted.
var defaultKeyFiles = []string{"id_ed25519", "id_ecdsa"}

// readPassphrase asks for the passphrase of a key file. Tests replace it.
var readPassphrase = func(prompt string) ([]byte, error) {
	in := os.Stdin
	if !term.IsTerminal(int(in.Fd())) {
		tty, err := os.Open("/dev/tty")
		if err != nil {
			return nil, userErrf("a passphrase is needed and there is no terminal to ask on — `ssh-add` the key first")
		}
		defer tty.Close()
		in = tty
	}
	fmt.Fprint(os.Stderr, prompt)
	pass, err := term.ReadPassword(int(in.Fd()))
	fmt.Fprintln(os.Stderr)
	return pass, err
}

// accountKeys is what was found.
type accountKeys struct {
	ready  []ssh.Signer // usable right away: from ssh-agent, or files without a passphrase
	locked []ssh.Signer // files that ask for their passphrase when first used
	sawRSA bool         // RSA keys were found (and skipped)
	looked []string     // where we looked, for the error message
}

func tilde(path string) string {
	if home, err := os.UserHomeDir(); err == nil && strings.HasPrefix(path, home+string(filepath.Separator)) {
		return "~" + path[len(home):]
	}
	return path
}

// lockedKey is a key file with a passphrase. It is opened on first use.
type lockedKey struct {
	path string
	pub  ssh.PublicKey
	pem  []byte

	once sync.Once
	s    ssh.Signer
	err  error
}

func (k *lockedKey) PublicKey() ssh.PublicKey { return k.pub }

func (k *lockedKey) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	k.once.Do(func() {
		for try := 0; try < 3; try++ {
			pass, err := readPassphrase(fmt.Sprintf("Passphrase for %s: ", tilde(k.path)))
			if err != nil {
				k.err = err
				return
			}
			if k.s, err = ssh.ParsePrivateKeyWithPassphrase(k.pem, pass); err == nil {
				return
			}
		}
		k.err = userErrf("that is not the passphrase of %s", tilde(k.path))
	})
	if k.err != nil {
		return nil, k.err
	}
	return k.s.Sign(rand, data)
}

func agentKeys() []ssh.Signer {
	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		return nil
	}
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil
	}
	signers, err := agent.NewClient(conn).Signers()
	if err != nil {
		conn.Close()
		return nil
	}
	return signers // the connection stays open: the signers use it
}

// findAccountKeys gathers the SSH keys this user could prove an itter
// account with.
func findAccountKeys() (*accountKeys, error) {
	ks := &accountKeys{}
	have := func(pub ssh.PublicKey) bool {
		for _, s := range append(append([]ssh.Signer{}, ks.ready...), ks.locked...) {
			if bytes.Equal(s.PublicKey().Marshal(), pub.Marshal()) {
				return true
			}
		}
		return false
	}
	usable := func(pub ssh.PublicKey) bool {
		// RSA is assumed broken, so RSA keys cannot vouch for the binding.
		if !api.AllowedSSHKeyType(pub.Type()) {
			ks.sawRSA = true
			return false
		}
		return !have(pub)
	}

	ks.looked = append(ks.looked, "ssh-agent")
	for _, s := range agentKeys() {
		if usable(s.PublicKey()) {
			ks.ready = append(ks.ready, s)
		}
	}

	var files []string
	if explicit := os.Getenv("ITTER_KEY"); explicit != "" {
		files = []string{explicit}
	} else if home, err := os.UserHomeDir(); err == nil {
		for _, name := range defaultKeyFiles {
			files = append(files, filepath.Join(home, ".ssh", name))
		}
	}
	for _, path := range files {
		ks.looked = append(ks.looked, tilde(path))
		pem, err := os.ReadFile(path)
		if err != nil {
			if os.Getenv("ITTER_KEY") != "" {
				return nil, userErrf("cannot read the key file ITTER_KEY names (%s): %v", tilde(path), err)
			}
			continue
		}
		s, err := ssh.ParsePrivateKey(pem)
		var missing *ssh.PassphraseMissingError
		switch {
		case err == nil:
			if usable(s.PublicKey()) {
				ks.ready = append(ks.ready, s)
			}
		case asPassphraseMissing(err, &missing):
			pub := missing.PublicKey
			if pub == nil { // older key formats do not show the public half: the .pub file does
				if raw, rerr := os.ReadFile(path + ".pub"); rerr == nil {
					pub, _, _, _, _ = ssh.ParseAuthorizedKey(raw)
				}
			}
			if pub == nil {
				continue
			}
			if usable(pub) {
				ks.locked = append(ks.locked, &lockedKey{path: path, pub: pub, pem: pem})
			}
		}
	}
	if len(ks.ready)+len(ks.locked) > 0 {
		return ks, nil
	}
	if ks.sawRSA {
		return nil, userErrf("only RSA keys were found, and RSA is not accepted. Create a key with `ssh-keygen -t ed25519`, add it to your itter account (settings → keys in the itter app), and try again")
	}
	return nil, userErrf("no SSH key found. itter DMs need the key you log in to itter with, once, to show that the account is yours. Looked in: %s. If it is somewhere else: ITTER_KEY=/path/to/key", strings.Join(ks.looked, ", "))
}

func asPassphraseMissing(err error, target **ssh.PassphraseMissingError) bool {
	pm, ok := err.(*ssh.PassphraseMissingError)
	if ok {
		*target = pm
	}
	return ok
}

// sshSigs signs payload with every given key that will.
func sshSigs(signers []ssh.Signer, payload []byte, random io.Reader) ([]api.SSHSig, error) {
	var sigs []api.SSHSig
	var first error
	for _, s := range signers {
		sig, err := s.Sign(random, payload)
		switch {
		case err != nil:
			if first == nil {
				first = err
			}
		case api.AllowedSSHSigFormat(sig.Format):
			sigs = append(sigs, api.SSHSig{Format: sig.Format, Blob: sig.Blob, Rest: sig.Rest})
		}
	}
	if len(sigs) == 0 && first != nil {
		return nil, first
	}
	return sigs, nil
}

// withAccountKeys runs send with the keys that are free to use first. If
// the relay answers that none of them belongs to the account, the key files
// with a passphrase get their turn, one by one. send returns the relay's
// error unchanged, so that a 403 can be told from everything else.
func (ks *accountKeys) withAccountKeys(send func(signers []ssh.Signer) error) error {
	var rounds [][]ssh.Signer
	if len(ks.ready) > 0 {
		rounds = append(rounds, ks.ready)
	}
	for _, k := range ks.locked {
		rounds = append(rounds, []ssh.Signer{k})
	}
	var err error
	for _, signers := range rounds {
		if err = send(signers); relay.Status(err) != http.StatusForbidden {
			return err
		}
	}
	return err
}
