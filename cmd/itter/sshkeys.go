package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"

	"github.com/rrmn/itter-client/internal/api"
	"github.com/rrmn/itter-client/internal/relay"
)

// `itter` logs in to itter with an SSH key of the account, and setting up (or
// linking) a device takes one signature with it, which shows the relay that
// the account is yours. The key is looked for where ssh itself would find it
// for itter's host, so nothing has to be prepared: in the agent ssh would use
// (IdentityAgent in ~/.ssh/config, like 1Password's, or else the one in
// SSH_AUTH_SOCK), in 1Password's agent at its usual place, and in the key
// files ssh would try (IdentityFile; by default ~/.ssh/id_ed25519 and
// id_ecdsa). `ssh -G` tells what ssh would use, ~/.ssh/config's Include and
// Match included. A key file with a passphrase is only opened, and the
// passphrase only asked for, if the keys that are free to use were not enough.

// defaultKeyFiles are tried in ~/.ssh when neither ITTER_KEY nor ssh's
// configuration names files. RSA keys are left out on purpose: they are not
// accepted.
var defaultKeyFiles = []string{"id_ed25519", "id_ecdsa"}

// sshSettings is what ssh would use for itter's host.
type sshSettings struct {
	agent          string   // IdentityAgent: a socket, "none", or "" (SSH_AUTH_SOCK)
	files          []string // IdentityFile, in order
	identitiesOnly bool     // only the keys of those files, also from agents
}

// sshConfig asks ssh what it would use for host:port (`ssh -G`). Tests
// replace it.
var sshConfig = func(host, port string) (sshSettings, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ssh", "-G", "-p", port, host).Output()
	if err != nil {
		return sshSettings{}, false
	}
	return parseSSHConfig(string(out)), true
}

func parseSSHConfig(out string) sshSettings {
	var c sshSettings
	for _, line := range strings.Split(out, "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch strings.ToLower(key) {
		case "identityagent":
			c.agent = expandHome(val)
			if c.agent == "SSH_AUTH_SOCK" {
				c.agent = ""
			}
		case "identityfile":
			c.files = append(c.files, expandHome(val))
		case "identitiesonly":
			c.identitiesOnly = val == "yes"
		}
	}
	return c
}

func expandHome(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return home + path[1:]
		}
	}
	return path
}

// onePasswordAgent is the socket of 1Password's SSH agent, if it is there.
// Tests replace it.
var onePasswordAgent = func() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	for _, p := range []string{
		filepath.Join(home, "Library", "Group Containers", "2BUA8C4S2C.com.1password", "t", "agent.sock"), // macOS
		filepath.Join(home, ".1password", "agent.sock"),                                                   // Linux
	} {
		if fi, err := os.Stat(p); err == nil && fi.Mode()&os.ModeSocket != 0 {
			return p
		}
	}
	return ""
}

// readPassphrase asks for the passphrase of a key file. Tests replace it.
var readPassphrase = func(prompt string) ([]byte, error) {
	in := os.Stdin
	if !term.IsTerminal(int(in.Fd())) {
		tty, err := os.Open("/dev/tty")
		if err != nil {
			return nil, userErrf("This key needs its passphrase, and there's no terminal to ask on. ssh-add it first?")
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

// all is every key found, the ones free to use first.
func (ks *accountKeys) all() []ssh.Signer {
	return append(append([]ssh.Signer{}, ks.ready...), ks.locked...)
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
		k.err = userErrf("That's not the passphrase of %s.", tilde(k.path))
	})
	if k.err != nil {
		return nil, k.err
	}
	return k.s.Sign(rand, data)
}

// agentKeys asks the SSH agent at socket for its keys.
func agentKeys(socket string) []ssh.Signer {
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

// publicKeyOf is the public half of a key file, without its passphrase: from
// the file itself (a private key in OpenSSH's format, or a public key) or
// from the .pub file next to it.
func publicKeyOf(path string) ssh.PublicKey {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	if pub, _, _, _, err := ssh.ParseAuthorizedKey(raw); err == nil {
		return pub
	}
	if s, err := ssh.ParsePrivateKey(raw); err == nil {
		return s.PublicKey()
	} else if pm, ok := err.(*ssh.PassphraseMissingError); ok && pm.PublicKey != nil {
		return pm.PublicKey
	}
	if raw, err := os.ReadFile(path + ".pub"); err == nil {
		if pub, _, _, _, err := ssh.ParseAuthorizedKey(raw); err == nil {
			return pub
		}
	}
	return nil
}

// findAccountKeys gathers the SSH keys this user could prove an itter
// account with.
func findAccountKeys() (*accountKeys, error) {
	ks := &accountKeys{}
	explicit := os.Getenv("ITTER_KEY")
	var cfg sshSettings
	var cfgOK bool
	if addr, err := itterHost(); err == nil {
		if host, port, err := net.SplitHostPort(addr); err == nil {
			cfg, cfgOK = sshConfig(host, port)
		}
	}

	// The key files to try: ITTER_KEY, or the ones ssh would try.
	var files []string
	switch {
	case explicit != "":
		files = []string{expandHome(explicit)}
	case cfgOK && len(cfg.files) > 0:
		files = cfg.files
	default:
		if home, err := os.UserHomeDir(); err == nil {
			for _, name := range defaultKeyFiles {
				files = append(files, filepath.Join(home, ".ssh", name))
			}
		}
	}

	// Only these keys, if ITTER_KEY names one or ssh says IdentitiesOnly
	// (which is how people pick one of the many keys in 1Password).
	var only []ssh.PublicKey
	if explicit != "" || cfg.identitiesOnly {
		for _, f := range files {
			if pub := publicKeyOf(f); pub != nil {
				only = append(only, pub)
			}
		}
	}
	allowed := func(pub ssh.PublicKey) bool {
		if len(only) == 0 {
			return true
		}
		for _, o := range only {
			if bytes.Equal(o.Marshal(), pub.Marshal()) {
				return true
			}
		}
		return false
	}
	have := func(pub ssh.PublicKey) bool {
		for _, s := range ks.all() {
			if bytes.Equal(s.PublicKey().Marshal(), pub.Marshal()) {
				return true
			}
		}
		return false
	}
	usable := func(pub ssh.PublicKey) bool {
		if !allowed(pub) || have(pub) {
			return false
		}
		// RSA is assumed broken, so RSA keys cannot vouch for the binding.
		if !api.AllowedSSHKeyType(pub.Type()) {
			ks.sawRSA = true
			return false
		}
		return true
	}

	// The agents: the one ssh would use, the one in SSH_AUTH_SOCK, 1Password's.
	looked := func(place string) {
		if !slices.Contains(ks.looked, place) {
			ks.looked = append(ks.looked, place)
		}
	}
	if cfg.agent != "none" {
		var socks []string
		for _, sock := range []string{cfg.agent, os.Getenv("SSH_AUTH_SOCK"), onePasswordAgent()} {
			if sock != "" && !slices.Contains(socks, sock) {
				socks = append(socks, sock)
			}
		}
		for _, sock := range socks {
			looked(agentName(sock))
			for _, s := range agentKeys(sock) {
				if usable(s.PublicKey()) {
					ks.ready = append(ks.ready, s)
				}
			}
		}
		looked("ssh-agent")
		looked("1Password")
	}

	for _, path := range files {
		pem, err := os.ReadFile(path)
		if err == nil || explicit != "" || slices.Contains(defaultKeyFiles, filepath.Base(path)) {
			looked(tilde(path)) // ssh's other default names (id_rsa, id_dsa, ...) only if they exist
		}
		if err != nil {
			if explicit != "" {
				return nil, userErrf("Can't read the key file ITTER_KEY names (%s): %v", tilde(path), err)
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
		return nil, userErrf("Only RSA keys here, and RSA is out (we assume it's broken).\n" +
			"Make a new key: ssh-keygen -t ed25519\n" +
			"Add it to your account in itter: settings key add <name> <public key>\n" +
			"Then try again.")
	}
	return nil, userErrf("Couldn't find your SSH key. itter needs the one you log in to itter with.\n"+
		"Looked in: %s.\n"+
		"Somewhere else? Try: ITTER_KEY=/path/to/key itter", strings.Join(ks.looked, ", "))
}

// agentName says which agent a socket is, for messages.
func agentName(sock string) string {
	switch {
	case strings.Contains(strings.ToLower(sock), "1password"):
		return "1Password"
	case sock == os.Getenv("SSH_AUTH_SOCK"):
		return "ssh-agent"
	}
	return "the agent at " + tilde(sock)
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
