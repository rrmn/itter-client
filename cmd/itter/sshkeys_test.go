package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestParseSSHConfig(t *testing.T) {
	t.Setenv("HOME", "/home/x")
	c := parseSSHConfig(`user roman
hostname app.itter.sh
identitiesonly yes
identityagent /Users/roman/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock
identityfile ~/.ssh/itter.pub
identityfile /keys/other
`)
	if c.agent != "/Users/roman/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock" {
		t.Fatalf("agent %q", c.agent)
	}
	if !c.identitiesOnly || len(c.files) != 2 || c.files[0] != "/home/x/.ssh/itter.pub" || c.files[1] != "/keys/other" {
		t.Fatalf("%+v", c)
	}
	if c := parseSSHConfig("identityagent SSH_AUTH_SOCK\nidentitiesonly no\n"); c.agent != "" || c.identitiesOnly {
		t.Fatalf("SSH_AUTH_SOCK: %+v", c)
	}
	if c := parseSSHConfig("identityagent none\n"); c.agent != "none" {
		t.Fatalf("none: %+v", c)
	}
}

func newEd25519(t *testing.T) (ed25519.PrivateKey, ssh.PublicKey) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

// keysWorld isolates findAccountKeys: its own home, no ssh agent, and ssh's
// configuration and 1Password's agent as the test says.
func keysWorld(t *testing.T, cfg sshSettings, cfgOK bool, onePassword string) string {
	home := isolateHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")
	oldCfg, old1p := sshConfig, onePasswordAgent
	t.Cleanup(func() { sshConfig, onePasswordAgent = oldCfg, old1p })
	sshConfig = func(host, port string) (sshSettings, bool) {
		if host != "app.itter.sh" || port != "22" {
			t.Errorf("ssh -G for %s:%s", host, port)
		}
		return cfg, cfgOK
	}
	onePasswordAgent = func() string { return onePassword }
	return home
}

func found(t *testing.T, ks *accountKeys, err error, want ...ssh.PublicKey) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	got := ks.all()
	if len(got) != len(want) {
		t.Fatalf("found %d keys, want %d", len(got), len(want))
	}
	for i := range want {
		if string(got[i].PublicKey().Marshal()) != string(want[i].Marshal()) {
			t.Fatalf("key %d is not the one expected", i)
		}
	}
}

func TestFindKeysWhereSSHDoes(t *testing.T) {
	k1, p1 := newEd25519(t)
	k2, p2 := newEd25519(t)
	k3, p3 := newEd25519(t)

	t.Run("the agent ssh's config names (1Password, say), with SSH_AUTH_SOCK empty", func(t *testing.T) {
		sock := startAgent(t, shortDir(t), k1)
		keysWorld(t, sshSettings{agent: sock}, true, "")
		ks, err := findAccountKeys()
		found(t, ks, err, p1)
	})

	t.Run("1Password's agent at its usual place, configured nowhere", func(t *testing.T) {
		sock := startAgent(t, shortDir(t), k1)
		keysWorld(t, sshSettings{}, false, sock)
		ks, err := findAccountKeys()
		found(t, ks, err, p1)
	})

	t.Run("several agents: each key once, the configured agent first", func(t *testing.T) {
		cfgSock := startAgent(t, shortDir(t), k2)
		envSock := startAgent(t, shortDir(t), k1, k2)
		keysWorld(t, sshSettings{agent: cfgSock}, true, "")
		t.Setenv("SSH_AUTH_SOCK", envSock)
		ks, err := findAccountKeys()
		found(t, ks, err, p2, p1)
	})

	t.Run("IdentitiesOnly picks one of many agent keys by its .pub file", func(t *testing.T) {
		sock := startAgent(t, shortDir(t), k1, k2, k3)
		home := keysWorld(t, sshSettings{}, true, "")
		pubFile := filepath.Join(home, ".ssh", "itter.pub")
		os.MkdirAll(filepath.Dir(pubFile), 0o700)
		os.WriteFile(pubFile, ssh.MarshalAuthorizedKey(p2), 0o600)
		cfg := sshSettings{agent: sock, files: []string{pubFile}, identitiesOnly: true}
		sshConfig = func(host, port string) (sshSettings, bool) { return cfg, true }
		ks, err := findAccountKeys()
		found(t, ks, err, p2)
	})

	t.Run("ITTER_KEY naming a .pub file does the same", func(t *testing.T) {
		sock := startAgent(t, shortDir(t), k1, k2, k3)
		home := keysWorld(t, sshSettings{}, false, sock)
		pubFile := filepath.Join(home, "k3.pub")
		os.WriteFile(pubFile, ssh.MarshalAuthorizedKey(p3), 0o600)
		t.Setenv("ITTER_KEY", pubFile)
		ks, err := findAccountKeys()
		found(t, ks, err, p3)
	})

	t.Run("IdentityAgent none: no agents at all", func(t *testing.T) {
		sock := startAgent(t, shortDir(t), k1)
		keysWorld(t, sshSettings{agent: "none"}, true, sock)
		t.Setenv("SSH_AUTH_SOCK", sock)
		_, err := findAccountKeys()
		if err == nil || !strings.Contains(err.Error(), "Couldn't find your SSH key") {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("the key files ssh's config names", func(t *testing.T) {
		home := keysWorld(t, sshSettings{}, true, "")
		file := keyFile(t, filepath.Join(home, "keys", "itter_ed25519"), k1, "")
		sshConfig = func(host, port string) (sshSettings, bool) { return sshSettings{files: []string{file}}, true }
		ks, err := findAccountKeys()
		found(t, ks, err, p1)
	})

	t.Run("only RSA: says so, and what to do", func(t *testing.T) {
		rk, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		sock := startAgent(t, shortDir(t), rk)
		keysWorld(t, sshSettings{agent: sock}, true, "")
		_, err = findAccountKeys()
		if err == nil || !strings.Contains(err.Error(), "RSA is out") || !strings.Contains(err.Error(), "ssh-keygen -t ed25519") {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("nothing anywhere: says where it looked", func(t *testing.T) {
		sock := startAgent(t, shortDir(t))
		keysWorld(t, sshSettings{agent: sock}, true, "")
		_, err := findAccountKeys()
		if err == nil || !strings.Contains(err.Error(), "Looked in: the agent at") || !strings.Contains(err.Error(), "ITTER_KEY=/path/to/key itter") {
			t.Fatalf("got %v", err)
		}
	})
}
