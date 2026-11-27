package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"itter-cli/internal/api"
	"itter-cli/internal/vault"
)

// The first time someone runs `itter`, there is nothing to learn first: it
// asks who they are on itter and sets the device up, with the SSH key they
// log in to itter with. If the account already uses DMs on another device,
// it offers to add this one to it.

// interactive reports whether a person is sitting at this terminal. Tests
// replace it.
var interactive = func() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

// needsFirstRun reports whether this device still has to be set up (or a
// setup has to be finished).
func needsFirstRun() bool {
	dir := configDir()
	if !vault.Exists(dir) {
		return true
	}
	v, err := vault.Open(dir)
	if err != nil {
		return false // open() reports what is wrong with it
	}
	reg, keys := v.SetupState()
	return !reg || !keys
}

// prompter reads the answers of the person at the terminal.
type prompter struct {
	in  *bufio.Reader
	out io.Writer
}

func (p *prompter) line(question, preset string) (string, error) {
	if preset != "" {
		fmt.Fprintf(p.out, "%s [%s]: ", question, preset)
	} else {
		fmt.Fprintf(p.out, "%s: ", question)
	}
	s, err := p.in.ReadString('\n')
	if err != nil && s == "" {
		return "", userErrf("no answer — nothing was set up")
	}
	if s = strings.TrimSpace(s); s == "" {
		s = preset
	}
	return s, nil
}

func (p *prompter) yes(question string) bool {
	s, err := p.line(question+" [Y/n]", "")
	if err != nil {
		return false
	}
	s = strings.ToLower(s)
	return s == "" || s == "y" || s == "yes"
}

// guessUsername proposes the login name of this computer's user, if it could
// be an itter username.
func guessUsername() string {
	for _, env := range []string{"ITTER_USER", "USER", "LOGNAME"} {
		if u := os.Getenv(env); api.ValidUsername(u) {
			return u
		}
	}
	return ""
}

// firstRun sets this device up, asking what it needs to know.
func firstRun(in io.Reader, out io.Writer) error {
	p := &prompter{in: bufio.NewReader(in), out: out}
	dir := configDir()

	// A setup that was interrupted: finish it, nothing to ask.
	if vault.Exists(dir) {
		v, err := vault.Open(dir)
		if err != nil {
			return err
		}
		me, _ := v.Me()
		fmt.Fprintf(out, "Finishing the setup for @%s.\n", me)
		if v.IsLinked() {
			rc, err := newRelay()
			if err != nil {
				return err
			}
			return linkDevice(dir, rc, me)
		}
		_, err = setupDevice(me)
		return err
	}

	fmt.Fprintln(out, "itter DMs: private messages between itter accounts, encrypted on your own device.")
	fmt.Fprintln(out, "This device is not set up yet. That takes a minute, and the SSH key you log in to itter with.")
	fmt.Fprintln(out)
	name, err := p.line("Your itter username", guessUsername())
	if err != nil {
		return err
	}
	name = stripAt(name)
	if !api.ValidUsername(name) {
		return userErrf("%q is not a valid itter username — run `itter` again", name)
	}

	_, err = setupDevice(name)
	var taken *alreadySetUp
	if errors.As(err, &taken) {
		fmt.Fprintf(out, "\n@%s already uses DMs on another device.\n", name)
		if !p.yes("Add this device to the account? It shows a code that you type on the other one") {
			return userErrf("nothing was set up. To move the account here instead, see `itter help` (burn, recover)")
		}
		rc, rerr := newRelay()
		if rerr != nil {
			return rerr
		}
		err = linkDevice(dir, rc, name)
	}
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "When you talk to someone, compare safety numbers with them (/sn in a chat):")
	fmt.Fprintln(out, "that comparison is what proves who you are talking to.")
	fmt.Fprintln(out)
	_, _ = p.line("Press Enter to open the chat", "")
	return nil
}
