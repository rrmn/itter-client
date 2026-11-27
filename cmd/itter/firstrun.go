package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/rrmn/itter-client/internal/api"
	"github.com/rrmn/itter-client/internal/vault"
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

// prompter reads the answers of the person at the terminal. On a terminal
// it edits the line itself, so Backspace works whichever code the terminal
// sends for it (^? or ^H), as in a shell. Elsewhere (scripts, tests) it reads
// lines as they come.
type prompter struct {
	in  *bufio.Reader
	out io.Writer
	tty *os.File // the terminal the answers come from, if they do
}

func newPrompter(in io.Reader, out io.Writer) *prompter {
	p := &prompter{in: bufio.NewReader(in), out: out}
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		p.tty = f
	}
	return p
}

func (p *prompter) line(question, preset string) (string, error) {
	prompt := question + ": "
	if preset != "" {
		prompt = fmt.Sprintf("%s [%s]: ", question, preset)
	}
	s, err := p.read(prompt)
	if err != nil && s == "" {
		return "", &byeErr{"Later!"}
	}
	if s = strings.TrimSpace(s); s == "" {
		s = preset
	}
	return s, nil
}

// read shows the prompt and reads one line. On a terminal that is x/term's
// line editor in raw mode: Backspace (^? and ^H), Ctrl-U, Ctrl-W and the
// arrows work; Ctrl-C and Ctrl-D give up.
func (p *prompter) read(prompt string) (string, error) {
	if p.tty != nil {
		fd := int(p.tty.Fd())
		if old, err := term.MakeRaw(fd); err == nil {
			t := term.NewTerminal(struct {
				io.Reader
				io.Writer
			}{lfIsEnter{p.tty}, p.out}, prompt)
			// A terminal that says it is 0 wide (some do) keeps the
			// editor's 80 columns: with 0 it would wrap after every letter.
			if w, h, err := term.GetSize(fd); err == nil && w > 0 && h > 0 {
				_ = t.SetSize(w, h)
			}
			s, err := t.ReadLine()
			_ = term.Restore(fd, old)
			if err != nil {
				fmt.Fprintln(p.out)
			}
			return s, err
		}
	}
	fmt.Fprint(p.out, prompt)
	return p.in.ReadString('\n')
}

// lfIsEnter makes a line feed end the line too: terminals send a carriage
// return for Enter, but programs that type into one often send a line feed.
type lfIsEnter struct{ r io.Reader }

func (l lfIsEnter) Read(b []byte) (int, error) {
	n, err := l.r.Read(b)
	for i := range b[:n] {
		if b[i] == '\n' {
			b[i] = '\r'
		}
	}
	return n, err
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
	p := newPrompter(in, out)
	dir := configDir()

	// A setup that was interrupted: finish it, nothing to ask.
	if vault.Exists(dir) {
		return setUpDMs(p, out, "")
	}

	fmt.Fprintln(out, "itter DMs: end-to-end encrypted, so only you and the people you write to can read them.")
	fmt.Fprintln(out, "This computer isn't set up for DMs yet. Takes a minute, and the SSH key you log in to itter with.")
	fmt.Fprintln(out)
	name, err := p.line("Your itter username", guessUsername())
	if err != nil {
		return err
	}
	name = stripAt(name)
	if !api.ValidUsername(name) {
		return userErrf("Invalid username. Must be 3-20 characters (letters, numbers, underscores).")
	}

	if err := setUpDMs(p, out, name); err != nil {
		return err
	}
	fmt.Fprintln(out, "Tip: compare safety numbers with the people you write to (/sn in a chat).")
	fmt.Fprintln(out, "That's how you know it's really them.")
	fmt.Fprintln(out)
	_, _ = p.line("Press Enter to open the chat", "")
	return nil
}

// setUpDMs sets this device up for name's DMs: as the account's first
// device, or, if the account already uses DMs elsewhere, linked to it (after
// asking). A setup that was interrupted is finished instead, for the account
// it was for.
func setUpDMs(p *prompter, out io.Writer, name string) error {
	dir := configDir()
	if vault.Exists(dir) {
		v, err := vault.Open(dir)
		if err != nil {
			return err
		}
		me, _ := v.Me()
		fmt.Fprintf(out, "Finishing the setup for @%s...\n", me)
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
	_, err := setupDevice(name)
	var taken *alreadySetUp
	if errors.As(err, &taken) {
		fmt.Fprintf(out, "\n@%s already has DMs on another device.\n", name)
		if !p.yes("Add this one too? You'll get a code to type on the other one") {
			return &byeErr{"Okay, nothing was set up. (To move your DMs here instead: burn and recover, in itter help.)"}
		}
		rc, rerr := newRelay()
		if rerr != nil {
			return rerr
		}
		err = linkDevice(dir, rc, name)
	}
	return err
}
