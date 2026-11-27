package main

// The itter view: `itter` shows itter itself, the way `ssh` would, logged in
// with the account's own SSH key, and keeps the DMs one keypress away.
//
// itter's screen is passed through untouched. Two things are added:
//
//   - The itter command `dm` opens the DM view: itter sees that this program
//     is connected and answers with a private marker instead of text (see
//     markerStart). Ctrl-] does the same. In the DM view, Esc or Ctrl-]
//     comes back. The DM view draws on the terminal's alternate screen, so
//     itter's screen is still there afterwards, and what itter sent in the
//     meantime is shown then.
//   - New DMs show in the terminal's title, with one ring of its bell.
//
// Nothing about the DMs goes to itter: they are encrypted on this device and
// travel through the DM relay, as always.

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/muesli/cancelreader"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/rrmn/itter-client/internal/api"
	"github.com/rrmn/itter-client/internal/relay"
	"github.com/rrmn/itter-client/internal/vault"
)

const (
	switchKey   = 0x1d // Ctrl-]
	markerStart = "\x1b]7777;itter-client;"
	markerMax   = 128     // longest marker body accepted
	heldLimit   = 4 << 20 // itter output kept while the DMs are open
	accountFile = "account"
)

// clientVersion is how itter's server recognises this program (and which
// version it is). The SSH standard allows no '-' in this part.
func clientVersion() string {
	v := strings.Map(func(r rune) rune {
		if r == '.' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
			return r
		}
		return '_'
	}, version)
	return "SSH-2.0-itterclient_" + v
}

// --- finding the markers in itter's output ---

// markerScanner splits what itter sends into text for the screen and the
// markers meant for this program. A marker can arrive in two pieces; the
// start of one is held back until the rest is there (or until flush).
type markerScanner struct{ pending []byte }

func (s *markerScanner) feed(b []byte, text func([]byte), marker func(string)) {
	data := append(s.pending, b...)
	s.pending = nil
	for len(data) > 0 {
		i := bytes.Index(data, []byte(markerStart))
		if i < 0 {
			k := partialSuffix(data, markerStart)
			text(data[:len(data)-k])
			if k > 0 {
				s.pending = bytes.Clone(data[len(data)-k:])
			}
			return
		}
		text(data[:i])
		body := data[i+len(markerStart):]
		end := bytes.IndexByte(body, '\a')
		switch {
		case end >= 0 && end <= markerMax:
			marker(string(body[:end]))
			data = body[end+1:]
		case end < 0 && len(body) <= markerMax:
			s.pending = bytes.Clone(data[i:]) // the rest is still on its way
			return
		default: // too long to be one of ours: just text
			text(data[i : i+len(markerStart)])
			data = body
		}
	}
}

// flush gives up waiting for the rest of a marker: what was held is text.
func (s *markerScanner) flush(text func([]byte)) {
	if len(s.pending) > 0 {
		text(s.pending)
		s.pending = nil
	}
}

// partialSuffix is the length of the longest end of data that is the start
// of pat (shorter than pat itself).
func partialSuffix(data []byte, pat string) int {
	for k := min(len(data), len(pat)-1); k > 0; k-- {
		if bytes.HasSuffix(data, []byte(pat[:k])) {
			return k
		}
	}
	return 0
}

// parseMarker reads a marker body: "dm" or "dm;@user". ok is false for
// anything else, which is then ignored.
func parseMarker(body string) (target string, ok bool) {
	cmd, arg, _ := strings.Cut(body, ";")
	if cmd != "dm" {
		return "", false
	}
	if arg == "" {
		return "", true
	}
	name := stripAt(arg)
	if !api.ValidUsername(name) {
		return "", true
	}
	return name, true
}

// --- where itter's output stands ---

// ansiTracker follows itter's output through escape sequences and UTF-8, so
// that the program only adds something of its own (the title) between two
// complete pieces, never in the middle of one.
type ansiTracker struct {
	state int
	utf8  int // continuation bytes still to come
}

const (
	stGround = iota
	stEsc
	stCSI
	stString    // OSC, DCS, APC, PM, SOS: up to BEL or ESC \
	stStringEsc // ESC inside one of those
	stOneMore   // ESC ( and friends: one more byte
)

func (a *ansiTracker) feed(b []byte) {
	for _, c := range b {
		switch a.state {
		case stGround:
			switch {
			case c == 0x1b:
				a.state, a.utf8 = stEsc, 0
			case c >= 0xc0 && c <= 0xdf:
				a.utf8 = 1
			case c >= 0xe0 && c <= 0xef:
				a.utf8 = 2
			case c >= 0xf0 && c <= 0xf7:
				a.utf8 = 3
			case c >= 0x80 && c <= 0xbf:
				a.utf8 = max(0, a.utf8-1)
			default:
				a.utf8 = 0
			}
		case stEsc:
			switch c {
			case '[':
				a.state = stCSI
			case ']', 'P', 'X', '^', '_':
				a.state = stString
			case '(', ')', '*', '+', '-', '.', '/', '#', '%', ' ':
				a.state = stOneMore
			default:
				a.state = stGround
			}
		case stCSI:
			if c >= 0x40 && c <= 0x7e {
				a.state = stGround
			}
		case stString:
			switch c {
			case 0x07:
				a.state = stGround
			case 0x1b:
				a.state = stStringEsc
			}
		case stStringEsc:
			if c == '\\' {
				a.state = stGround
			} else {
				a.state = stString
			}
		case stOneMore:
			a.state = stGround
		}
	}
}

func (a *ansiTracker) safe() bool { return a.state == stGround && a.utf8 == 0 }

// --- the view ---

// view connects the terminal with itter's session.
type view struct {
	out     io.Writer                                 // the terminal
	toItter io.Writer                                 // itter's input
	resize  func()                                    // tells itter the terminal's size
	keys    func() (cancelreader.CancelReader, error) // a new reader of the keyboard
	openDMs func(target string)                       // shows the DMs; returns when the user is back
	bell    bool

	mu         sync.Mutex
	inDMs      bool
	held       []byte
	dropped    bool
	ansi       ansiTracker
	scan       markerScanner
	unread     int
	titleDirty bool
	ring       bool

	switchCh chan string
}

func newView(out, toItter io.Writer) *view {
	return &view{out: out, toItter: toItter, switchCh: make(chan string, 1), titleDirty: true}
}

// write shows what itter sent, or keeps it while the DMs are open.
func (v *view) write(b []byte) {
	if len(b) == 0 {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.inDMs {
		if len(v.held)+len(b) > heldLimit {
			v.held, v.dropped = nil, true
		}
		v.held = append(v.held, b...)
		return
	}
	v.out.Write(b)
	v.ansi.feed(b)
	v.maybeTitle()
}

// maybeTitle updates the title if it is due and the output is at a place
// where something can be added. v.mu is held.
func (v *view) maybeTitle() {
	if v.inDMs || !v.ansi.safe() || (!v.titleDirty && !v.ring) {
		return
	}
	var b strings.Builder
	if v.titleDirty {
		b.WriteString("\x1b]0;" + titleText(v.unread) + "\a")
		v.titleDirty = false
	}
	if v.ring && v.bell {
		b.WriteByte('\a')
	}
	v.ring = false
	io.WriteString(v.out, b.String())
}

func titleText(unread int) string {
	switch unread {
	case 0:
		return "itter"
	case 1:
		return "itter — 1 new DM (type dm)"
	}
	return fmt.Sprintf("itter — %d new DMs (type dm)", unread)
}

// setUnread is told how many DMs are unread.
func (v *view) setUnread(n int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if n == v.unread {
		return
	}
	if n > v.unread {
		v.ring = true
	}
	v.unread, v.titleDirty = n, true
	v.maybeTitle()
}

// marker handles one marker from itter.
func (v *view) marker(body string) {
	if target, ok := parseMarker(body); ok {
		v.requestDMs(target)
	}
}

func (v *view) requestDMs(target string) {
	select {
	case v.switchCh <- target:
	default: // one is already on its way
	}
}

// pumpItter shows what itter sends until it stops sending.
func (v *view) pumpItter(from io.Reader) {
	chunks := make(chan []byte, 4)
	go func() {
		defer close(chunks)
		buf := make([]byte, 32<<10)
		for {
			n, err := from.Read(buf)
			if n > 0 {
				chunks <- bytes.Clone(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	var wait <-chan time.Time
	for {
		select {
		case c, ok := <-chunks:
			if !ok {
				v.scan.flush(v.write)
				return
			}
			v.scan.feed(c, v.write, v.marker)
			wait = nil
			if len(v.scan.pending) > 0 {
				wait = time.After(150 * time.Millisecond)
			}
		case <-wait:
			v.scan.flush(v.write)
			wait = nil
		}
	}
}

// pumpKeys sends what is typed to itter until the reader is cancelled.
// Ctrl-] asks for the DMs.
func (v *view) pumpKeys(r io.Reader) {
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			b := buf[:n]
			if i := bytes.IndexByte(b, switchKey); i >= 0 {
				v.toItter.Write(b[:i])
				v.requestDMs("")
				// What was typed after it was meant for the DMs, which are
				// not open yet: dropped.
			} else {
				v.toItter.Write(b)
			}
		}
		if err != nil {
			return
		}
	}
}

// run passes the keyboard to itter until done is closed, opening the DMs
// whenever asked.
func (v *view) run(done <-chan struct{}, resized <-chan os.Signal) error {
	for {
		kr, err := v.keys()
		if err != nil {
			return err
		}
		keysDone := make(chan struct{})
		go func() { v.pumpKeys(kr); close(keysDone) }()

		var target string
		open := false
	wait:
		for {
			select {
			case <-done:
				kr.Cancel()
				<-keysDone
				kr.Close()
				return nil
			case <-resized:
				v.resize()
			case target = <-v.switchCh:
				open = true
				break wait
			}
		}
		kr.Cancel()
		<-keysDone
		kr.Close()
		if !open {
			continue
		}

		v.mu.Lock()
		v.inDMs = true
		v.mu.Unlock()

		v.openDMs(target)

		v.mu.Lock()
		v.inDMs = false
		held, dropped := v.held, v.dropped
		v.held, v.dropped = nil, false
		if dropped {
			io.WriteString(v.out, "\r\n[itter sent more than could be kept while your DMs were open: type clear to redraw]\r\n")
		}
		v.out.Write(held)
		v.ansi.feed(held)
		v.titleDirty = true
		v.maybeTitle()
		v.mu.Unlock()
		v.resize() // the terminal may have changed size meanwhile
		select {
		case <-done:
			return nil
		default:
		}
	}
}

// --- the command ---

// currentAccount is the itter username this device uses, "" if it does not
// know one yet. remembered is true if the program logged in with it before.
func currentAccount() (name string, remembered bool) {
	dir := configDir()
	if b, err := os.ReadFile(filepath.Join(dir, accountFile)); err == nil {
		if n := strings.TrimSpace(string(b)); api.ValidUsername(n) {
			return n, true
		}
	}
	// DMs set up on this device: their account.
	if b, err := os.ReadFile(vault.UsernamePath(dir)); err == nil {
		if n := strings.TrimSpace(string(b)); api.ValidUsername(n) {
			return n, true
		}
	}
	return "", false
}

func rememberAccount(name string) {
	dir := configDir()
	if os.MkdirAll(dir, 0o700) == nil {
		_ = os.WriteFile(filepath.Join(dir, accountFile), []byte(name+"\n"), 0o600)
	}
}

func cmdItter() error {
	if !interactive() {
		return userErrf("`itter` shows itter, and needs a terminal for it. In scripts, use `itter dm` and `itter read`")
	}
	p := &prompter{in: bufio.NewReader(os.Stdin), out: os.Stdout}
	name, remembered := currentAccount()
	if name == "" {
		fmt.Println("itter: microblogging in your terminal, with private messages.")
		fmt.Println()
		n, err := p.line("Your itter username (a new one signs you up)", guessUsername())
		if err != nil {
			return err
		}
		name = stripAt(n)
		if !api.ValidUsername(name) {
			return userErrf("%q is not a valid itter username (3 to 20 letters, digits or _)", name)
		}
	}
	keys, err := findAccountKeys()
	if err != nil {
		return err
	}
	t, err := itterTunnel()
	if err != nil {
		return err
	}
	cli, err := loginOrSignUp(t, name, keys, p, !remembered)
	if err != nil {
		return err
	}
	defer cli.Close()
	rememberAccount(name)
	return showItter(cli, name)
}

// loginOrSignUp logs in to itter. If that fails for a name this device has
// not used before, it offers to create the account with the user's key.
func loginOrSignUp(t *relay.Tunnel, name string, keys *accountKeys, p *prompter, mayCreate bool) (*ssh.Client, error) {
	ctx := context.Background()
	signers := keys.all()
	auth := ssh.PublicKeysCallback(func() ([]ssh.Signer, error) { return signers, nil })
	cli, err := t.Login(ctx, name, clientVersion(), auth)
	var ae *relay.AuthError
	if err == nil || !errors.As(err, &ae) {
		return cli, explainLogin(err)
	}
	if !mayCreate {
		return nil, userErrf("itter did not let @%s in with your SSH key. If the key changed, add the new one in itter (settings key add <name> <public key>) from a device that still gets in", name)
	}
	fmt.Printf("\nitter did not let @%s in with your SSH key.\n", name)
	fmt.Printf("If @%s is yours, add this key to it in itter: settings key add <name> <public key>.\n", name)
	key := signers[0]
	if !p.yes(fmt.Sprintf("If @%s is new: create it now, with your key %s", name, ssh.FingerprintSHA256(key.PublicKey()))) {
		return nil, userErrf("not logged in")
	}
	reg, err := t.Login(ctx, "register:"+name, clientVersion(), ssh.PublicKeys(key))
	if errors.As(err, &ae) {
		return nil, userErrf("%s", strings.TrimSpace(ae.Error()))
	}
	if err != nil {
		return nil, explainLogin(err)
	}
	// itter creates the account in a session of its own and says so.
	if s, err := reg.NewSession(); err == nil {
		s.Stdout, s.Stderr = io.Discard, io.Discard
		if s.Shell() == nil {
			_ = s.Wait()
		}
	}
	reg.Close()
	cli, err = t.Login(ctx, name, clientVersion(), auth)
	if err != nil {
		return nil, userErrf("@%s was not created (%v). The name may be taken: try another one", name, err)
	}
	fmt.Printf("Welcome to itter, @%s!\n", name)
	return cli, nil
}

func explainLogin(err error) error {
	if err == nil {
		return nil
	}
	var he *relay.HostKeyError
	if errors.As(err, &he) {
		return userErrf("itter's server showed another SSH host key than the one on record (%s, in %s). That can mean someone is in between: not connecting", he.Got, tilde(he.Record))
	}
	return userErrf("cannot reach itter: %v", err)
}

// showItter runs itter's session in this terminal until it ends.
func showItter(cli *ssh.Client, name string) error {
	sess, err := cli.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	toItter, err := sess.StdinPipe()
	if err != nil {
		return err
	}
	fromItter, err := sess.StdoutPipe()
	if err != nil {
		return err
	}
	sess.Stderr = os.Stderr
	fd := int(os.Stdin.Fd())
	w, h, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		w, h = 80, 24
	}
	termType := os.Getenv("TERM")
	if termType == "" || termType == "dumb" {
		termType = "xterm-256color"
	}
	if err := sess.RequestPty(termType, h, w, ssh.TerminalModes{ssh.TTY_OP_ISPEED: 38400, ssh.TTY_OP_OSPEED: 38400}); err != nil {
		return err
	}
	if err := sess.Shell(); err != nil {
		return err
	}

	cooked, err := term.MakeRaw(fd)
	if err != nil {
		return err
	}
	restore := sync.OnceFunc(func() {
		_ = term.Restore(fd, cooked)
		os.Stdout.WriteString("\x1b]0;\a\x1b[23;0t") // the title as it was
	})
	defer restore()
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(quit)
	go func() {
		if _, ok := <-quit; ok {
			restore()
			os.Exit(1)
		}
	}()

	v := newView(os.Stdout, toItter)
	v.bell = os.Getenv("ITTER_BELL") != "0"
	v.resize = func() {
		if w, h, err := term.GetSize(int(os.Stdout.Fd())); err == nil {
			_ = sess.WindowChange(h, w)
		}
	}
	v.keys = func() (cancelreader.CancelReader, error) { return cancelreader.NewReader(os.Stdin) }
	os.Stdout.WriteString("\x1b[22;0t") // keep the title, to put it back at the end
	hub := &dmHub{name: name, onUnread: v.setUnread, cooked: func() { _ = term.Restore(fd, cooked) },
		raw: func() { _, _ = term.MakeRaw(fd) }}
	hub.startIfReady()
	v.openDMs = hub.open

	done := make(chan struct{})
	var sessErr error
	go func() {
		v.pumpItter(fromItter)
		sessErr = sess.Wait()
		close(done)
	}()
	go keepAlive(cli, done)
	resized := make(chan os.Signal, 1)
	notifyResize(resized)
	defer signal.Stop(resized)

	err = v.run(done, resized)
	restore()
	var exitMissing *ssh.ExitMissingError
	switch {
	case err != nil:
		return err
	case sessErr == nil || errors.As(sessErr, &exitMissing):
		fmt.Println()
		return nil
	}
	return userErrf("\nthe connection to itter was lost (%v)", sessErr)
}

// keepAlive asks the server for a sign of life now and then, so that idle
// connections are not dropped on the way, and notices when one is gone.
func keepAlive(cli *ssh.Client, done <-chan struct{}) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			if _, _, err := cli.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				cli.Close()
				return
			}
		}
	}
}
