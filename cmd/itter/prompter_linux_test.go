//go:build linux

package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// openPTY opens a pseudo-terminal: tty is the program's side, ptm the side a
// terminal window holds (what is typed goes in there).
func openPTY(t *testing.T) (ptm, tty *os.File) {
	ptm, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skip("no pseudo-terminals here:", err)
	}
	fd := int(ptm.Fd())
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		t.Skip(err)
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		t.Skip(err)
	}
	tty, err = os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { tty.Close(); ptm.Close() })
	return ptm, tty
}

// screen collects what the program shows on the terminal.
type screen struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *screen) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *screen) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func lineMode(t *testing.T, tty *os.File) bool {
	tio, err := unix.IoctlGetTermios(int(tty.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	return tio.Lflag&unix.ICANON != 0
}

// answer has the prompter ask on a terminal, types keys once it is
// listening, and returns its answer.
func answer(t *testing.T, keys string) (string, error) {
	s, _, err := answerSized(t, keys, 0)
	return s, err
}

// answerSized is answer on a terminal that says it is cols wide (0: what a
// new pseudo-terminal says), and also returns what was shown.
func answerSized(t *testing.T, keys string, cols uint16) (string, string, error) {
	ptm, tty := openPTY(t)
	if err := unix.IoctlSetWinsize(int(tty.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Col: cols, Row: 24}); cols > 0 && err != nil {
		t.Fatal(err)
	}
	var shown screen
	go io.Copy(&shown, ptm)
	p := newPrompter(tty, tty)
	type result struct {
		s   string
		err error
	}
	done := make(chan result, 1)
	go func() {
		s, err := p.line("Your itter username", "dflt")
		done <- result{s, err}
	}()
	for deadline := time.Now().Add(5 * time.Second); lineMode(t, tty); {
		if time.Now().After(deadline) {
			t.Fatal("the prompt did not switch the terminal to raw mode")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := ptm.Write([]byte(keys)); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		if !lineMode(t, tty) {
			t.Fatal("the terminal was left in raw mode")
		}
		time.Sleep(20 * time.Millisecond) // the last of what was shown
		return r.s, shown.String(), r.err
	case <-time.After(5 * time.Second):
		t.Fatal("no answer")
	}
	return "", "", nil
}

func TestPromptEditsTheLine(t *testing.T) {
	for _, c := range []struct{ name, keys, want string }{
		{"Backspace as ^H, which some terminals send", "rom\x08\x08oman\r", "roman"},
		{"Backspace as DEL, which most send", "romx\x7fan\r", "roman"},
		{"Ctrl-U clears the line", "admin\x15roman\r", "roman"},
		{"Enter alone takes the default", "\r", "dflt"},
		{"a line feed ends the line too", "roman\n", "roman"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := answer(t, c.keys)
			if err != nil || got != c.want {
				t.Fatalf("got %q, %v; want %q", got, err, c.want)
			}
		})
	}
	for _, cols := range []uint16{0, 80} {
		t.Run(fmt.Sprintf("the prompt shows in one piece on a terminal %d wide", cols), func(t *testing.T) {
			got, shown, err := answerSized(t, "roman\r", cols)
			if err != nil || got != "roman" {
				t.Fatalf("got %q, %v", got, err)
			}
			if !strings.Contains(shown, "Your itter username [dflt]: roman") {
				t.Fatalf("shown: %q", shown)
			}
		})
	}
	t.Run("Ctrl-C gives up", func(t *testing.T) {
		if got, err := answer(t, "rom\x03"); err == nil {
			t.Fatalf("got %q, no error", got)
		}
	})
}
