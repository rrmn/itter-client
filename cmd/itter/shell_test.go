package main

import (
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/rrmn/itter-client/internal/api"
	"github.com/rrmn/itter-client/internal/relay"
	"github.com/rrmn/itter-client/internal/vault"
)

// The shell is tested without a terminal: lines are "typed" into the model
// and the rendered view is inspected.

type shellT struct {
	t *testing.T
	m appModel
}

func newShell(t *testing.T, u *user) *shellT {
	s := &shellT{t: t, m: newModel(u.app())}
	s.feed(tea.WindowSizeMsg{Width: 140, Height: 40})
	return s
}

func (s *shellT) feed(msg tea.Msg) tea.Cmd {
	next, cmd := s.m.Update(msg)
	s.m = next.(appModel)
	return cmd
}

// run executes a command the model returned (a lookup, saving the read
// markers) and feeds its result back, like bubbletea would.
func (s *shellT) run(cmd tea.Cmd) {
	for cmd != nil {
		msg := cmd()
		if msg == nil {
			return
		}
		if _, quit := msg.(tea.QuitMsg); quit {
			return
		}
		cmd = s.feed(msg)
	}
}

// line types a line and presses Enter; background work the line starts
// (sends, lookups) is run to completion, like the real workers would.
func (s *shellT) line(text string) {
	s.t.Helper()
	s.m.ti.SetValue(text)
	s.run(s.feed(tea.KeyMsg{Type: tea.KeyEnter}))
}

// deliver runs queued sends the way sendWorker does.
func (s *shellT) deliver() {
	for {
		select {
		case req := <-s.m.sendCh:
			out, err := s.m.a.send(req.target, req.text)
			s.run(s.feed(sendDoneMsg{id: req.id, req: req, out: out, err: err, when: time.Now()}))
		default:
			return
		}
	}
}

// keys types text one key at a time (completion follows what is typed).
func (s *shellT) keys(text string) {
	for _, r := range text {
		s.feed(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
}

func (s *shellT) view() string { return s.m.View() }

func (s *shellT) wantView(sub string) {
	s.t.Helper()
	if !strings.Contains(s.view(), sub) {
		s.t.Fatalf("view does not contain %q:\n%s", sub, s.view())
	}
}

func (s *shellT) wantNoView(sub string) {
	s.t.Helper()
	if strings.Contains(s.view(), sub) {
		s.t.Fatalf("view contains %q:\n%s", sub, s.view())
	}
}

func TestShell(t *testing.T) {
	w := newWorld(t)
	alice, bob := w.ready(t, "alice"), w.ready(t, "bob")
	w.ready(t, "carol")
	s := newShell(t, alice)

	t.Run("an empty shell says how to start", func(t *testing.T) {
		s.t = t
		s.wantView("No conversations yet. Write to someone:  @user hello")
	})

	t.Run("outside a chat nothing is sent by accident", func(t *testing.T) {
		s.t = t
		s.line("hello world")
		s.wantView("You are not in a chat")
		if len(s.m.sendCh) != 0 {
			t.Fatal("something was queued for sending")
		}
		s.line("/help")
		s.wantView("/verify [@user]")
		s.line("/clear")
		s.wantNoView("/verify [@user]")
	})

	t.Run("sending is immediate on screen and never blocks the UI", func(t *testing.T) {
		s.t = t
		s.line("/chat @bob")
		s.wantView("(alice) -> @bob>")
		s.wantView("@bob · no messages yet")
		s.line("hello bob")
		s.wantView("hello bob")
		s.wantView("[sending…]") // shown before any network I/O happened
		s.deliver()
		s.wantNoView("[sending…]")
		s.wantView("hello bob")
		s.wantView("not verified")
		expectTexts(t, bob.pull("alice"), "hello bob")
	})

	t.Run("in a chat only slash lines are commands", func(t *testing.T) {
		s.t = t
		for _, text := range []string{"exit", "x", "chat later?", "dm me maybe", "clear"} {
			s.line(text)
		}
		s.line("//slash at the start")
		s.deliver()
		expectTexts(t, bob.pull("alice"), "exit", "x", "chat later?", "dm me maybe", "clear", "/slash at the start")
		s.line("/nosuchcommand")
		s.wantView("Unknown command /nosuchcommand")
		if len(s.m.sendCh) != 0 {
			t.Fatal("an unknown command was sent as a message")
		}
	})

	t.Run("a message that cannot be sent comes back into the input", func(t *testing.T) {
		s.t = t
		s.line("/dm @nosuchuser are you there?")
		s.deliver()
		s.wantView("Not sent: there is no itter user @nosuchuser")
		if s.m.ti.Value() != "are you there?" {
			t.Fatalf("input is %q, want the text back", s.m.ti.Value())
		}
		s.m.ti.SetValue("")
	})

	t.Run("offline sends are queued and say so", func(t *testing.T) {
		s.t = t
		a := s.m.a
		a.rc.HC.Transport = &flaky{match: isSend}
		s.line("sent while offline")
		s.deliver()
		a.rc.HC.Transport = nil
		s.wantView("sent while offline")
		s.wantView("[queued]")
		s.wantView("Queued, will be sent automatically")
		if err := s.m.a.flush(); err != nil {
			t.Fatal(err)
		}
		s.feed(pollMsg{})
		s.wantNoView("[queued]")
		expectTexts(t, bob.pull("alice"), "sent while offline")
	})

	t.Run("safety numbers and verification from inside the chat", func(t *testing.T) {
		s.t = t
		s.line("/sn")
		s.wantView("Safety number with @bob (NOT verified)")
		s.line("/verify")
		s.wantView("@bob marked as verified")
		s.wantView("@bob · " + FgGreen + "verified")
		s.line("/unverify @bob")
		s.wantView("not verified — /sn")
		s.line("/contacts")
		s.wantView("@bob")
	})

	t.Run("messages in other chats are announced", func(t *testing.T) {
		s.t = t
		s.line("/chat @carol")
		bob.mustSend("alice", "psst")
		if _, err := s.m.a.pull(0); err != nil {
			t.Fatal(err)
		}
		s.feed(pollMsg{})
		s.wantView("New: @bob (1)")
		s.wantNoView("psst")
		s.line("/chat bob")
		s.wantView("psst")
		s.wantNoView("New: @bob")
	})

	t.Run("outside a chat, @user writes to someone or opens their chat", func(t *testing.T) {
		s.t = t
		s.line("/chat all")
		s.line("@bob quick one from the overview")
		s.wantView("(alice) itter>") // still in the overview
		s.deliver()
		s.wantView("→ @bob")
		expectTexts(t, bob.pull("alice"), "quick one from the overview")
		s.line("@BOB")
		s.wantView("(alice) -> @bob>")
		s.line("@carol is mentioned, not addressed") // in a chat this is just text
		s.deliver()
		expectTexts(t, bob.pull("alice"), "@carol is mentioned, not addressed")
	})

	t.Run("Tab completes commands and names", func(t *testing.T) {
		s.t = t
		s.keys("/ch")
		s.feed(tea.KeyMsg{Type: tea.KeyTab})
		s.keys("@b")
		s.feed(tea.KeyMsg{Type: tea.KeyTab})
		if got := s.m.ti.Value(); got != "/chat @bob" {
			t.Fatalf("completed to %q, want %q", got, "/chat @bob")
		}
		s.feed(tea.KeyMsg{Type: tea.KeyEnter})
		s.wantView("(alice) -> @bob>")
		s.feed(tea.KeyMsg{Type: tea.KeyTab}) // nothing typed: nothing to complete
		if got := s.m.ti.Value(); got != "" {
			t.Fatalf("Tab on an empty line produced %q", got)
		}
		s.keys("hello /ch") // ordinary text is left alone
		s.feed(tea.KeyMsg{Type: tea.KeyTab})
		if got := s.m.ti.Value(); got != "hello /ch" {
			t.Fatalf("Tab changed ordinary text to %q", got)
		}
		s.m.ti.SetValue("")
	})

	t.Run("arrow keys scroll; the mouse is left to the terminal", func(t *testing.T) {
		s.t = t
		s.feed(tea.KeyMsg{Type: tea.KeyUp})
		s.feed(tea.KeyMsg{Type: tea.KeyUp})
		s.feed(tea.KeyMsg{Type: tea.KeyDown})
		if s.m.scroll != 1 {
			t.Fatalf("scroll = %d, want 1", s.m.scroll)
		}
		s.feed(tea.KeyMsg{Type: tea.KeyDown})
		s.feed(tea.KeyMsg{Type: tea.KeyDown})
		if s.m.scroll != 0 {
			t.Fatalf("scroll = %d, want 0", s.m.scroll)
		}
	})

	t.Run("unread survives closing the shell; read is read everywhere", func(t *testing.T) {
		s.t = t
		s.line("/chat @carol")
		bob.mustSend("alice", "while you were elsewhere")
		if _, err := alice.app().pull(0); err != nil { // another process fetches it (itter dm, say)
			t.Fatal(err)
		}
		s.feed(tickMsg{})
		s.wantView("New: @bob (1)")
		// The shell is closed without looking; a one-shot read shows exactly that message.
		alice.use()
		out, err := capture(func() error { return cmdRead(nil) })
		if err != nil || !strings.Contains(out, "while you were elsewhere") || strings.Contains(out, "quick one from the overview") {
			t.Fatalf("itter read: %q, %v", out, err)
		}
		if out, _ = capture(func() error { return cmdRead(nil) }); !strings.Contains(out, "No new messages") {
			t.Fatalf("second itter read: %q", out)
		}
		s.feed(tickMsg{}) // the open shell learns that it was read elsewhere
		s.wantNoView("New: @bob")
		s.line("/chat @bob")
		s.wantView("while you were elsewhere")
	})

	t.Run("connection problems are visible", func(t *testing.T) {
		s.t = t
		s.feed(pollMsg{err: errors.New("dial tcp: connection refused")})
		s.wantView("Offline: can't reach the relay (dial tcp: connection refused). Retrying")
		s.feed(pollMsg{err: &relay.HTTPError{Status: 401, Body: api.ErrUnknownIdentity}})
		s.wantView("the relay no longer knows this device")
		s.wantNoView("Retrying")
		s.feed(pollMsg{})
		s.wantNoView("Offline:")
		s.wantNoView("no longer knows this device")
	})

	t.Run("hostile text cannot escape onto the terminal", func(t *testing.T) {
		s.t = t
		a := s.m.a
		_ = a.v.Update(func() error {
			a.v.AddMessage("bob", vault.ChatMsg{ID: "x", Status: vault.StatusSent, TS: time.Now().Unix(), Text: "boo\x1b]52;c;ZXZpbA==\x07\x1b[2J"})
			return nil
		})
		s.wantView("boo]52;c;ZXZpbA==[2J")
		s.wantNoView("\x1b]52")
		s.wantNoView("\x1b[2J")
	})

	t.Run("another itter process shows up in the open shell", func(t *testing.T) {
		s.t = t
		alice.mustSend("bob", "from another terminal") // a second process, same vault
		s.feed(tickMsg{})
		s.wantView("from another terminal")
	})

	t.Run("exit quits", func(t *testing.T) {
		s.t = t
		s.m.ti.SetValue("/exit")
		cmd := s.feed(tea.KeyMsg{Type: tea.KeyEnter})
		if cmd == nil {
			t.Fatal("no quit command")
		}
		if _, ok := cmd().(tea.QuitMsg); !ok {
			t.Fatal("expected tea.Quit")
		}
	})
}

// The background loop must notice an outage, say so, and deliver what was
// queued as soon as the relay is back, without any help from the UI.
func TestPollLoopRecoversAndFlushes(t *testing.T) {
	w := newWorld(t)
	alice, bob := w.ready(t, "alice"), w.ready(t, "bob")
	alice.mustSend("bob", "hi")
	bob.pull("alice")

	a := alice.app()
	down := &flaky{match: func(*http.Request) bool { return true }}
	a.rc.HC.Transport, a.rc.Long.Transport = down, down
	if out, err := a.send("bob", "written while offline"); err != nil || out.Status != vault.StatusQueued {
		t.Fatalf("send while offline: %+v, %v", out, err)
	}

	var mu sync.Mutex
	var seen []pollMsg
	go pollLoop(a, func(m tea.Msg) {
		if pm, ok := m.(pollMsg); ok {
			mu.Lock()
			seen = append(seen, pm)
			mu.Unlock()
		}
	})
	waitFor := func(what string, cond func([]pollMsg) bool) {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			ok := cond(seen)
			mu.Unlock()
			if ok {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for: %s", what)
	}
	waitFor("the outage to be reported", func(s []pollMsg) bool { return len(s) > 0 && s[0].err != nil })
	if got := bob.pull("alice"); len(got) != 0 {
		t.Fatalf("bob got %q during the outage", got)
	}
	// While the loop knows the relay is away, a send is queued at once
	// instead of waiting for yet another connection attempt to fail.
	out, err := a.send("bob", "also written offline")
	if err != nil || out.Status != vault.StatusQueued || !strings.Contains(out.Note, "no connection") {
		t.Fatalf("send during a known outage: %+v, %v", out, err)
	}

	down.match = nil // the network is back
	bob.mustSend("alice", "are you there?")
	waitFor("a successful poll", func(s []pollMsg) bool { return s[len(s)-1].err == nil })
	expectTexts(t, bob.pull("alice"), "written while offline", "also written offline")
	waitFor("bob's message to arrive", func([]pollMsg) bool {
		msgs := a.v.GetMessages("bob")
		return msgs[len(msgs)-1].Text == "are you there?"
	})
	for _, m := range a.v.GetMessages("bob") {
		if m.IsOut && m.Status != vault.StatusSent {
			t.Fatalf("%q still has status %d", m.Text, m.Status)
		}
	}
}
