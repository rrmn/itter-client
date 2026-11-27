package main

import (
	"bufio"
	"fmt"
	"os"
	"sync"

	tea "github.com/charmbracelet/bubbletea"
)

// dmHub runs the DMs inside the itter view: it keeps them current in the
// background (so new ones show in the title), and shows the DM view when
// asked. The DM view keeps its state between visits.
type dmHub struct {
	name     string
	onUnread func(int)
	cooked   func() // the terminal's normal mode, for the questions of a setup
	raw      func() // back to the mode of the itter view

	mu      sync.Mutex
	a       *app
	model   *appModel
	prog    *tea.Program // the DM view on screen, nil while itter is
	backlog []tea.Msg    // results that came in while the DM view was closed
}

// startIfReady starts the background work if this device is set up for DMs.
// If it is not, that waits for the first visit.
func (h *dmHub) startIfReady() {
	if needsFirstRun() {
		return
	}
	if a, err := open(); err == nil {
		h.start(a)
	}
}

func (h *dmHub) start(a *app) {
	m := newModel(a)
	m.embedded = true
	h.mu.Lock()
	h.a, h.model = a, &m
	h.mu.Unlock()
	go sendWorker(a, m.sendCh, h.deliver)
	go pollLoop(a, h.deliver)
	h.reportUnread()
}

func (h *dmHub) deliver(msg tea.Msg) {
	h.mu.Lock()
	p := h.prog
	if p == nil {
		switch msg.(type) {
		case sendDoneMsg, noteMsg: // the DM view needs these when it opens again
			h.backlog = append(h.backlog, msg)
		}
	}
	h.mu.Unlock()
	if p != nil {
		p.Send(msg)
	}
	if _, ok := msg.(pollMsg); ok {
		h.reportUnread()
	}
}

func (h *dmHub) reportUnread() {
	h.mu.Lock()
	a := h.a
	h.mu.Unlock()
	if a != nil && h.onUnread != nil {
		h.onUnread(a.unreadCount())
	}
}

// open shows the DMs (with target's chat open, if given) until the user
// goes back to itter. The first time on a device, it sets the DMs up.
func (h *dmHub) open(target string) {
	h.mu.Lock()
	ready := h.a != nil
	h.mu.Unlock()
	if !ready && !h.setUp() {
		return
	}
	h.mu.Lock()
	m := *h.model
	backlog := h.backlog
	h.backlog = nil
	a := h.a
	h.mu.Unlock()
	if target != "" {
		m.setFilter(a.resolve(target))
	}
	p := tea.NewProgram(m, tea.WithAltScreen())
	h.mu.Lock()
	h.prog = p
	h.mu.Unlock()
	go func() {
		for _, msg := range backlog {
			p.Send(msg)
		}
	}()
	final, err := p.Run()
	h.mu.Lock()
	h.prog = nil
	fm, ok := final.(appModel)
	if ok && err == nil {
		h.model = &fm
	}
	h.mu.Unlock()
	if ok {
		// What was on screen counts as read, saved now: the DM view may have
		// closed before it got to that.
		_ = a.v.Update(func() error { a.v.MarkRead(fm.seen); return nil })
	}
	h.reportUnread()
}

// setUp sets this device up for DMs, asking first. It runs on the alternate
// screen, so itter's screen is untouched, and in the terminal's normal mode,
// for the questions. It reports whether the DMs are ready.
func (h *dmHub) setUp() bool {
	h.cooked()
	defer h.raw()
	out := os.Stdout
	fmt.Fprint(out, "\x1b[?1049h\x1b[H\x1b[2J")
	defer fmt.Fprint(out, "\x1b[?1049l")
	p := &prompter{in: bufio.NewReader(os.Stdin), out: out}
	back := func(err error) bool {
		fmt.Fprintf(out, "\n%s\n\n", explainLocal(err))
		_, _ = p.line("Press Enter to go back to itter", "")
		return false
	}

	fmt.Fprint(out, dmIntro)
	if !p.yes("Set up DMs on this computer now?") {
		return false
	}
	if err := setUpDMs(p, out, h.name); err != nil {
		return back(err)
	}
	a, err := open()
	if err != nil {
		return back(err)
	}
	h.start(a)
	fmt.Fprintln(out, "When you talk to someone, compare safety numbers with them (/sn in a chat):")
	fmt.Fprintln(out, "that comparison is what proves who you are talking to.")
	fmt.Fprintln(out)
	_, _ = p.line("Press Enter to open your DMs", "")
	return true
}

const dmIntro = `Direct messages

DMs on itter are end-to-end encrypted: they are locked on this computer, and
only the people you write to can unlock them. Not itter, not anyone else.

This computer is not set up for DMs yet. That takes a minute, and one
signature with the SSH key you log in to itter with.

`

// unreadCount is how many received messages have not been shown yet.
func (a *app) unreadCount() int {
	read := a.v.ReadCounts()
	n := 0
	for name, msgs := range a.v.GetAllMessages() {
		for i := min(read[name], len(msgs)); i < len(msgs); i++ {
			if !msgs[i].IsOut && !msgs[i].IsSystem {
				n++
			}
		}
	}
	return n
}
