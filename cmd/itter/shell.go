package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/rrmn/itter-client/internal/api"
	"github.com/rrmn/itter-client/internal/pqc"
	"github.com/rrmn/itter-client/internal/relay"
	"github.com/rrmn/itter-client/internal/vault"
)

const shellHelp = `In a chat, whatever you type is sent. Commands start with a slash:
  /chat @user        open the chat with a user  (/chat all: every conversation)
  /dm @user <msg>    send without switching chats
  /contacts          who you talk to, and whether they are verified
  /sn [@user]        safety number to compare (your fingerprint outside a chat)
  /verify [@user]    you compared safety numbers and they matched
  /unverify [@user]  remove that mark
  /accept [@user]    a contact shows a new identity: accept it, read what was held
  /reset [@user]     drop a stuck session and start a fresh one
  /ignore [@user]    stop getting DMs from someone (itter's ignore list); /unignore undoes it
  /devices           the devices of your account
  /approve <code>    let a new device in (the code "itter link" shows there)
  /unlink <id>       remove a linked device
  /clear             clear this view (messages stay stored)
  /exit              leave (also Esc, Ctrl+C or Ctrl+])
Outside a chat, "@user hello" sends and "@user" opens the chat.
Tab completes commands and names. PgUp/PgDn and the arrow keys scroll.
To send a line that starts with "/", type "//".`

const shellWelcome = `No conversations yet. Write to someone:  @user hello
(/help lists everything else)`

// Messages delivered to the UI from background work.
type (
	pollMsg     struct{ err error }
	sendDoneMsg struct {
		id   int
		req  sendReq
		out  sendOutcome
		err  error
		when time.Time
	}
	noteMsg struct {
		lines []string
		err   error
	}
	tickMsg struct{}
)

type sendReq struct {
	id     int
	target string
	text   string
	ts     int64
}

type appModel struct {
	a      *app
	me     string
	ti     textinput.Model
	filter string // "" shows every conversation
	width  int
	height int
	scroll int

	status    string // result of the last action
	statusBad bool
	connErr   string // why the relay cannot be used ("" when connected)
	connRetry bool   // connErr is temporary; the poll loop keeps trying

	notes   []vault.ChatMsg  // local lines (help, safety numbers): shown, never stored
	hidden  map[string]int64 // /clear: per view, hide everything older
	seen    map[string]int   // messages already shown, per contact
	sending []sendReq        // on their way
	nextID  int
	sendCh  chan sendReq // strictly ordered sends

	embedded bool // shown inside the itter view: leaving goes back to itter
}

func newModel(a *app) appModel {
	me, _ := a.v.Me()
	ti := textinput.New()
	ti.Focus()
	ti.CharLimit = api.MaxTextLen
	// What arrived while the shell was closed (fetched by `itter dm`, say)
	// starts out unread.
	ti.ShowSuggestions = true // Tab completes commands and names
	m := appModel{a: a, me: me, ti: ti, hidden: map[string]int64{}, seen: a.v.ReadCounts(),
		sendCh: make(chan sendReq, 256)}
	m.setFilter("")
	if len(a.v.GetAllMessages()) == 0 {
		m.note(strings.Split(shellWelcome, "\n")...)
	}
	return m
}

func (m *appModel) setFilter(name string) {
	m.filter = name
	if name == "" {
		m.ti.Prompt = fmt.Sprintf("(%s) itter> ", m.me)
	} else {
		m.ti.Prompt = fmt.Sprintf("(%s) -> @%s> ", m.me, name)
	}
	m.complete()
}

// complete refreshes what Tab can complete: commands, and the names of the
// people the user talks to.
func (m *appModel) complete() {
	out := []string{"/chat ", "/chat all", "/dm ", "/contacts", "/sn", "/verify", "/unverify", "/accept", "/reset",
		"/ignore", "/unignore ", "/devices", "/approve ", "/unlink ", "/clear", "/help", "/exit"}
	for _, name := range m.a.v.IgnoreList() {
		out = append(out, "/unignore @"+name)
	}
	for _, c := range m.a.v.ContactList() {
		at := "@" + c.Name
		out = append(out, "/chat "+at, "/dm "+at+" ", "/sn "+at, "/verify "+at, "/unverify "+at, "/reset "+at, "/ignore "+at)
		if len(c.Pending) > 0 {
			out = append(out, "/accept "+at)
		}
		if m.filter == "" {
			out = append(out, at+" ")
		}
	}
	m.ti.SetSuggestions(out)
}

// markSeen records what is on screen as read. When that is news, it returns
// a command that saves the markers (off the UI goroutine: it writes to disk).
func (m *appModel) markSeen() tea.Cmd {
	if m.width == 0 {
		return nil // nothing has been drawn yet
	}
	m.complete()
	changed := map[string]int{}
	for name, msgs := range m.a.v.GetAllMessages() {
		if (m.filter == "" || m.filter == name) && len(msgs) > m.seen[name] {
			m.seen[name] = len(msgs)
			changed[name] = len(msgs)
		}
	}
	if len(changed) == 0 {
		return nil
	}
	a := m.a
	return func() tea.Msg {
		_ = a.v.Update(func() error { a.v.MarkRead(changed); return nil })
		return nil
	}
}

// shown returns the model after marking what is on screen as read.
func (m appModel) shown() (tea.Model, tea.Cmd) {
	save := m.markSeen() // changes m: must happen before m is returned
	return m, save
}

func (m *appModel) note(lines ...string) {
	ts := time.Now().Unix()
	for _, l := range lines {
		m.notes = append(m.notes, vault.ChatMsg{IsSystem: true, TS: ts, Text: l})
	}
	m.scroll = 0
}

func (m *appModel) setStatus(bad bool, format string, args ...any) {
	m.status, m.statusBad = fmt.Sprintf(format, args...), bad
}

func tick() tea.Cmd { return tea.Tick(5*time.Second, func(time.Time) tea.Msg { return tickMsg{} }) }

func (m appModel) Init() tea.Cmd { return tea.Batch(textinput.Blink, tick()) }

func (m appModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m.shown()
	case tickMsg:
		_ = m.a.v.Refresh() // another itter process may have written...
		for name, n := range m.a.v.ReadCounts() {
			m.seen[name] = max(m.seen[name], n) // ...or shown messages (itter read)
		}
		save := m.markSeen()
		return m, tea.Batch(tick(), save)
	case pollMsg:
		m.connErr, m.connRetry = "", false
		if msg.err != nil {
			m.connErr, m.connRetry = explain(msg.err), retryable(msg.err)
		}
		return m.shown()
	case noteMsg:
		if msg.err != nil {
			m.setStatus(true, "%s", explain(msg.err))
		}
		m.note(msg.lines...)
		return m.shown()
	case sendDoneMsg:
		m.sendDone(msg)
		return m.shown()
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC, tea.KeyEsc, tea.KeyCtrlCloseBracket:
			return m, tea.Quit
		case tea.KeyPgUp:
			m.scroll += max(1, m.height-4)
		case tea.KeyPgDown:
			m.scroll = max(0, m.scroll-max(1, m.height-4))
		// The mouse is deliberately not captured, so text (a safety number,
		// say) can be selected and copied as in any terminal. Most terminals
		// turn the wheel into arrow keys on a full-screen program.
		case tea.KeyUp:
			m.scroll++
			return m, nil
		case tea.KeyDown:
			m.scroll = max(0, m.scroll-1)
			return m, nil
		case tea.KeyEnter:
			text := strings.TrimSpace(m.ti.Value())
			if text == "" {
				return m, nil
			}
			m.ti.SetValue("")
			m.complete() // forget the completion of the line that was just entered
			m.scroll = 0
			m.status = ""
			return m.enter(text)
		}
	}
	m.ti, cmd = m.ti.Update(msg)
	return m, cmd
}

// enter handles a submitted line.
func (m appModel) enter(text string) (tea.Model, tea.Cmd) {
	inChat := m.filter != ""
	switch {
	case inChat && strings.HasPrefix(text, "//"):
		m.queueSend(m.filter, text[1:])
		return m, nil
	case inChat && !strings.HasPrefix(text, "/"):
		m.queueSend(m.filter, text)
		return m, nil
	case !inChat && strings.HasPrefix(text, "@"):
		// "@user hello" writes to someone, "@user" opens the chat.
		name, body, _ := strings.Cut(text, " ")
		if body = strings.TrimSpace(body); body == "" {
			text = "/chat " + name
			break
		}
		m.queueSend(m.a.resolve(name), body)
		return m, nil
	}
	fields := strings.Fields(strings.TrimPrefix(text, "/"))
	if len(fields) == 0 {
		return m, nil
	}
	arg := func(i int) string {
		if len(fields) > i {
			return stripAt(fields[i])
		}
		return ""
	}
	// who a trust command is about: the named user, or the open chat
	who := arg(1)
	if who == "" {
		who = m.filter
	}
	needWho := func() bool {
		if who == "" {
			m.setStatus(true, "Which user? For example: /%s @someone", fields[0])
			return false
		}
		return true
	}
	a := m.a
	switch strings.ToLower(fields[0]) {
	case "exit", "quit", "x", "q":
		return m, tea.Quit
	case "help", "h", "?":
		m.note(strings.Split(shellHelp, "\n")...)
	case "clear", "c":
		m.hidden[m.filter] = time.Now().Unix()
		m.notes = nil
	case "chat":
		switch name := a.resolve(arg(1)); {
		case arg(1) == "":
			m.setStatus(true, "Usage: /chat @user   or   /chat all")
		case strings.EqualFold(name, "all"):
			m.setFilter("")
		case !api.ValidUsername(name):
			m.setStatus(true, "%q is not a valid itter username", name)
		case strings.EqualFold(name, m.me):
			m.setStatus(true, "That is you.")
		default:
			m.setFilter(name)
		}
		return m.shown()
	case "dm":
		rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(text, "/"), fields[0]))
		_, body, ok := strings.Cut(rest, " ")
		if arg(1) == "" || !ok || strings.TrimSpace(body) == "" {
			m.setStatus(true, "Usage: /dm @user <message>")
			break
		}
		m.queueSend(a.resolve(arg(1)), strings.TrimSpace(body))
	case "contacts":
		list := a.v.ContactList()
		if len(list) == 0 {
			m.note("No conversations yet. Start one: /chat @user")
		}
		for _, c := range list {
			m.note(contactLine(c))
		}
	case "sn", "safety-number":
		if who == "" {
			m.note(fmt.Sprintf("Your fingerprint (the same on all your devices): %s", pqc.Fingerprint(a.v.AccountIdentity())))
			break
		}
		return m, func() tea.Msg { return noteMsg{lines: a.safetyReport(who)} }
	case "verify", "pin":
		if needWho() {
			return m, func() tea.Msg { s, err := a.setVerified(who, true); return noteMsg{lines: lines(s), err: err} }
		}
	case "unverify", "unpin":
		if needWho() {
			return m, func() tea.Msg { s, err := a.setVerified(who, false); return noteMsg{lines: lines(s), err: err} }
		}
	case "accept":
		if needWho() {
			return m, func() tea.Msg { s, err := a.accept(who); return noteMsg{lines: lines(s), err: err} }
		}
	case "reset":
		if needWho() {
			return m, func() tea.Msg { s, err := a.reset(who); return noteMsg{lines: lines(s), err: err} }
		}
	case "ignore", "unignore":
		on := strings.ToLower(fields[0]) == "ignore"
		if arg(1) == "" && on {
			return m, func() tea.Msg {
				names, err := a.rc.Ignored(a.auth())
				out := []string{"You ignore nobody."}
				if len(names) > 0 {
					out = []string{"You ignore: @" + strings.Join(names, ", @")}
				}
				return noteMsg{lines: out, err: err}
			}
		}
		if needWho() {
			return m, func() tea.Msg { s, err := a.setIgnore(who, on); return noteMsg{lines: lines(s), err: err} }
		}
	case "devices":
		return m, func() tea.Msg { ls, err := a.deviceLines(); return noteMsg{lines: ls, err: err} }
	case "approve":
		words := fields[1:]
		sure := len(words) > 1 && words[len(words)-1] == approveWord
		if sure {
			words = words[:len(words)-1]
		}
		secret, err := api.ParseRecovery(strings.Join(words, ""))
		if err != nil {
			m.setStatus(true, "Usage: /approve <code>   (the code `itter link` shows on the new device)")
			break
		}
		if !sure {
			for _, l := range approveWarning(m.me) {
				m.note(l)
			}
			m.note(fmt.Sprintf("To go on: /approve %s %s", api.FormatRecovery(secret), approveWord))
			break
		}
		m.setStatus(false, "Checking the request and signing your device list…")
		return m, func() tea.Msg { s, err := a.approve(secret); return noteMsg{lines: lines(s), err: err} }
	case "unlink":
		if arg(1) == "" {
			m.setStatus(true, "Usage: /unlink <device id>   (/devices shows the ids)")
			break
		}
		id := arg(1)
		return m, func() tea.Msg { s, err := a.unlink(id); return noteMsg{lines: lines(s), err: err} }
	default:
		if inChat {
			m.setStatus(true, "Sorry, unknown command: /%s. Are you making stuff up? /help shows what's possible. (To send a line starting with a slash, type two.)", fields[0])
		} else {
			m.setStatus(true, "You're not in a chat. Write to someone: @user hello   (/help for more)")
		}
	}
	return m, nil
}

func lines(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

func (m *appModel) queueSend(target, text string) {
	m.nextID++
	req := sendReq{id: m.nextID, target: target, text: text, ts: time.Now().Unix()}
	select {
	case m.sendCh <- req:
		m.sending = append(m.sending, req)
	default:
		m.setStatus(true, "Whoa, slow down: too many messages on their way. Wait a moment.")
		m.ti.SetValue(text)
	}
}

func (m *appModel) sendDone(d sendDoneMsg) {
	kept := m.sending[:0:0]
	for _, s := range m.sending {
		if s.id != d.id {
			kept = append(kept, s)
		}
	}
	m.sending = kept
	switch {
	case d.err != nil:
		// Nothing was queued: say why and give the text back.
		m.setStatus(true, "Not sent: %s", explain(d.err))
		if strings.TrimSpace(m.ti.Value()) == "" {
			m.ti.SetValue(d.req.text)
			m.ti.CursorEnd()
		}
	case d.out.Status == vault.StatusQueued:
		m.setStatus(false, "Queued, will be sent automatically: %s", d.out.Note)
	case d.out.Status == vault.StatusFailed:
		m.setStatus(true, "Not delivered. See the notice in the chat.")
	}
	// The relay may spell the name differently than it was typed.
	if d.err == nil && m.filter != d.out.Target && strings.EqualFold(m.filter, d.out.Target) {
		m.setFilter(d.out.Target)
	}
}

type viewLine struct {
	peer string
	msg  vault.ChatMsg
	tag  string
	note bool // a local line (help, safety number): full width, as typed
}

func (m appModel) buildLines() []string {
	var flat []viewLine
	for peer, msgs := range m.a.v.GetAllMessages() {
		if m.filter != "" && peer != m.filter {
			continue
		}
		for _, msg := range msgs {
			flat = append(flat, viewLine{peer: peer, msg: msg})
		}
	}
	for _, s := range m.sending {
		if m.filter == "" || strings.EqualFold(s.target, m.filter) {
			flat = append(flat, viewLine{peer: s.target, tag: FgBrightBlk + " [sending…]" + Reset,
				msg: vault.ChatMsg{IsOut: true, Status: vault.StatusSent, TS: s.ts, Text: s.text}})
		}
	}
	for _, n := range m.notes {
		flat = append(flat, viewLine{msg: n, note: true})
	}
	cutoff := m.hidden[m.filter]
	sort.SliceStable(flat, func(i, j int) bool { return flat[i].msg.TS < flat[j].msg.TS })

	label := func(l viewLine) string {
		switch {
		case l.msg.IsSystem:
			return "system"
		case !l.msg.IsOut:
			return "@" + l.peer
		case m.filter == "": // in the combined view, say who it went to
			return "→ @" + l.peer
		}
		return "@" + m.me
	}
	var labels []string
	for _, l := range flat {
		if l.msg.TS >= cutoff && !l.note {
			labels = append(labels, label(l))
		}
	}
	userW := labelWidth(labels...)

	var out []string
	for _, l := range flat {
		if l.msg.TS < cutoff {
			continue
		}
		if l.note {
			for _, line := range wrapPre(clean(l.msg.Text), m.width-2) {
				out = append(out, FgBrightBlk+"  "+line+Reset)
			}
			continue
		}
		ls := formatEetLines(label(l), l.msg.IsOut, l.msg, userW, m.width)
		if l.tag != "" {
			ls[len(ls)-1] += l.tag
		}
		out = append(out, ls...)
	}
	return out
}

func (m appModel) header() string {
	if m.filter == "" {
		return "Direct messages (all conversations)"
	}
	info, known := m.a.v.ContactInfo(m.filter)
	parts := []string{"@" + m.filter}
	switch {
	case !known:
		parts = append(parts, "no messages yet")
	case len(info.Pending) > 0:
		parts = append(parts, FgRed+"IDENTITY CHANGED — compare /sn, then /accept"+Reset+Bold)
	case info.Verified:
		parts = append(parts, FgGreen+"verified"+Reset+Bold)
	default:
		parts = append(parts, "not verified — /sn")
	}
	if info.HasSession {
		if info.Stalled != "" {
			parts = append(parts, FgRed+"PQ ratchet stalled — /reset"+Reset+Bold)
		} else {
			parts = append(parts, fmt.Sprintf("PQ ratchet steps: ML-KEM %d, FrodoKEM %d", info.MLKEM, info.Frodo))
		}
	}
	return strings.Join(parts, " · ")
}

func (m appModel) unread() string {
	var parts []string
	for name, msgs := range m.a.v.GetAllMessages() {
		if name == m.filter || m.filter == "" {
			continue
		}
		n := 0
		for i := min(m.seen[name], len(msgs)); i < len(msgs); i++ {
			if !msgs[i].IsOut {
				n++
			}
		}
		if n > 0 {
			parts = append(parts, fmt.Sprintf("@%s (%d)", name, n))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	sort.Strings(parts)
	return "New: " + strings.Join(parts, ", ") + " — /chat @user"
}

func (m appModel) statusLine() string {
	switch {
	case m.status != "" && m.statusBad:
		return FgRed + clean(m.status) + Reset
	case m.status != "":
		return FgBrightBlk + clean(m.status) + Reset
	case m.connErr != "" && m.connRetry:
		return FgBrightYellow + "Offline: " + ended(clean(m.connErr)) + " Retrying; messages you send are queued." + Reset
	case m.connErr != "":
		return FgRed + clean(m.connErr) + Reset
	}
	if u := m.unread(); u != "" {
		return FgCyan + u + Reset
	}
	if m.filter == "" {
		return FgBrightBlk + "@user hello to write · /chat @user to open a chat · /help · " + m.leaveHint() + Reset
	}
	return FgBrightBlk + "/help · /chat all · Tab completes · " + m.leaveHint() + Reset
}

func (m appModel) leaveHint() string {
	if m.embedded {
		return "Esc: back to itter"
	}
	return "Esc quits"
}

func (m appModel) View() string {
	if m.width == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(Bold + "--- " + m.header() + " ---" + Reset + "\n")

	lines := m.buildLines()
	viewHeight := max(1, m.height-3)
	scroll := min(m.scroll, max(0, len(lines)-viewHeight))
	start := max(0, len(lines)-viewHeight-scroll)
	end := min(len(lines), start+viewHeight)
	for i := start; i < end; i++ {
		b.WriteString(lines[i] + "\n")
	}
	for i := end - start; i < viewHeight; i++ {
		b.WriteString("\n")
	}
	b.WriteString(m.statusLine() + "\n")
	b.WriteString(m.ti.View())
	return b.String()
}

// sendWorker delivers queued sends one at a time, in the order typed.
func sendWorker(a *app, ch <-chan sendReq, deliver func(tea.Msg)) {
	for req := range ch {
		out, err := a.send(req.target, req.text)
		deliver(sendDoneMsg{id: req.id, req: req, out: out, err: err, when: time.Now()})
	}
}

// pollLoop keeps the conversation current: it long-polls the relay, flushes
// the outbox and looks after prekeys.
func pollLoop(a *app, deliver func(tea.Msg)) {
	backoff := 2 * time.Second
	for {
		_ = a.v.Refresh()
		err := a.flush()
		if err == nil || retryable(err) {
			_, err = a.pull(api.MaxWait - 5)
		}
		if err == nil {
			err = a.maintain()
		}
		a.offline.Store(err != nil && relay.Status(err) == 0) // no answer at all
		deliver(pollMsg{err: err})
		if err != nil {
			time.Sleep(backoff)
			backoff = min(2*backoff, 30*time.Second)
		} else {
			backoff = 2 * time.Second
		}
	}
}

func cmdShell() error {
	if interactive() && needsFirstRun() {
		if err := firstRun(os.Stdin, os.Stdout); err != nil {
			return err
		}
	}
	a, err := open()
	if err != nil {
		return err
	}
	m := newModel(a)
	p := tea.NewProgram(m, tea.WithAltScreen())
	go sendWorker(a, m.sendCh, p.Send)
	go pollLoop(a, p.Send)
	_, err = p.Run()
	return err
}
