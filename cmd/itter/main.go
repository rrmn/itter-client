package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/mattn/go-runewidth"
	"golang.org/x/term"

	"itter-cli/internal/pqc"
	"itter-cli/internal/relay"
	"itter-cli/internal/vault"
)

const (
	Reset          = "\033[0m"
	Bold           = "\033[1m"
	FgCyan         = "\033[36m"
	FgBrightYellow = "\033[93m"
	FgBrightBlk    = "\033[90m"
)

const usage = `itter — Private direct messaging

usage:
  itter                    open the live interactive shell
  itter dm @<user> <msg>   send a message instantly and exit
  itter fetch              fetch and print all new messages
  itter fetch @<user>      fetch and print only new messages from a specific user
  itter senders            show who has pending messages without downloading
  
setup:
  itter init <username>    create identity & register
  itter publish            upload fresh keys
  itter profile            show your own identity fingerprint
  itter profile @<user>    verify a contact's fingerprint and safety number
  itter trust @<user>      pin a contact's identity key
  itter untrust @<user>    un-pin a contact's identity key

env:
  ITTER_RELAY   relay base URL (default http://127.0.0.1:8080)
  ITTER_DIR     state directory  (default ~/.itter-cli)
`

var usernameRE = regexp.MustCompile(`^[a-zA-Z0-9_]{3,20}$`)

func main() {
	if len(os.Args) < 2 {
		cmdShell()
		return
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit()
	case "publish":
		err = cmdPublish()
	case "dm":
		err = cmdDM(os.Args[2:])
	case "fetch":
		err = cmdFetch(os.Args[2:])
	case "senders":
		err = cmdSenders()
	case "profile", "p":
		err = cmdProfile(os.Args[2:])
	case "trust":
		err = cmdTrust(os.Args[2:])
	case "untrust":
		err = cmdUntrust(os.Args[2:])
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func configDir() string {
	if d := os.Getenv("ITTER_DIR"); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".itter-cli")
}

func relayURL() string {
	if u := os.Getenv("ITTER_RELAY"); u != "" {
		return strings.TrimRight(u, "/")
	}
	return "http://127.0.0.1:8080"
}

func readPassphrase(prompt string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		tty = os.Stdin
	} else {
		defer tty.Close()
	}
	fmt.Fprint(tty, prompt)
	b, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	return string(b), err
}

func unlock() (*vault.Vault, string, error) {
	dir := configDir()
	if !vault.Exists(dir) {
		return nil, "", fmt.Errorf("no identity in %s — run `itter init <username>` first", dir)
	}
	pass, err := readPassphrase("passphrase: ")
	if err != nil {
		return nil, "", err
	}
	v, err := vault.Unlock(dir, pass)
	if err != nil {
		return nil, "", err
	}
	return v, pass, nil
}

func cmdInit() error {
	if len(os.Args) < 3 {
		return errors.New("usage: itter init <username>")
	}
	username := strings.TrimPrefix(os.Args[2], "@")
	if !usernameRE.MatchString(username) {
		return errors.New("username: 3-20 chars, letters/numbers/underscore")
	}
	dir := configDir()
	if vault.Exists(dir) {
		return fmt.Errorf("identity already exists in %s", dir)
	}
	p1, err := readPassphrase("choose passphrase: ")
	if err != nil {
		return err
	}
	p2, err := readPassphrase("repeat passphrase: ")
	if err != nil {
		return err
	}
	if p1 != p2 {
		return errors.New("passphrases don't match")
	}
	if len(p1) < 8 {
		return errors.New("passphrase too short (min 8 chars)")
	}
	v, err := vault.Create(dir, username, p1)
	if err != nil {
		return err
	}
	rc := relay.New(relayURL())
	if err := rc.Register(username, v.Identity); err != nil {
		return fmt.Errorf("relay registration failed: %w", err)
	}
	fmt.Printf("identity created for @%s\nfingerprint: %s\n\nnow run: itter publish\n",
		username, pqc.Fingerprint(v.Identity.SignPub))
	return nil
}

func cmdPublish() error {
	v, pass, err := unlock()
	if err != nil {
		return err
	}
	id := v.NextPreKeyID
	spk, err := pqc.GenerateSignedPreKey(v.Identity, id)
	if err != nil {
		return err
	}
	id++
	var otpks []*pqc.OneTimePreKey
	for i := 0; i < 20; i++ {
		k, err := pqc.GenerateOneTimePreKey(id)
		if err != nil {
			return err
		}
		id++
		otpks = append(otpks, k)
	}
	v.NextPreKeyID = id
	v.SPKs = append([]*pqc.SignedPreKey{spk}, v.SPKs...)
	if len(v.SPKs) > 3 {
		v.SPKs = v.SPKs[:3]
	}
	v.OTPKs = append(v.OTPKs, otpks...)

	rc := relay.New(relayURL())
	if err := rc.UploadKeys(v.Username, v.Identity, spk, otpks); err != nil {
		return err
	}
	if err := v.Save(configDir(), pass); err != nil {
		return err
	}
	fmt.Println("published: 1 signed prekey + 20 one-time prekeys")
	return nil
}

func cmdTrust(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: itter trust @<user>")
	}
	target := strings.TrimPrefix(args[0], "@")
	v, pass, err := unlock()
	if err != nil {
		return err
	}

	v.Mu.Lock()
	sess := v.Sessions[target]
	v.Mu.Unlock()

	if sess == nil {
		return errors.New("no session yet. Send or receive a message first to establish an identity to trust.")
	}

	sess.Trusted = true
	if err := v.Save(configDir(), pass); err != nil {
		return err
	}
	fmt.Printf("Identity pinned for @%s.\n", target)
	return nil
}

func cmdUntrust(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: itter untrust @<user>")
	}
	target := strings.TrimPrefix(args[0], "@")
	v, pass, err := unlock()
	if err != nil {
		return err
	}

	v.Mu.Lock()
	sess := v.Sessions[target]
	v.Mu.Unlock()

	if sess == nil {
		return errors.New("no session found.")
	}

	sess.Trusted = false
	if err := v.Save(configDir(), pass); err != nil {
		return err
	}
	fmt.Printf("Identity un-pinned for @%s.\n", target)
	return nil
}

func cmdProfile(args []string) error {
	v, _, err := unlock()
	if err != nil {
		return err
	}

	if len(args) == 0 {
		fmt.Printf("--- Profile: @%s ---\n", v.Username)
		fmt.Printf("Fingerprint:\n  %s\n", pqc.Fingerprint(v.Identity.SignPub))
		fmt.Println("\nShare this over a secure secondary channel (in person, Signal, etc.)")
		fmt.Println("so your contacts can verify they are talking to the real you.")
		return nil
	}

	target := strings.TrimPrefix(args[0], "@")
	if target == v.Username {
		fmt.Println("That's you! Run `itter profile` without arguments to see your own info.")
		return nil
	}

	rc := relay.New(relayURL())
	b, err := rc.FetchBundle(target)
	if err != nil {
		return fmt.Errorf("cannot fetch keys for @%s: %w", target, err)
	}
	if err := b.VerifySignature(); err != nil {
		return fmt.Errorf("signature verification failed for @%s", target)
	}

	fmt.Printf("--- Profile: @%s ---\n", target)
	fmt.Printf("Fingerprint:\n  %s\n\n", pqc.Fingerprint(b.SignPub))

	v.Mu.Lock()
	sess := v.Sessions[target]
	v.Mu.Unlock()

	if sess != nil {
		if !bytes.Equal(sess.TheirSignPub, b.SignPub) {
			fmt.Printf("%s[!] Identity key mismatch%s\n", FgBrightYellow, Reset)
			fmt.Println("The server provided a different key than your active session.")
		} else {
			fmt.Printf("Key Match: Yes\n")
		}
		if sess.Trusted {
			fmt.Printf("Status:    Pinned (Trusted)\n")
		} else {
			fmt.Printf("Status:    Not pinned (Run `itter trust @%s` to pin)\n", target)
		}

		fmt.Printf("\nSafety Number (Compare with @%s):\n%s\n", target, pqc.SafetyNumber(v.Identity.SignPub, b.SignPub))
	} else {
		fmt.Println("Status: No active session.")
		fmt.Println("Record this fingerprint and verify it before sending sensitive data.")
	}

	return nil
}

// --- Text Formatting & Wrapping ---

func timeAgo(ts int64) string {
	diff := time.Since(time.Unix(ts, 0))
	secs := int(diff.Seconds())
	if secs < 10 {
		return "just now"
	}
	if secs < 60 {
		return fmt.Sprintf("%ds ago", secs)
	}
	mins := secs / 60
	if mins < 60 {
		return fmt.Sprintf("%dm ago", mins)
	}
	hours := mins / 60
	if hours < 24 {
		return fmt.Sprintf("%dh ago", hours)
	}
	days := hours / 24
	return fmt.Sprintf("%dd ago", days)
}

func stripAnsi(text string) string {
	re := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	return re.ReplaceAllString(text, "")
}

func customWrap(text string, maxWidth int) []string {
	if maxWidth < 1 {
		return []string{""}
	}
	var lines []string
	var currentLine string
	words := strings.Fields(text)

	for _, w := range words {
		if runewidth.StringWidth(stripAnsi(currentLine+" "+w)) <= maxWidth {
			if currentLine == "" {
				currentLine = w
			} else {
				currentLine += " " + w
			}
		} else {
			if currentLine != "" {
				lines = append(lines, currentLine)
				currentLine = w
			} else {
				lines = append(lines, w)
				currentLine = ""
			}
		}
	}
	if currentLine != "" {
		lines = append(lines, currentLine)
	}
	if len(lines) == 0 {
		lines = append(lines, "")
	}
	return lines
}

func formatEetLines(sender, text, self string, ts int64, isSystem bool, termW int) []string {
	timeW, userW, sepW := 12, 20, 3
	eetW := termW - timeW - userW - (sepW * 2) - 2
	if eetW < 10 {
		eetW = 10
	}

	timeStr := timeAgo(ts)
	var userStr, userRaw string

	if isSystem {
		userStr = FgBrightBlk + "system" + Reset
		userRaw = "system"
	} else {
		userRaw = "@" + sender
		if sender == self {
			userStr = FgBrightYellow + userRaw + Reset
		} else {
			userStr = FgCyan + userRaw + Reset
		}
	}

	userTrunc := runewidth.Truncate(userRaw, userW, "")
	if len(userTrunc) < len(userRaw) {
		if isSystem {
			userStr = FgBrightBlk + userTrunc + Reset
		} else if sender == self {
			userStr = FgBrightYellow + userTrunc + Reset
		} else {
			userStr = FgCyan + userTrunc + Reset
		}
	} else {
		userTrunc = userRaw
	}

	timePad := timeW - runewidth.StringWidth(timeStr)
	if timePad < 0 {
		timePad = 0
	}
	userPad := userW - runewidth.StringWidth(userTrunc)
	if userPad < 0 {
		userPad = 0
	}

	paddedTime := timeStr + strings.Repeat(" ", timePad)
	paddedUser := userStr + strings.Repeat(" ", userPad)
	indentStr := strings.Repeat(" ", timeW+sepW+userW+sepW)

	wrapped := customWrap(text, eetW)
	var output []string

	for i, line := range wrapped {
		if i == 0 {
			output = append(output, fmt.Sprintf("%s   %s   %s", paddedTime, paddedUser, line))
		} else {
			output = append(output, fmt.Sprintf("%s%s", indentStr, line))
		}
	}
	return output
}

// --- Messaging Logic ---

func sendSingle(v *vault.Vault, pass string, target string, text string) error {
	rc := relay.New(relayURL())
	payload := pqc.PackInner(text)

	v.Mu.Lock()
	sess := v.Sessions[target]
	v.Mu.Unlock()

	var w *pqc.WireMsg
	if sess == nil {
		bun, err := rc.FetchBundle(target)
		if err != nil {
			return fmt.Errorf("cannot fetch keys for @%s", target)
		}
		sess, im, _ := pqc.Initiate(v.Identity, bun, payload)
		p, _ := json.Marshal(im)
		w = &pqc.WireMsg{Type: pqc.WireInitial, From: v.Username, Payload: p}
		v.Mu.Lock()
		v.Sessions[target] = sess
		v.Mu.Unlock()
	} else {
		env, _ := sess.Encrypt(payload)
		p, _ := json.Marshal(env)
		w = &pqc.WireMsg{Type: pqc.WireEnvelope, From: v.Username, Payload: p}
	}

	if err := rc.Send(target, w); err != nil {
		return err
	}

	chatMsg := vault.ChatMsg{IsOut: true, IsSystem: false, TS: time.Now().Unix(), Text: text}
	v.AddMessage(target, chatMsg)
	return v.Save(configDir(), pass)
}

func pullQueue(v *vault.Vault, rc *relay.Client, target string) (int, error) {
	msgs, err := rc.InboxFrom(v.Username, v.Identity, target)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, w := range msgs {
		var pt []byte
		switch w.Type {
		case pqc.WireInitial:
			var im pqc.InitialMessage
			json.Unmarshal(w.Payload, &im)

			v.Mu.Lock()
			oldSess := v.Sessions[w.From]
			v.Mu.Unlock()

			if oldSess != nil && !bytes.Equal(oldSess.TheirSignPub, im.IKSign) {
				if oldSess.Trusted {
					sysMsg := vault.ChatMsg{IsSystem: true, TS: time.Now().Unix(), Text: fmt.Sprintf("Blocked message from @%s: identity key changed but is pinned. Unpin to accept.", w.From)}
					v.AddMessage(w.From, sysMsg)
					count++
					continue // Skip updating session
				} else {
					sysMsg := vault.ChatMsg{IsSystem: true, TS: time.Now().Unix(), Text: fmt.Sprintf("Identity key changed for @%s.", w.From)}
					v.AddMessage(w.From, sysMsg)
					count++
				}
			}

			sess, p, err := pqc.Respond(v.Identity, v.FindSPK(im.SPKID), v.FindOTPK(im.OTPKID), &im)
			if err == nil {
				sess.TheirUsername = w.From
				if oldSess != nil && bytes.Equal(oldSess.TheirSignPub, im.IKSign) {
					sess.Trusted = oldSess.Trusted
				}

				v.Mu.Lock()
				v.Sessions[w.From] = sess
				v.Mu.Unlock()
				if im.OTPKID != 0 {
					v.ConsumeOTPK(im.OTPKID)
				}
				pt = p
			}
		case pqc.WireEnvelope:
			v.Mu.Lock()
			sess := v.Sessions[w.From]
			v.Mu.Unlock()
			if sess != nil {
				var env pqc.Envelope
				json.Unmarshal(w.Payload, &env)
				p, err := sess.Decrypt(&env)
				if err == nil {
					pt = p
				}
			}
		}

		if pt != nil {
			im, _ := pqc.UnpackInner(pt)
			chatMsg := vault.ChatMsg{IsOut: false, IsSystem: false, TS: im.TS, Text: im.Text}
			v.AddMessage(w.From, chatMsg)
			count++
		}
	}
	return count, nil
}

func cmdDM(args []string) error {
	if len(args) < 2 {
		return errors.New("usage: itter dm @<user> <msg>")
	}
	target := strings.TrimPrefix(args[0], "@")
	text := strings.Join(args[1:], " ")

	v, pass, err := unlock()
	if err != nil {
		return err
	}
	if target == v.Username {
		return errors.New("cannot message yourself")
	}

	if err := sendSingle(v, pass, target, text); err != nil {
		return err
	}
	fmt.Printf("Queued for @%s.\n", target)
	return nil
}

func cmdFetch(args []string) error {
	v, pass, err := unlock()
	if err != nil {
		return err
	}
	rc := relay.New(relayURL())

	target := ""
	if len(args) > 0 {
		target = strings.TrimPrefix(args[0], "@")
	}

	senders, err := rc.FetchSenders(v.Username, v.Identity, 0)
	if err != nil {
		return err
	}

	fetchedCount := 0
	requests := 0

	for sender := range senders {
		if target != "" && sender != target {
			continue
		}

		v.Mu.Lock()
		_, known := v.Sessions[sender]
		v.Mu.Unlock()

		if !known && target == "" {
			requests++
			continue
		}

		n, _ := pullQueue(v, rc, sender)
		fetchedCount += n
	}

	if fetchedCount > 0 {
		_ = v.Save(configDir(), pass)
	}

	w, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		w = 80
	}

	if target != "" {
		for _, m := range v.GetMessages(target) {
			sender := target
			if m.IsOut {
				sender = v.Username
			}
			for _, line := range formatEetLines(sender, m.Text, v.Username, m.TS, m.IsSystem, w) {
				fmt.Println(line)
			}
		}
	} else {
		all := v.GetAllMessages()
		type display struct {
			s string
			m vault.ChatMsg
		}
		var flat []display
		for s, msgs := range all {
			for _, m := range msgs {
				flat = append(flat, display{s, m})
			}
		}
		sort.Slice(flat, func(i, j int) bool { return flat[i].m.TS < flat[j].m.TS })
		for _, d := range flat {
			sender := d.s
			if d.m.IsOut {
				sender = v.Username
			}
			for _, line := range formatEetLines(sender, d.m.Text, v.Username, d.m.TS, d.m.IsSystem, w) {
				fmt.Println(line)
			}
		}
	}

	if requests > 0 {
		fmt.Printf("\n%s%d message requests pending. Run `itter fetch @stranger` to accept.%s\n", FgBrightBlk, requests, Reset)
	}

	return nil
}

func cmdSenders() error {
	v, _, err := unlock()
	if err != nil {
		return err
	}
	rc := relay.New(relayURL())
	senders, err := rc.FetchSenders(v.Username, v.Identity, 0)
	if err != nil {
		return err
	}
	if len(senders) == 0 {
		fmt.Println("No pending messages.")
		return nil
	}
	for s, count := range senders {
		v.Mu.Lock()
		_, known := v.Sessions[s]
		v.Mu.Unlock()
		status := ""
		if !known {
			status = " (request)"
		}
		fmt.Printf("@%-20s %d%s\n", s, count, status)
	}
	return nil
}

// --- Bubble Tea App Model (Live Shell) ---

type msgsUpdatedMsg struct{}

type appModel struct {
	v      *vault.Vault
	rc     *relay.Client
	pass   string
	ti     textinput.Model
	filter string
	errStr string

	width  int
	height int
	scroll int

	history []string
	histIdx int
}

func (m appModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m appModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case msgsUpdatedMsg:
		return m, nil

	case tea.MouseMsg:
		if msg.Type == tea.MouseWheelUp {
			m.scroll += 3
		} else if msg.Type == tea.MouseWheelDown {
			m.scroll -= 3
			if m.scroll < 0 {
				m.scroll = 0
			}
		}

	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC, tea.KeyEsc:
			return m, tea.Quit

		case tea.KeyPgUp:
			m.scroll += (m.height - 4)

		case tea.KeyPgDown:
			m.scroll -= (m.height - 4)
			if m.scroll < 0 {
				m.scroll = 0
			}

		case tea.KeyUp:
			if len(m.history) > 0 && m.histIdx > 0 {
				m.histIdx--
				m.ti.SetValue(m.history[m.histIdx])
				m.ti.SetCursor(len(m.history[m.histIdx]))
			}

		case tea.KeyDown:
			if m.histIdx < len(m.history)-1 {
				m.histIdx++
				m.ti.SetValue(m.history[m.histIdx])
				m.ti.SetCursor(len(m.history[m.histIdx]))
			} else if m.histIdx == len(m.history)-1 {
				m.histIdx = len(m.history)
				m.ti.SetValue("")
			}

		case tea.KeyEnter:
			text := strings.TrimSpace(m.ti.Value())
			if text == "" {
				return m, nil
			}

			if len(m.history) == 0 || m.history[len(m.history)-1] != text {
				m.history = append(m.history, text)
			}
			m.histIdx = len(m.history)
			m.ti.SetValue("")
			m.scroll = 0
			m.errStr = ""

			parts := strings.SplitN(text, " ", 3)
			command := parts[0]

			switch command {
			case "exit", "x":
				return m, tea.Quit

			case "clear", "c":
				m.scroll = 0
				return m, nil

			case "watch":
				if len(parts) > 1 {
					target := strings.TrimPrefix(parts[1], "@")
					if target == "all" {
						m.filter = ""
						m.ti.Prompt = fmt.Sprintf("(%s)itter> ", m.v.Username)
					} else {
						m.filter = target
						m.ti.Prompt = fmt.Sprintf("(%s) -> @%s> ", m.v.Username, target)
					}
				}

			case "dm":
				if len(parts) > 2 {
					target := strings.TrimPrefix(parts[1], "@")
					msgText := parts[2]
					if target == m.v.Username {
						m.errStr = "Cannot message yourself."
					} else {
						if err := sendSingle(m.v, m.pass, target, msgText); err != nil {
							m.errStr = fmt.Sprintf("Error: %v", err)
						}
					}
				}

			default:
				m.errStr = "Unknown command. Try: dm @user <msg>, watch @user, watch all, clear, exit"
			}
		}
	}

	m.ti, cmd = m.ti.Update(msg)
	return m, cmd
}

func (m appModel) buildLines() []string {
	var lines []string
	if m.filter != "" {
		for _, msg := range m.v.GetMessages(m.filter) {
			sender := m.filter
			if msg.IsOut {
				sender = m.v.Username
			}
			lines = append(lines, formatEetLines(sender, msg.Text, m.v.Username, msg.TS, msg.IsSystem, m.width)...)
		}
	} else {
		all := m.v.GetAllMessages()
		type display struct {
			s string
			msg vault.ChatMsg
		}
		var flat []display
		for s, msgs := range all {
			for _, msg := range msgs {
				flat = append(flat, display{s, msg})
			}
		}
		sort.Slice(flat, func(i, j int) bool { return flat[i].msg.TS < flat[j].msg.TS })
		for _, d := range flat {
			sender := d.s
			if d.msg.IsOut {
				sender = m.v.Username
			}
			lines = append(lines, formatEetLines(sender, d.msg.Text, m.v.Username, d.msg.TS, d.msg.IsSystem, m.width)...)
		}
	}
	return lines
}

func (m appModel) View() string {
	if m.width == 0 {
		return ""
	}

	var b strings.Builder

	title := "all"
	if m.filter != "" {
		title = "@" + m.filter
	}

	header1 := fmt.Sprintf("%s--- Direct Messages (%s) ---%s\n", Bold, title, Reset)
	timeW, userW, sepW := 12, 20, 3
	eetW := m.width - timeW - userW - (sepW * 2) - 2
	if eetW < 10 {
		eetW = 10
	}
	header2 := fmt.Sprintf("%-*s   %-*s   %-*s\n", timeW, "Time", userW, "User", eetW, "Eet")
	header3 := fmt.Sprintf("%s%s%s\n", FgBrightBlk, strings.Repeat("-", m.width), Reset)

	b.WriteString(header1 + header2 + header3)

	lines := m.buildLines()

	footerHeight := 1
	if m.errStr != "" {
		footerHeight = 2
	}

	viewHeight := m.height - 3 - footerHeight
	if viewHeight < 1 {
		viewHeight = 1
	}

	maxScroll := len(lines) - viewHeight
	if maxScroll < 0 {
		maxScroll = 0
	}
	if m.scroll > maxScroll {
		m.scroll = maxScroll
	}

	start := len(lines) - viewHeight - m.scroll
	if start < 0 {
		start = 0
	}
	end := start + viewHeight
	if end > len(lines) {
		end = len(lines)
	}

	for i := start; i < end; i++ {
		b.WriteString(lines[i] + "\n")
	}

	for i := end - start; i < viewHeight; i++ {
		b.WriteString("\n")
	}

	if m.errStr != "" {
		b.WriteString(fmt.Sprintf("%s%s%s\n", FgBrightBlk, m.errStr, Reset))
	}
	b.WriteString(m.ti.View())

	return b.String()
}

func startPolling(p *tea.Program, v *vault.Vault, rc *relay.Client, pass string) {
	for {
		senders, err := rc.FetchSenders(v.Username, v.Identity, 25)
		if err != nil {
			time.Sleep(3 * time.Second)
			continue
		}

		needsSave := false
		for s := range senders {
			v.Mu.Lock()
			_, known := v.Sessions[s]
			v.Mu.Unlock()
			if !known {
				continue
			}

			n, _ := pullQueue(v, rc, s)
			if n > 0 {
				needsSave = true
			}
		}
		if needsSave {
			_ = v.Save(configDir(), pass)
			p.Send(msgsUpdatedMsg{})
		}
	}
}

func cmdShell() {
	v, pass, err := unlock()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	ti := textinput.New()
	ti.Focus()
	ti.Prompt = fmt.Sprintf("(%s)itter> ", v.Username)

	m := appModel{
		v:       v,
		rc:      relay.New(relayURL()),
		pass:    pass,
		ti:      ti,
		histIdx: 0,
	}

	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseCellMotion())

	go startPolling(p, m.v, m.rc, m.pass)

	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}