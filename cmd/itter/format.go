package main

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/mattn/go-runewidth"

	"github.com/rrmn/itter-client/internal/vault"
)

const (
	Reset          = "\033[0m"
	Bold           = "\033[1m"
	FgRed          = "\033[31m"
	FgGreen        = "\033[32m"
	FgCyan         = "\033[36m"
	FgBrightYellow = "\033[93m"
	FgBrightBlk    = "\033[90m"
)

// clean makes text from the network safe to print. Without it a contact
// could send terminal escape sequences (clear the screen, rewrite earlier
// lines, set the clipboard via OSC 52) or bidi overrides that make text read
// differently from what was sent.
func clean(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(' ')
		case r == unicode.ReplacementChar:
			b.WriteRune(r)
		case unicode.IsControl(r): // C0, DEL, C1 (includes ESC and CSI)
		case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069: // bidi embeddings, overrides, isolates
		case r == 0x200E || r == 0x200F || r == 0x061C: // direction marks
		case r == 0xFEFF || r == 0x2028 || r == 0x2029: // BOM, line/paragraph separators
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func timeAgo(ts int64) string {
	secs := int(time.Since(time.Unix(ts, 0)).Seconds())
	if secs < 10 {
		return "just now"
	}
	if secs < 60 {
		return fmt.Sprintf("%ds ago", secs)
	}
	if mins := secs / 60; mins < 60 {
		return fmt.Sprintf("%dm ago", mins)
	}
	if hours := secs / 3600; hours < 24 {
		return fmt.Sprintf("%dh ago", hours)
	}
	return fmt.Sprintf("%dd ago", secs/86400)
}

// wrap breaks text into lines of at most maxWidth cells, at spaces where
// possible; words longer than a line (URLs) are split.
func wrap(text string, maxWidth int) []string {
	if maxWidth < 1 {
		maxWidth = 1
	}
	var lines []string
	cur := ""
	flush := func() {
		if cur != "" {
			lines = append(lines, cur)
			cur = ""
		}
	}
	for _, w := range strings.Fields(text) {
		for runewidth.StringWidth(w) > maxWidth {
			flush()
			head := runewidth.Truncate(w, maxWidth, "")
			if head == "" { // a single rune wider than the line
				head = string([]rune(w)[:1])
			}
			lines = append(lines, head)
			w = w[len(head):]
		}
		switch {
		case w == "":
		case cur == "":
			cur = w
		case runewidth.StringWidth(cur)+1+runewidth.StringWidth(w) <= maxWidth:
			cur += " " + w
		default:
			flush()
			cur = w
		}
	}
	flush()
	if len(lines) == 0 {
		lines = []string{""}
	}
	return lines
}

// wrapPre breaks a preformatted line (help text, a table) at maxWidth cells
// without touching its spacing.
func wrapPre(text string, maxWidth int) []string {
	if maxWidth < 10 {
		maxWidth = 10
	}
	var lines []string
	for runewidth.StringWidth(text) > maxWidth {
		head := runewidth.Truncate(text, maxWidth, "")
		if head == "" {
			break
		}
		lines = append(lines, head)
		text = text[len(head):]
	}
	return append(lines, text)
}

var ansiRE = regexp.MustCompile("\x1b\\[[0-9;]*m")

// plain removes colour codes, for output that does not go to a terminal.
func plain(s string) string { return ansiRE.ReplaceAllString(s, "") }

func pad(s string, width int) string {
	return s + strings.Repeat(" ", max(0, width-runewidth.StringWidth(s)))
}

// labelWidth is the width of the name column that fits all of labels: no
// wider than needed, so that short names leave the room to the text.
func labelWidth(labels ...string) int {
	const minW, maxW = 6, 23 // "system" … "→ @" plus the longest itter name
	w := minW
	for _, l := range labels {
		w = max(w, runewidth.StringWidth(clean(l)))
	}
	return min(w, maxW)
}

// formatEetLines renders one message in itter's three-column layout. label is
// what goes in the middle column (userW cells wide, see labelWidth); mine
// marks the user's own messages.
func formatEetLines(label string, mine bool, msg vault.ChatMsg, userW, termW int) []string {
	const timeW, sepW = 12, 2
	textW := termW - timeW - userW - 2*sepW - 1
	if textW < 10 {
		textW = 10
	}

	color := FgCyan
	switch {
	case msg.IsSystem:
		label, color = "system", FgBrightBlk
	case mine:
		color = FgBrightYellow
	}
	label = runewidth.Truncate(clean(label), userW, "")

	status := ""
	if msg.IsOut {
		switch msg.Status {
		case vault.StatusQueued:
			status = FgBrightBlk + " [queued]" + Reset
		case vault.StatusFailed:
			status = FgRed + " [not delivered]" + Reset
		}
	}

	indent := strings.Repeat(" ", timeW+sepW+userW+sepW)
	wrapped := wrap(clean(msg.Text), textW)
	out := make([]string, 0, len(wrapped))
	for i, line := range wrapped {
		if msg.IsSystem {
			line = FgBrightBlk + line + Reset
		}
		if i == len(wrapped)-1 {
			line += status
		}
		if i == 0 {
			sep := strings.Repeat(" ", sepW)
			out = append(out, pad(timeAgo(msg.TS), timeW)+sep+color+label+Reset+strings.Repeat(" ", max(0, userW-runewidth.StringWidth(label)))+sep+line)
		} else {
			out = append(out, indent+line)
		}
	}
	return out
}
