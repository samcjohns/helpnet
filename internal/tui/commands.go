package tui

import (
	"strings"
)

type command struct {
	name, args, desc string
}

var commands = []command{
	{"/run", "", "Re-run the full workflow"},
	{"/quick", "", "Run only the fast checks (skip trace and bandwidth)"},
	{"/target", "<url>", "Change the HTTP target and re-run HTTP and trace"},
	{"/speed", "", "Run the bandwidth test now"},
	{"/trace", "[host]", "Run the per-hop route trace"},
	{"/dns", "[domain]", "Run the DNS comparison on a specific domain"},
	{"/export", "[path]", "Save the report (Markdown; .json extension → JSON)"},
	{"/details", "", "Toggle raw output for all blocks"},
	{"/help", "", "List commands and keys"},
	{"/quit", "", "Exit helpnet"},
}

// suggest returns commands matching what has been typed so far. Suggestions
// show only while the command name is being typed (before any space).
func suggest(input string) []command {
	if !strings.HasPrefix(input, "/") || strings.ContainsRune(input, ' ') {
		return nil
	}
	var out []command
	for _, c := range commands {
		if strings.HasPrefix(c.name, input) {
			out = append(out, c)
		}
	}
	// Exact match with nothing else to offer: hide the popup.
	if len(out) == 1 && out[0].name == input {
		return nil
	}
	return out
}

// parseCommand splits "/name rest of args" into name and argument.
func parseCommand(line string) (name, arg string) {
	line = strings.TrimSpace(line)
	name, arg, _ = strings.Cut(line, " ")
	return strings.ToLower(name), strings.TrimSpace(arg)
}

// looksLikeHost reports whether bare input should be treated as /target.
func looksLikeHost(s string) bool {
	if strings.ContainsAny(s, " \t") || s == "" {
		return false
	}
	return strings.Contains(s, "://") || strings.Contains(s, ".")
}

var keyHelp = [][2]string{
	{"↑/↓  j/k", "Move between check blocks"},
	{"enter/space", "Expand or collapse the selected block"},
	{"r", "Re-run the full workflow"},
	{"R", "Re-run only the selected check"},
	{"/", "Focus the command bar"},
	{"s", "Jump to the final summary"},
	{"c", "Copy the summary to the clipboard"},
	{"pgup/pgdn", "Scroll"},
	{"?", "Toggle this help"},
	{"q  ctrl+c", "Quit"},
}
