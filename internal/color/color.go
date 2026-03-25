package color

import "os"

// Enabled controls whether any ANSI escape codes are emitted.
// Automatically false when stdout is not a terminal or NO_COLOR is set.
var Enabled bool

// Full indicates a capable terminal where dim and gray render correctly.
// False on Linux VGA console (TERM=linux), vt100, and similar basic terminals.
var Full bool

func init() {
	Enabled = isTerminal() && os.Getenv("NO_COLOR") == ""
	Full = Enabled && isFullColor()
}

func isTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// isFullColor returns true when the terminal is known to support dim and
// extended colors properly. Linux VGA console and basic vt terminals do not.
func isFullColor() bool {
	// Explicit full-color declarations take priority.
	if ct := os.Getenv("COLORTERM"); ct == "truecolor" || ct == "24bit" || ct == "256color" {
		return true
	}
	term := os.Getenv("TERM")
	switch term {
	case "", "dumb", "linux", "vt100", "vt102", "vt220", "vt320", "ansi":
		return false
	}
	return true
}

const (
	reset   = "\033[0m"
	bold    = "\033[1m"
	dim     = "\033[2m"
	red     = "\033[31m"
	green   = "\033[32m"
	yellow  = "\033[33m"
	blue    = "\033[34m"
	magenta = "\033[35m"
	cyan    = "\033[36m"
	gray    = "\033[37m"
)

func apply(code, text string) string {
	if !Enabled {
		return text
	}
	return code + text + reset
}

// applyFull applies the code only on full-color terminals.
// Falls back to plain text on basic terminals.
func applyFull(code, text string) string {
	if !Full {
		return text
	}
	return code + text + reset
}

func Bold(text string) string    { return apply(bold, text) }
func Dim(text string) string     { return applyFull(dim, text) }
func Red(text string) string     { return apply(red, text) }
func Green(text string) string   { return apply(green, text) }
func Yellow(text string) string  { return apply(yellow, text) }
func Blue(text string) string    { return apply(blue, text) }
func Magenta(text string) string { return apply(magenta, text) }
func Cyan(text string) string    { return apply(cyan, text) }
func Gray(text string) string    { return applyFull(gray, text) }

func BoldCyan(text string) string {
	if !Enabled {
		return text
	}
	return bold + cyan + text + reset
}

func BoldGreen(text string) string {
	if !Enabled {
		return text
	}
	return bold + green + text + reset
}

func BoldRed(text string) string {
	if !Enabled {
		return text
	}
	return bold + red + text + reset
}

func BoldYellow(text string) string {
	if !Enabled {
		return text
	}
	return bold + yellow + text + reset
}
