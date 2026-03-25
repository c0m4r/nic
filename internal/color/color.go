package color

import "os"

var Enabled = isTerminal()

func isTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
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
	gray    = "\033[90m"
)

func apply(code, text string) string {
	if !Enabled {
		return text
	}
	return code + text + reset
}

func Bold(text string) string    { return apply(bold, text) }
func Dim(text string) string     { return apply(dim, text) }
func Red(text string) string     { return apply(red, text) }
func Green(text string) string   { return apply(green, text) }
func Yellow(text string) string  { return apply(yellow, text) }
func Blue(text string) string    { return apply(blue, text) }
func Magenta(text string) string { return apply(magenta, text) }
func Cyan(text string) string    { return apply(cyan, text) }
func Gray(text string) string    { return apply(gray, text) }

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
