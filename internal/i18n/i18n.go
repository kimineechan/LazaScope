// Package i18n translates the text LazaScope shows on screen.
//
// The English text is the key: every user-visible string is passed through
// T, and a language file maps it to another language. If a string has no
// translation, T returns it unchanged, so a missing entry is never an error.
package i18n

import (
	_ "embed"
	"encoding/json"
	"os"
	"strings"
	"syscall"
)

//go:embed de.json
var deJSON []byte

var (
	lang  = "en"
	table = map[string]string{}
)

func init() {
	_ = json.Unmarshal(deJSON, &table)
}

// Set chooses the language: "de" (or any de-* locale) turns German on,
// everything else leaves the English text in place.
func Set(l string) {
	l = strings.ToLower(strings.TrimSpace(l))
	if strings.HasPrefix(l, "de") {
		lang = "de"
		return
	}
	lang = "en"
}

// Current is the language in use, "en" or "de".
func Current() string { return lang }

// T returns the text in the current language, or s itself when there is no
// translation. s stays the English wording so the two can never drift.
func T(s string) string {
	if lang == "de" {
		if v, ok := table[s]; ok {
			return v
		}
	}
	return s
}

var procGetUserDefaultUILanguage = syscall.NewLazyDLL("kernel32.dll").NewProc("GetUserDefaultUILanguage")

// System reads the language Windows is set to. German is the only
// translation for now; every other language stays English.
func System() string {
	r, _, _ := procGetUserDefaultUILanguage.Call()
	if uint16(r)&0x3ff == 0x07 {
		return "de"
	}
	return "en"
}

// FromArgs looks for --lang <code> and returns it, or "" when it is absent.
func FromArgs(args []string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--lang" {
			return args[i+1]
		}
	}
	return ""
}

// Init picks --lang first, then the Windows language.
func Init(args []string) {
	if l := FromArgs(args); l != "" {
		Set(l)
		return
	}
	if v := os.Getenv("LAZASCOPE_LANG"); v != "" {
		Set(v)
		return
	}
	Set(System())
}
