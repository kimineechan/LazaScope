package rules

import (
	"strings"

	"lazascope/internal/cmdline"
	"lazascope/internal/winpath"
)

// Scrambled looks at a command for the ways an attacker hides what it does,
// and returns each one it finds in plain words. Nothing found gives nil.
//
// program is the program the command starts. The signs only mean something
// for Windows' scripting tools and the handful of other tools that are
// borrowed to fetch or run things, so any other program gives nil.
func Scrambled(program, command string) []string {
	stem := winpath.Stem(program)
	if !scriptHosts[stem] && !helperTools[stem] {
		return nil
	}
	lower := strings.ToLower(command)
	// The same text with the marks removed that are used to break words up.
	joined := strings.NewReplacer("^", "", "`", "", `"+"`, "", `'+'`, "", `" + "`, "", `' + '`, "").Replace(lower)
	has := func(words ...string) bool {
		for _, word := range words {
			if strings.Contains(joined, word) {
				return true
			}
		}
		return false
	}
	var signs []string
	add := func(sign string) { signs = append(signs, sign) }

	if encoded(command) {
		add("It hands PowerShell its instructions in an encoded form, which hides what they say.")
	}
	if has("frombase64string", "[convert]::", "-bxor", "gzipstream", "deflatestream", "[text.encoding]", "[system.text.encoding]", "certutil -decode", "certutil.exe -decode", "certutil /decode") ||
		strings.Count(joined, "[char]") >= 3 {
		add("It unpacks or decodes hidden text before running it.")
	}
	if has("invoke-expression", "iex ", "iex(", "|iex", "| iex", "iex\"", "iex'") {
		add("It runs a piece of text as commands, so the real commands are not on the line.")
	}
	web := strings.Contains(joined, "http://") || strings.Contains(joined, "https://") || strings.Contains(joined, "ftp://")
	if has("downloadstring", "downloadfile", "downloaddata", "net.webclient", "invoke-webrequest", "invoke-restmethod", "start-bitstransfer", "msxml2.xmlhttp", "winhttp.winhttprequest", "-urlcache", "/urlcache", "/transfer") ||
		(web && has("iwr ", "irm ", "curl ", "wget ", "bitsadmin")) || (web && (stem == "mshta" || stem == "regsvr32" || stem == "msiexec" || stem == "rundll32")) {
		add("It fetches something from the internet and runs it.")
	}
	if has("javascript:", "vbscript:") || (stem == "regsvr32" && has("scrobj.dll")) {
		add("It makes a Windows tool run script that is written on the command line itself.")
	}
	if strings.Count(lower, "^") >= 4 || strings.Count(lower, "`") >= 4 || strings.Count(lower, `"+"`)+strings.Count(lower, `'+'`)+strings.Count(lower, `" + "`)+strings.Count(lower, `' + '`) >= 3 || strings.Contains(lower, ":~") {
		add("Its words are broken into pieces so that they are hard to read or search for.")
	}
	if blob(command) {
		add("It carries a long block of unreadable text.")
	}
	return signs
}

// Hidden reports whether a command asks a scripting tool to work without
// showing a window.
func Hidden(program, command string) bool {
	stem := winpath.Stem(program)
	if stem != "powershell" && stem != "pwsh" && stem != "conhost" && stem != "cmd" && stem != "wscript" && stem != "mshta" {
		return false
	}
	words := cmdline.Words(strings.ToLower(command))
	for i, word := range words {
		if word == "--headless" {
			return true
		}
		if len(word) > 1 && (word[0] == '-' || word[0] == '/') {
			name := strings.TrimLeft(word, "-/")
			if name != "" && strings.HasPrefix("windowstyle", name) && i+1 < len(words) {
				if next := words[i+1]; strings.HasPrefix("hidden", next) || next == "1" {
					return true
				}
			}
		}
	}
	return false
}

// encoded reports whether a command gives PowerShell the -EncodedCommand
// switch, in any of the shortened forms PowerShell accepts.
func encoded(command string) bool {
	words := cmdline.Words(command)
	for i, word := range words {
		if len(word) < 2 || (word[0] != '-' && word[0] != '/') || i+1 >= len(words) {
			continue
		}
		name := strings.ToLower(strings.TrimLeft(word, "-/"))
		if name == "ec" || (name != "" && strings.HasPrefix("encodedcommand", name) && !strings.HasPrefix("executionpolicy", name)) {
			if base64ish(words[i+1]) >= 16 {
				return true
			}
		}
	}
	return false
}

// base64ish returns the length of a word if it is made only of the letters
// that encoded text uses, and zero otherwise.
func base64ish(word string) int {
	for _, r := range word {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '+' || r == '/' || r == '=') {
			return 0
		}
	}
	return len(word)
}

// blob reports whether a command holds a long run of encoded-looking text.
// Paths, numbers written in sixteens and names made of whole words are let
// through.
func blob(command string) bool {
	for _, word := range strings.FieldsFunc(command, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '"' || r == '\'' || r == ',' || r == ';' || r == '(' || r == ')' || r == '\\' || r == ':' || r == '.' || r == '-' || r == '_' || r == '{' || r == '}'
	}) {
		if base64ish(word) < 80 {
			continue
		}
		// Encoded text mixes capitals and small letters throughout.
		upper, lower := 0, 0
		for _, r := range word {
			switch {
			case r >= 'A' && r <= 'Z':
				upper++
			case r >= 'a' && r <= 'z':
				lower++
			}
		}
		if upper*8 >= len(word) && lower*8 >= len(word) {
			return true
		}
	}
	return false
}
