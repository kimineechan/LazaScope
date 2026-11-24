package cmdline

import (
	"encoding/base64"
	"strings"
	"unicode/utf16"

	"lazascope/internal/winpath"
)

// PowerShell can be handed its commands in an encoded form: the text is
// turned into a long run of letters and digits (base64) and given with the
// switch -EncodedCommand. Honest tools do this to get awkward characters
// past the command line. It also hides what the commands say from anyone
// who reads the line, which is why it is worth undoing here.

// encodedArgument returns the encoded text a PowerShell command line
// carries, as it stands on the line.
func encodedArgument(words []string) (string, bool) {
	for i := 0; i+1 < len(words); i++ {
		name, isOption := option(words[i])
		if !isOption {
			continue
		}
		// PowerShell takes any beginning of the switch's name. "e" alone means
		// this switch, and "ex" and longer mean ExecutionPolicy.
		if name == "ec" || (strings.HasPrefix("encodedcommand", name) && !strings.HasPrefix(name, "ex")) {
			if text := strings.Trim(words[i+1], `'"`); len(text) >= 8 {
				return text, true
			}
		}
	}
	return "", false
}

// EncodedCommand returns the commands that a command line hands to
// PowerShell in encoded form, decoded back into text. ok is false when the
// line carries none, or when what it carries does not decode into text.
func EncodedCommand(line string) (commands string, ok bool) {
	words := Words(line)
	if len(words) < 2 {
		return "", false
	}
	// The switch only means this for PowerShell, wherever on the line
	// PowerShell is named: "cmd /c powershell -enc ..." counts too.
	named := false
	for _, word := range words {
		switch winpath.Stem(word) {
		case "powershell", "pwsh", "powershell_ise":
			named = true
		}
	}
	if !named {
		return "", false
	}
	text, found := encodedArgument(words)
	if !found {
		return "", false
	}
	raw, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		// Some tools leave off the padding at the end.
		if raw, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(text, "=")); err != nil {
			return "", false
		}
	}
	if len(raw) < 2 {
		return "", false
	}
	// PowerShell expects two bytes to a letter.
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	decoded := string(utf16.Decode(units))
	// What comes out must read as text. Commands are written almost wholly
	// in the plain letters, digits and signs of a keyboard, with room for
	// the odd word in another alphabet. Anything else was not commands in
	// this form, and showing it would only confuse.
	plain, all := 0, 0
	for _, r := range decoded {
		all++
		if (r >= ' ' && r <= '~') || r == '\r' || r == '\n' || r == '\t' {
			plain++
		}
	}
	if all == 0 || plain*10 < all*8 {
		return "", false
	}
	return decoded, true
}

// Encoded reports whether a command line hands PowerShell its commands in
// encoded form.
func Encoded(line string) bool {
	text, found := encodedArgument(Words(line))
	if !found || len(text) < 16 {
		return false
	}
	for _, r := range text {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '+' || r == '/' || r == '=') {
			return false
		}
	}
	return true
}
