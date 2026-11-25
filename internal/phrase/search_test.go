package phrase

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"lazascope/internal/model"
)

func write(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

// zipped writes a document file holding one part.
func zipped(t *testing.T, path, part, content string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	z := zip.NewWriter(f)
	w, _ := z.Create(part)
	w.Write([]byte(content))
	z.Close()
	f.Close()
}

func utf16le(text string, mark bool) []byte {
	var out []byte
	if mark {
		out = []byte{0xFF, 0xFE}
	}
	for _, u := range utf16.Encode([]rune(text)) {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

func TestTextOfEachKind(t *testing.T) {
	dir := t.TempDir()
	twelve := vectors[1].phrase
	words := strings.Fields(twelve)

	// WordPad's rich text, with the phrase in the second paragraph, half of
	// it in bold.
	rtf := `{\rtf1\ansi\ansicpg1252\deff0\nouicompat\deflang2057{\fonttbl{\f0\fnil\fcharset0 Calibri;}}` + "\r\n" +
		`{\*\generator Riched20 10.0.19041}\viewkind4\uc1 ` + "\r\n" +
		`\pard\sa200\sl276\slmult1\f0\fs22\lang9 My wallet\par` + "\r\n" +
		`\b ` + strings.Join(words[:6], " ") + `\b0  ` + strings.Join(words[6:], " ") + `\par` + "\r\n}\r\n"
	write(t, filepath.Join(dir, "notes.rtf"), []byte(rtf))

	// Word splits words over pieces of markup; the phrase is in paragraph 3.
	body := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\r\n" +
		`<w:document><w:body><w:p><w:r><w:t>Backup</w:t></w:r></w:p><w:p/><w:p><w:r><w:t xml:space="preserve">leg</w:t></w:r><w:r><w:rPr><w:b/></w:rPr><w:t>al ` +
		strings.Join(words[1:6], " ") + `</w:t></w:r><w:r><w:br/></w:r><w:r><w:t>` + strings.Join(words[6:], " ") + `</w:t></w:r></w:p></w:body></w:document>`
	zipped(t, filepath.Join(dir, "notes.docx"), "word/document.xml", body)

	// LibreOffice: the phrase in the second paragraph, after a heading.
	content := `<?xml version="1.0" encoding="UTF-8"?>` + "\n" + `<office:document-content><office:body><office:text><text:h>Keys</text:h><text:p>` +
		strings.Join(words[:6], `<text:s/>`) + `<text:line-break/>` + strings.Join(words[6:], " ") + `</text:p></office:text></office:body></office:document-content>`
	zipped(t, filepath.Join(dir, "notes.odt"), "content.xml", content)

	write(t, filepath.Join(dir, "marked.txt"), utf16le("Wallet\r\n"+twelve, true))
	write(t, filepath.Join(dir, "unmarked.txt"), utf16le("Wallet\r\n"+twelve, false))
	write(t, filepath.Join(dir, "utf8.txt"), []byte("\xEF\xBB\xBFWallet\r\n"+twelve))

	for _, name := range []string{"notes.rtf", "notes.docx", "notes.odt", "marked.txt", "unmarked.txt", "utf8.txt"} {
		text, err := Text(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		want := Hit{Line: 2, Words: 12, Phrase: 12}
		if name == "notes.docx" {
			want.Line = 3
		}
		if got := Find(text); len(got) != 1 || got[0] != want {
			t.Errorf("%s: got %+v, want %+v\ntext: %q", name, got, want, text)
		}
	}
	if _, err := Text(filepath.Join(dir, "missing.txt")); err == nil {
		t.Error("a missing file read without an error")
	}
	// A file that says it is a Word document and is not.
	write(t, filepath.Join(dir, "broken.docx"), []byte("not a zip"))
	if _, err := Text(filepath.Join(dir, "broken.docx")); err == nil {
		t.Error("a broken document read without an error")
	}
}

func TestSearch(t *testing.T) {
	root := t.TempDir()
	twelve := vectors[1].phrase
	write(t, filepath.Join(root, "Notes", "wallet.txt"), []byte("Exodus\n\n"+twelve+"\n"))
	write(t, filepath.Join(root, "Notes", "odd words.md"), []byte("# Words\n\n"+strings.Repeat("abandon ", 12)+"\n"))
	write(t, filepath.Join(root, "Projects", "app", "assets", "bip39.json"), []byte(`["`+strings.Join(strings.Fields(english), `","`)+`"]`))
	write(t, filepath.Join(root, "Projects", "app", "node_modules", "lib", "README.md"), []byte(twelve)) // in a folder never entered
	write(t, filepath.Join(root, "Projects", "app", "main_test.go"), []byte(twelve))                     // program code is not read
	write(t, filepath.Join(root, "Projects", "app", "wallet.env"), []byte("MNEMONIC=\""+vectors[6].phrase+"\"\n"))
	write(t, filepath.Join(root, "empty.txt"), nil)
	write(t, filepath.Join(root, "letter.txt"), []byte("Dear Sam, thank you for the lovely visit."))
	big := make([]byte, Most+1)
	for i := range big {
		big[i] = 'a'
	}
	write(t, filepath.Join(root, "big.log"), big)
	deep := root
	for range Depth + 1 {
		deep = filepath.Join(deep, "d")
	}
	write(t, filepath.Join(deep, "deep.txt"), []byte(twelve)) // further down than a search goes
	write(t, filepath.Join(root, "d", "shallow.txt"), []byte(twelve))
	write(t, filepath.Join(root, "Notes", "old seed copy.txt"), []byte(electrumSeeds[1]))
	write(t, filepath.Join(root, "Notes", "my seed words.txt"), []byte(strings.Repeat("abandon ", 12))) // no phrase, but its name points to one

	result := Search([]string{root}, nil, func(int) {})
	if result.Stopped || result.Full || result.Big != 1 || result.Locked != 0 || result.Cloud != 0 {
		t.Errorf("stopped %v, full %v, big %d, locked %d, cloud %d", result.Stopped, result.Full, result.Big, result.Locked, result.Cloud)
	}
	// wallet.txt, old seed copy.txt, my seed words.txt, odd words.md,
	// bip39.json, wallet.env, letter.txt, shallow.txt
	if result.Read != 8 {
		t.Errorf("read %d files, want 8", result.Read)
	}
	got := map[string]string{}
	for _, f := range result.Found {
		rel, _ := filepath.Rel(root, f.Path)
		got[rel] = fmt.Sprintf("lines %v, words %d, phrase %d, electrum %v, named %v, list %v", f.Lines, f.Words, f.Phrase, f.Electrum, f.Named, f.List)
	}
	want := map[string]string{
		filepath.Join("Notes", "wallet.txt"):                     "lines [3], words 12, phrase 12, electrum false, named true, list false",
		filepath.Join("Projects", "app", "wallet.env"):           "lines [1], words 12, phrase 12, electrum false, named true, list false",
		filepath.Join("d", "shallow.txt"):                        "lines [1], words 12, phrase 12, electrum false, named false, list false",
		filepath.Join("Notes", "old seed copy.txt"):              "lines [1], words 12, phrase 12, electrum true, named true, list false",
		filepath.Join("Notes", "my seed words.txt"):              "lines [1], words 12, phrase 0, electrum false, named true, list false",
		filepath.Join("Notes", "odd words.md"):                   "lines [3], words 12, phrase 0, electrum false, named false, list false",
		filepath.Join("Projects", "app", "assets", "bip39.json"): "lines [1], words 0, phrase 0, electrum false, named false, list true",
	}
	if len(got) != len(want) {
		t.Errorf("found %d files, want %d: %v", len(got), len(want), got)
	}
	for name, w := range want {
		if got[name] != w {
			t.Errorf("%s: got %q, want %q", name, got[name], w)
		}
	}
	// The likeliest phrases come first and the word list last.
	if n := len(result.Found); n == 0 || result.Found[0].Phrase == 0 || !result.Found[n-1].List {
		t.Errorf("the order is wrong: %+v", result.Found)
	}
	// Nothing in the result is a word of a phrase: it holds where, never
	// what. The paths are left out of this check, as a folder could have any
	// name.
	bare := result
	bare.Folders = nil
	bare.Found = append([]model.PhraseFile{}, result.Found...)
	for i := range bare.Found {
		bare.Found[i].Path = ""
	}
	all := strings.ToLower(jsonOf(bare))
	for _, w := range append(append(strings.Fields(twelve), strings.Fields(vectors[6].phrase)...), strings.Fields(electrumSeeds[1])...) {
		if strings.Contains(all, w) {
			t.Errorf("the result holds the word %q: %s", w, all)
		}
	}

	// A search that is stopped says so.
	stop := make(chan struct{})
	close(stop)
	if r := Search([]string{root}, stop, nil); !r.Stopped || r.Read != 0 {
		t.Errorf("a stopped search: stopped %v, read %d", r.Stopped, r.Read)
	}
	// A folder that is not there is one that could not be opened.
	if r := Search([]string{filepath.Join(root, "missing")}, nil, nil); r.Locked != 1 || r.Read != 0 {
		t.Errorf("a missing folder: locked %d, read %d", r.Locked, r.Read)
	}
}

func jsonOf(v any) string {
	data, _ := json.Marshal(v)
	return string(data)
}

func TestDepth(t *testing.T) {
	root := filepath.Join("Users", "sam")
	for path, want := range map[string]int{
		root:                                     0,
		filepath.Join(root, "Desktop"):           1,
		filepath.Join(root, "Desktop", "a", "b"): 3,
	} {
		if got := depth(root, path); got != want {
			t.Errorf("depth(%q) = %d, want %d", path, got, want)
		}
	}
}

func TestNamed(t *testing.T) {
	for name, want := range map[string]bool{
		"old seed copy.txt": true, "My Wallet.docx": true, "metamask backup.md": true, "24 words.txt": true, "eth keys.txt": true,
		"secrets.txt": true, "BTC.txt": true, "ledger_nano.txt": true,
		"methods.md": false, "together.txt": false, "notes.txt": false, "general ledgers.csv": false, "shopping list.txt": false,
	} {
		if got := Named(filepath.Join("C:", "Users", "sam", name)); got != want {
			t.Errorf("Named(%q) = %v, want %v", name, got, want)
		}
	}
	// Only the file's own name counts, not the folders it is in.
	if Named(filepath.Join("C:", "Users", "sam", "Wallet stuff", "notes.txt")) {
		t.Error("a folder's name counted")
	}
}
