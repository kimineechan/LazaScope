package phrase

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"testing"
)

// The word list is BIP 39's English list exactly, byte for byte, as
// downloaded from github.com/bitcoin/bips (bip-0039/english.txt) on
// 24 November 2026.
func TestTheWordList(t *testing.T) {
	sum := sha256.Sum256([]byte(english))
	if got := hex.EncodeToString(sum[:]); got != "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda" {
		t.Fatalf("english.txt has the fingerprint %s, not the published list's", got)
	}
	words := strings.Fields(english)
	if len(words) != 2048 || len(list) != 2048 {
		t.Fatalf("%d words, %d different: want 2048", len(words), len(list))
	}
	if !sort.StringsAreSorted(words) {
		t.Error("the list is not in alphabetical order")
	}
	first := map[string]string{}
	for _, w := range words {
		if len(w) < 3 || len(w) > 8 || strings.Trim(w, "abcdefghijklmnopqrstuvwxyz") != "" {
			t.Errorf("%q is not a word of 3 to 8 small letters", w)
		}
		// The list is made so that the first four letters tell every word apart.
		key := w[:min(4, len(w))]
		if other, ok := first[key]; ok {
			t.Errorf("%q and %q start alike", other, w)
		}
		first[key] = w
	}
}

// phraseOf makes the phrase for some entropy the way BIP 39 sets out, as a
// check on Valid that does not share its code.
func phraseOf(entropy []byte) string {
	sum := sha256.Sum256(entropy)
	var bits strings.Builder
	for _, b := range entropy {
		fmt.Fprintf(&bits, "%08b", b)
	}
	fmt.Fprintf(&bits, "%08b", sum[0])
	all := bits.String()[:len(entropy)*8+len(entropy)*8/32]
	words := strings.Fields(english)
	var out []string
	for i := 0; i < len(all); i += 11 {
		var index int
		fmt.Sscanf(all[i:i+11], "%b", &index)
		out = append(out, words[index])
	}
	return strings.Join(out, " ")
}

// The test vectors published with BIP 39 (Trezor's vectors.json), English.
var vectors = []struct{ entropy, phrase string }{
	{"00000000000000000000000000000000", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"},
	{"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", "legal winner thank year wave sausage worth useful legal winner thank yellow"},
	{"ffffffffffffffffffffffffffffffff", "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"},
	{"808080808080808080808080808080808080808080808080", "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always"},
	{"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"},
	{"9e885d952ad362caeb4efe34a8e91bd2", "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic"},
	{"c0ba5a8e914111210f2bd131f3d5e08d", "scheme spot photo card baby mountain device kick cradle pact join borrow"},
	{"23db8160a31d3e0dca3688ed941adbf3", "cat swing flag economy stadium alone churn speed unique patch report train"},
	{"f30f8c1da665478f49b001d94c5fc452", "vessel ladder alter error federal sibling chat ability sun glass valve picture"},
}

func TestValidOnThePublishedVectors(t *testing.T) {
	for _, v := range vectors {
		entropy, _ := hex.DecodeString(v.entropy)
		if got := phraseOf(entropy); got != v.phrase {
			t.Errorf("entropy %s makes %q, want %q", v.entropy, got, v.phrase)
		}
		if !Valid(strings.Fields(v.phrase)) {
			t.Errorf("Valid(%q) = false", v.phrase)
		}
	}
	// Every length a phrase can have, from entropy made up here.
	for _, n := range Lengths {
		entropy := make([]byte, n*11*32/33/8)
		for i := range entropy {
			entropy[i] = byte(i*37 + n)
		}
		phrase := strings.Fields(phraseOf(entropy))
		if len(phrase) != n || !Valid(phrase) {
			t.Errorf("a made %d-word phrase: %d words, Valid %v", n, len(phrase), Valid(phrase))
		}
	}
}

func TestValidRefusesWhatIsNotAPhrase(t *testing.T) {
	twelve := strings.Fields(vectors[1].phrase)
	cases := map[string][]string{
		"the last word changed":   append(append([]string{}, twelve[:11]...), "zoo"),
		"two words swapped":       append([]string{twelve[1], twelve[0]}, twelve[2:]...),
		"one word short":          twelve[:11],
		"one word too many":       append(append([]string{}, twelve...), "legal"),
		"a word not in the list":  append(append([]string{}, twelve[:11]...), "wallet"),
		"a word in capitals":      append(append([]string{}, twelve[:11]...), "YELLOW"),
		"twelve times the same":   strings.Fields(strings.Repeat("abandon ", 12)),
		"twenty-seven words long": strings.Fields(strings.Repeat("abandon ", 26) + "about"),
		"nothing":                 nil,
	}
	for name, words := range cases {
		if Valid(words) {
			t.Errorf("%s: Valid = true", name)
		}
	}
}

func TestFind(t *testing.T) {
	twelve := vectors[1].phrase
	numbered := func(phrase string) string {
		var b strings.Builder
		for i, w := range strings.Fields(phrase) {
			fmt.Fprintf(&b, "%d. %s\r\n", i+1, w)
		}
		return b.String()
	}
	cases := []struct {
		name string
		text string
		want []Hit
	}{
		{"a phrase on one line", "My notes\n" + twelve + "\n", []Hit{{Line: 2, Words: 12, Phrase: 12}}},
		{"numbered, one word a line", "Wallet backup\r\n\r\n" + numbered(twelve), []Hit{{Line: 3, Words: 12, Phrase: 12}}},
		{"in capitals, with commas", strings.ToUpper(strings.ReplaceAll(twelve, " ", ", ")), []Hit{{Line: 1, Words: 12, Phrase: 12}}},
		{"after a heading made of list words", "Seed phrase: " + twelve, []Hit{{Line: 1, Words: 14, Phrase: 12}}},
		{"a 24-word phrase", vectors[4].phrase, []Hit{{Line: 1, Words: 24, Phrase: 24}}},
		{"two phrases", twelve + "\nand\n" + vectors[6].phrase, []Hit{{Line: 1, Words: 12, Phrase: 12}, {Line: 3, Words: 12, Phrase: 12}}},
		{"twelve list words that are not a phrase", strings.Repeat("abandon ", 12), []Hit{{Line: 1, Words: 12}}},
		{"eleven words", strings.Join(strings.Fields(twelve)[:11], " "), nil},
		{"broken by another word", strings.Join(strings.Fields(twelve)[:6], " ") + " wallet " + strings.Join(strings.Fields(twelve)[6:], " "), nil},
		{"broken by an accented word", strings.Join(strings.Fields(twelve)[:6], " ") + " café " + strings.Join(strings.Fields(twelve)[6:], " "), nil},
		{"the word list itself", english, []Hit{{Line: 1, Words: 2048, List: true}}},
		{"the word list under a heading", "word list\n" + english, []Hit{{Line: 1, Words: 2050, List: true}}},
		{"twelve words in the list's own order", "abandon ability able about above absent absorb abstract absurd abuse access accident", []Hit{{Line: 1, Words: 12, List: true}}},
		{"ordinary writing", "The meeting is on Tuesday at ten. Please bring the report and a pen, and tell Sam about the new rota before the weekend.", nil},
		{"nothing", "", nil},
	}
	for _, c := range cases {
		got := Find(c.text)
		if fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
}

// A run of random words passes the check now and then, and only a run of
// at least twelve counts at all: ordinary writing must not be taken for a
// phrase. Every sentence here is made of words that are on the list.
func TestOrdinaryWritingOfListWords(t *testing.T) {
	for _, text := range []string{
		"Please call me about the window, the door and the roof.",
		"I will visit my uncle in August; he has a farm with a horse, a goat and a cat.",
	} {
		if hits := Find(text); len(hits) != 0 {
			t.Errorf("%q: %+v", text, hits)
		}
	}
}
