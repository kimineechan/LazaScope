// Package phrase finds recovery phrases written down in files. A recovery
// phrase (or seed phrase) is the 12 to 24 words a cryptocurrency wallet
// gives when it is made, chosen from a public list of 2,048 words. Whoever
// has the words has the coins, so a phrase saved in a file can be taken by
// anyone, or any program, that reads the file, and malware that steals
// passwords looks for exactly that.
//
// The finder looks for runs of 12 or more words from the list. Within a run
// it looks for complete phrases: a phrase carries a check of its own, which
// a random run of words passes only now and then. BIP 39's check is used by
// most wallets, and Electrum's own by Electrum. It says where a phrase is
// (the file and the line) and never what it says: the words are not shown,
// kept or written anywhere.
//
// The word list is BIP 39's English list (bip-0039/english.txt in
// github.com/bitcoin/bips), under the MIT licence; see
// THIRD-PARTY-NOTICES.txt. Electrum's new seeds use the same list.
package phrase

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"strings"
	"unicode"
	"unicode/utf8"
)

//go:embed english.txt
var english string

// list holds each word's place in the list, from 0 to 2047.
var list = func() map[string]int {
	words := strings.Fields(english)
	out := make(map[string]int, len(words))
	for i, w := range words {
		out[w] = i
	}
	return out
}()

// Lengths are the lengths a BIP 39 phrase can have, longest first.
var Lengths = []int{24, 21, 18, 15, 12}

// Valid reports whether words, in small letters, are a complete BIP 39
// phrase whose check holds. A phrase of n words carries 11 bits a word: the
// last n/3 of them are the start of the SHA-256 of the rest.
func Valid(words []string) bool {
	n := len(words)
	if n < 12 || n > 24 || n%3 != 0 {
		return false
	}
	bits := make([]byte, 0, n*11)
	for _, w := range words {
		index, ok := list[w]
		if !ok {
			return false
		}
		for b := 10; b >= 0; b-- {
			bits = append(bits, byte(index>>b&1))
		}
	}
	checksum := n * 11 / 33
	entropy := make([]byte, (len(bits)-checksum)/8)
	for i := range entropy {
		for b := range 8 {
			entropy[i] = entropy[i]<<1 | bits[i*8+b]
		}
	}
	sum := sha256.Sum256(entropy)
	for b := range checksum {
		if sum[0]>>(7-b)&1 != bits[len(bits)-checksum+b] {
			return false
		}
	}
	return true
}

// Electrum reports whether words, in small letters, are a seed made by the
// Electrum wallet. Electrum uses the same word list with a check of its
// own: the HMAC-SHA512 of the phrase, keyed with "Seed version", starts with
// the seed's version written in hexadecimal: 01 for a standard wallet, 100
// for SegWit, and 101 or 102 for a wallet with two-factor sign-in. Random
// words pass about one time in 216. Its seeds have 12 words, and 13 in some
// early versions.
func Electrum(words []string) bool {
	if len(words) != 12 && len(words) != 13 {
		return false
	}
	for _, w := range words {
		if _, ok := list[w]; !ok {
			return false
		}
	}
	mac := hmac.New(sha512.New, []byte("Seed version"))
	mac.Write([]byte(strings.Join(words, " ")))
	sum := mac.Sum(nil)
	switch {
	case sum[0] == 0x01:
		return true
	case sum[0] == 0x10 && sum[1]>>4 <= 2: // 100, 101 and 102
		return true
	}
	return false
}

// Hit is a run of recovery words found in a text.
type Hit struct {
	Line     int  // the line the run starts on, counting from 1
	Words    int  // how many recovery words there are in a row
	Phrase   int  // the length of the longest complete phrase in the run, or 0 for none
	Electrum bool // that phrase is an Electrum seed, which only Electrum's check confirms
	List     bool // the words are in the list's own order: the word list itself, or part of it, not a phrase
}

// Shortest is the fewest words in a row that are reported: the length of
// the shortest phrase.
const Shortest = 12

// Find looks through a text for runs of recovery words. Numbers, marks and
// line breaks between the words, as in "1. abandon 2. ability", do not break
// a run; any other word does. So do the marks of program code, such as = and
// {, and names in program code such as canvas.width or seed_words: words
// joined by a dot or a line are one name.
func Find(text string) []Hit {
	var hits []Hit
	var run []string
	line, start := 1, 1
	flush := func() {
		if len(run) >= Shortest {
			hit := Hit{Line: start, Words: len(run), List: ordered(run)}
			if !hit.List {
				hit.Phrase, hit.Electrum = phrases(run)
			}
			hits = append(hits, hit)
		}
		clear(run) // the words go as soon as they are judged
		run = run[:0]
	}
	word := strings.Builder{}
	end := func() {
		if word.Len() == 0 {
			return
		}
		w := strings.ToLower(word.String())
		word.Reset()
		if _, ok := list[w]; ok {
			if len(run) == 0 {
				start = line
			}
			run = append(run, w)
			return
		}
		flush()
	}
	for i := 0; i < len(text); {
		r, size := utf8.DecodeRuneInString(text[i:])
		i += size
		switch {
		case asciiLetter(r):
			word.WriteRune(r)
		case r >= 0x80 && (unicode.IsLetter(r) || unicode.IsMark(r) || r == utf8.RuneError):
			// A letter outside plain ASCII belongs to a word that is in no
			// English list, and so does a byte that is not text: either
			// breaks the run.
			word.WriteRune(r)
		case (r == '.' || r == '_') && word.Len() > 0 && i < len(text) && asciiLetter(rune(text[i])):
			word.WriteRune(r)
		case r == '\\' && i < len(text) && strings.IndexByte("nrt", text[i]) >= 0:
			// A line break or a tab written as JSON writes one inside text.
			i++
			end()
		case strings.ContainsRune("={}<>&$^~`\\", r):
			// Marks of program code, which never stand between the words of
			// a phrase someone wrote down.
			end()
			flush()
		default:
			end()
			if r == '\n' {
				line++
			}
		}
	}
	end()
	flush()
	return hits
}

func asciiLetter(r rune) bool { return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' }

// ordered reports whether a run is the word list itself: each word comes
// after the one before it in the list's own order. Wallet programs carry
// the list in that order, while the words of a phrase are drawn at random,
// and 12 of them fall in order once in about 479 million phrases. A long
// run with a stray word or two, such as a heading, still counts.
func ordered(run []string) bool {
	out := 0
	for i := 1; i < len(run); i++ {
		if list[run[i]] <= list[run[i-1]] {
			out++
		}
	}
	return out == 0 || len(run) >= 100 && out <= 2
}

// Slack is how many other words from the list a run may hold for each
// phrase in it, such as the heading "seed phrase", which is made of list
// words too.
const Slack = 3

// phrases looks for complete phrases that make up a run of recovery words,
// and returns the length of the longest, and whether it is an Electrum
// seed. The run must be the phrases and little else: one phrase or several
// in a row, with at most Slack other words for each. A long run of other
// words holds a phrase-shaped stretch by chance, so it does not count.
//
// A phrase must also have words that are nearly all different. They are
// drawn at random from 2,048, so a word comes twice in about one 12-word
// phrase in 30 and three times almost never, while program code and
// ordinary writing repeat words all the time.
func phrases(run []string) (int, bool) {
	type state struct {
		cost     int // words left over, less Slack for each phrase
		longest  int
		electrum bool
		ok       bool
	}
	best := make([]state, len(run)+1)
	best[0].ok = true
	better := func(a, b state) bool {
		return !b.ok || a.cost < b.cost || a.cost == b.cost && a.longest > b.longest
	}
	for i := range len(run) {
		if !best[i].ok {
			continue
		}
		// The word at i is left over.
		next := best[i]
		next.cost++
		if better(next, best[i+1]) {
			best[i+1] = next
		}
		// A phrase starts at i.
		for _, n := range []int{24, 21, 18, 15, 13, 12} {
			if i+n > len(run) || !varied(run[i:i+n]) {
				continue
			}
			bip := n%3 == 0 && Valid(run[i:i+n])
			if !bip && !Electrum(run[i:i+n]) {
				continue
			}
			next := best[i]
			next.cost -= Slack
			if n > next.longest {
				next.longest, next.electrum = n, !bip
			}
			if better(next, best[i+n]) {
				best[i+n] = next
			}
		}
	}
	end := best[len(run)]
	if end.longest == 0 || end.cost > 0 {
		return 0, false
	}
	return end.longest, end.electrum
}

// varied reports whether nearly all the words of a stretch are different:
// at least three in four of them.
func varied(words []string) bool {
	seen := make(map[string]bool, len(words))
	for _, w := range words {
		seen[w] = true
	}
	return len(seen)*4 >= len(words)*3
}
