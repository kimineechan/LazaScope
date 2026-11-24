// Package phrase finds recovery phrases written down in files. A recovery
// phrase (or seed phrase) is the 12 to 24 words a cryptocurrency wallet
// gives when it is made, chosen from a public list of 2,048 words. Whoever
// has the words has the coins, so a phrase saved in a file on the PC can
// be taken by anyone, or any program, that reads the file, and malware that
// steals passwords looks for exactly that.
//
// The finder looks for runs of 12 or more words from the list, and for a
// complete phrase inside a run checks the phrase's own checksum, which a
// random run of words passes only now and then. It says where a phrase is
// (the file and the line) and never what it says: the words are not shown,
// kept or written anywhere.
//
// The word list is BIP 39's English list (bip-0039/english.txt in
// github.com/bitcoin/bips), under the MIT licence; see
// THIRD-PARTY-NOTICES.txt.
package phrase

import (
	"crypto/sha256"
	_ "embed"
	"strings"
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

// Lengths are the lengths a phrase can have, longest first.
var Lengths = []int{24, 21, 18, 15, 12}

// Valid reports whether words, in small letters, are a complete phrase whose
// checksum holds. A phrase of n words carries 11 bits a word: the last n/3
// of them are the start of the SHA-256 of the rest.
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

// Hit is a run of recovery words found in a text.
type Hit struct {
	Line   int  // the line the run starts on, counting from 1
	Words  int  // how many recovery words there are in a row
	Phrase int  // the length of a complete phrase in the run whose checksum holds, or 0 for none
	List   bool // the words are in the list's own order: the word list itself, or part of it, not a phrase
}

// Shortest is the fewest words in a row that are reported: the length of
// the shortest phrase.
const Shortest = 12

// Find looks through a text for runs of recovery words. Numbers, marks and
// line breaks between the words, as in "1. abandon 2. ability", do not break
// a run; any other word does.
func Find(text string) []Hit {
	var hits []Hit
	var run []string
	line, start := 1, 1
	flush := func() {
		if len(run) >= Shortest {
			hit := Hit{Line: start, Words: len(run), List: ordered(run)}
			if !hit.List {
				hit.Phrase = complete(run)
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
	for _, r := range text {
		switch {
		case r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z':
			word.WriteRune(r)
		case r >= 0x80 && isLetter(r):
			// A letter outside plain ASCII belongs to a word that is in no
			// English list: it breaks the run.
			word.WriteRune(r)
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

func isLetter(r rune) bool {
	return r >= 0xC0 && r != 0xD7 && r != 0xF7 // Latin-1 letters and everything beyond count as letters
}

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

// complete returns the length of the longest complete phrase in a run of
// recovery words whose checksum holds, or 0.
func complete(run []string) int {
	for _, n := range Lengths {
		for i := 0; i+n <= len(run); i++ {
			if Valid(run[i : i+n]) {
				return n
			}
		}
	}
	return 0
}
