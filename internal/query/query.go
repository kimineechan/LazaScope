// Package query reads what is typed into LazaScope's search box and says
// which rows it matches. A search is a list of terms, and a row must match
// every one of them:
//
//	anydesk              rows that mention AnyDesk anywhere
//	kind:service         rows whose kind mentions "service"
//	signed:no            rows about a file that carries no signature
//	path:*\Users\*       rows whose path fits, where * stands for anything
//	kind:service,driver  rows whose kind mentions either
//	-windows:yes         a minus in front leaves out what the term matches
//	"program files"      quotes keep words, spaces and commas together
//
// It is pure: it knows nothing of Windows or of the window, so it can be
// tested on its own and used by the command-line tool too.
package query

import (
	"errors"
	"sort"
	"strings"
)

// Field is a name a search can ask about.
type Field struct {
	Name   string
	About  string   // what it means, for the help text
	Values []string // the words it takes, when it takes only a few; nil for any text
	Exact  bool     // a value must match the whole of the row's value, not a part
}

// Fields are the names a search can ask about.
var Fields = []Field{
	{Name: "name", About: "the item's name"},
	{Name: "kind", About: "what kind of item it is, such as service, scheduled task or driver"},
	{Name: "path", About: "the full path of its file"},
	{Name: "maker", About: "who signed its file, or who the file says made it"},
	{Name: "signed", About: "whether its file carries a signature that holds", Values: []string{"yes", "no", "broken"}, Exact: true},
	{Name: "account", About: "the account it runs as"},
	{Name: "command", About: "the command it runs"},
	{Name: "pid", About: "a running program's number", Exact: true},
	{Name: "parent", About: "the number of the program that started it", Exact: true},
	{Name: "port", About: "a port number, at either end of a connection", Exact: true},
	{Name: "address", About: "an address at either end, or a name looked up for it"},
	{Name: "reach", About: "how far the other end is: this pc, local network or internet"},
	{Name: "level", About: "how much attention it deserves", Values: []string{"first", "look", "know", "fine", "unknown", "none"}, Exact: true},
	{Name: "rule", About: "the name of a rule that flagged it, such as startup-unsigned"},
	{Name: "attack", About: "an ATT&CK technique number, such as T1547.001"},
	{Name: "vt", About: "what VirusTotal's engines said", Values: []string{"flagged", "clean", "unknown", "notasked"}, Exact: true},
	{Name: "new", About: "new since the comparison or the watch", Values: []string{"yes", "no"}, Exact: true},
	{Name: "windows", About: "a part of Windows itself", Values: []string{"yes", "no"}, Exact: true},
	{Name: "page", About: "the page it is on, such as start-up or running"},
}

func field(name string) (Field, bool) {
	for _, f := range Fields {
		if f.Name == name {
			return f, true
		}
	}
	return Field{}, false
}

// Record is what a search is held against: a row's values by field, and
// everything the row says, for terms that name no field.
type Record struct {
	Fields map[string][]string
	Text   string
}

type term struct {
	field  string   // "" for a term that may match anywhere in the text
	values []string // in small letters; the row needs to match one
	negate bool
}

// Query is a search that has been read.
type Query struct {
	terms []term
}

// Empty reports whether the search asks for nothing, and so matches every row.
func (q Query) Empty() bool { return len(q.terms) == 0 }

// Parse reads a search. It fails, saying why, for a field that does not
// exist, a value a field does not take, or a quote left open.
func Parse(text string) (Query, error) {
	var q Query
	tokens, err := split(text)
	if err != nil {
		return q, err
	}
	for _, token := range tokens {
		t := term{negate: token.negate}
		name, value, named := strings.Cut(token.text, ":")
		if named && !token.quotedName && letters(name) {
			f, known := field(strings.ToLower(name))
			if !known {
				if len(name) > 1 {
					return q, errors.New("there is no field called " + name + ". The fields are " + names() + ".")
				}
				named = false // a single letter, as in C:\Users, is part of a word
			} else {
				t.field = f.Name
				for _, v := range splitValues(value, token.quotedValue) {
					v = strings.ToLower(v)
					if len(f.Values) > 0 && !contains(f.Values, v) {
						return q, errors.New(f.Name + " takes " + or(f.Values) + ", not " + v + ".")
					}
					t.values = append(t.values, v)
				}
				if len(t.values) == 0 {
					return q, errors.New("say what " + f.Name + " should be, after the colon.")
				}
			}
		}
		if !named || t.field == "" {
			word := strings.ToLower(strings.Trim(token.text, "*"))
			if word == "" {
				continue
			}
			t.values = []string{word}
		}
		q.terms = append(q.terms, t)
	}
	return q, nil
}

// Match reports whether a row matches every term of the search.
func (q Query) Match(r Record) bool {
	text := strings.ToLower(r.Text)
	for _, t := range q.terms {
		if matches(t, r, text) == t.negate {
			return false
		}
	}
	return true
}

func matches(t term, r Record, text string) bool {
	if t.field == "" {
		return strings.Contains(text, t.values[0])
	}
	f, _ := field(t.field)
	for _, have := range r.Fields[t.field] {
		have = strings.ToLower(have)
		for _, want := range t.values {
			switch {
			case strings.ContainsAny(want, "*?"):
				if glob(want, have) {
					return true
				}
			case f.Exact:
				if have == want {
					return true
				}
			case strings.Contains(have, want):
				return true
			}
		}
	}
	return false
}

// glob reports whether text fits a pattern in which * stands for any run
// of characters and ? for any one. Backslashes are plain characters, as
// they are in Windows paths.
func glob(pattern, text string) bool {
	p, s := []rune(pattern), []rune(text)
	star, from := -1, 0
	i, j := 0, 0
	for j < len(s) {
		switch {
		case i < len(p) && (p[i] == '?' || p[i] == s[j]):
			i++
			j++
		case i < len(p) && p[i] == '*':
			star, from = i, j
			i++
		case star >= 0:
			i, from = star+1, from+1
			j = from
		default:
			return false
		}
	}
	for i < len(p) && p[i] == '*' {
		i++
	}
	return i == len(p)
}

type token struct {
	text        string
	negate      bool
	quotedName  bool // a quote opened before the colon
	quotedValue bool // the value was quoted, so commas in it are not dividers
}

// split cuts a search into terms at spaces outside quotes, taking the
// quotes away.
func split(text string) ([]token, error) {
	var out []token
	runes := []rune(text)
	for i := 0; i < len(runes); {
		if runes[i] == ' ' || runes[i] == '\t' {
			i++
			continue
		}
		var t token
		if runes[i] == '-' && i+1 < len(runes) && runes[i+1] != ' ' {
			t.negate = true
			i++
		}
		var b strings.Builder
		quoted, colon := false, false
		for ; i < len(runes); i++ {
			r := runes[i]
			switch {
			case r == '"':
				if !quoted && colon && b.Len() > 0 && strings.HasSuffix(b.String(), ":") {
					t.quotedValue = true
				}
				if !quoted && !colon {
					t.quotedName = true
				}
				quoted = !quoted
				continue
			case (r == ' ' || r == '\t') && !quoted:
			case r == ':' && !quoted:
				colon = true
				b.WriteRune(r)
				continue
			case r == ',' && quoted && colon:
				// A comma inside quotes is kept apart from the dividing commas.
				b.WriteRune('\x00')
				continue
			default:
				b.WriteRune(r)
				continue
			}
			break
		}
		if quoted {
			return nil, errors.New("a quote was opened and not closed.")
		}
		t.text = b.String()
		out = append(out, t)
	}
	return out, nil
}

// splitValues cuts the value of a field at commas, keeping the commas that
// stood inside quotes.
func splitValues(value string, quoted bool) []string {
	var out []string
	for _, v := range strings.Split(value, ",") {
		v = strings.ReplaceAll(v, "\x00", ",")
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func letters(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return false
		}
	}
	return true
}

func contains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

func names() string {
	var all []string
	for _, f := range Fields {
		all = append(all, f.Name)
	}
	sort.Strings(all)
	return strings.Join(all[:len(all)-1], ", ") + " and " + all[len(all)-1]
}

func or(values []string) string {
	if len(values) == 1 {
		return values[0]
	}
	return strings.Join(values[:len(values)-1], ", ") + " or " + values[len(values)-1]
}

// Help says in a few lines how to search, for the window and the
// command-line tool.
func Help() []string {
	lines := []string{
		"Type words to find the rows that mention them. All the words must match.",
		"field:value finds rows whose field holds the value, such as kind:service or signed:no.",
		"* stands for anything, as in path:*\\Users\\*. A comma gives a choice, as in kind:service,driver.",
		"A minus in front leaves out what a term matches, as in -windows:yes. Quotes keep words together.",
		"The fields:",
	}
	for _, f := range Fields {
		line := f.Name + ": " + f.About
		if len(f.Values) > 0 {
			line += " (" + or(f.Values) + ")"
		}
		lines = append(lines, line)
	}
	return lines
}
