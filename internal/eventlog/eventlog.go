// Package eventlog reads Windows' own logs: the record Windows keeps of
// hardware errors, crashes, what its antivirus found and when a setting
// was changed.
//
// It only reads, and only what Windows already wrote. Nothing is looked up
// anywhere else.
package eventlog

import (
	"encoding/xml"
	"errors"
	"strconv"
	"strings"
	"time"
)

// Event is one record from a Windows log.
type Event struct {
	Time     time.Time
	Provider string // the part of Windows that wrote it, such as Microsoft-Windows-WHEA-Logger
	ID       int
	Level    int               // 1 critical, 2 error, 3 warning, 4 information
	Data     map[string]string // the record's named values
	Loose    []string          // its values that have no name, in order
	Message  string            // the record put into Windows' own words, when Windows can say them
}

// The levels Windows gives its records.
const (
	Critical = 1
	Error    = 2
	Warning  = 3
)

// Value returns a named value of the record, or "".
func (e Event) Value(name string) string { return strings.TrimSpace(e.Data[name]) }

// Number reads a named value as a whole number, written in tens or, with
// 0x in front, in sixteens.
func (e Event) Number(name string) (uint64, bool) {
	text := strings.TrimSpace(e.Data[name])
	if text == "" {
		return 0, false
	}
	base := 10
	if len(text) > 2 && (text[:2] == "0x" || text[:2] == "0X") {
		text, base = text[2:], 16
	}
	n, err := strconv.ParseUint(text, base, 64)
	return n, err == nil
}

// Parse reads one record in the form Windows hands it over: a small XML
// document with a System part that says what the record is and a part of
// its own values.
func Parse(document string) (Event, error) {
	event := Event{Data: map[string]string{}}
	decoder := xml.NewDecoder(strings.NewReader(document))
	var path []string  // the elements now open, outermost first
	var name string    // the Name of the Data element now open
	var text []byte    // the text of the element now open
	var children []int // how many elements each open element has had inside it
	seen := false
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := token.(type) {
		case xml.StartElement:
			if len(children) > 0 {
				children[len(children)-1]++
			}
			path, children, text, name = append(path, t.Name.Local), append(children, 0), text[:0], ""
			for _, attribute := range t.Attr {
				switch {
				case t.Name.Local == "Provider" && attribute.Name.Local == "Name" && inside(path, "System"):
					event.Provider = attribute.Value
				case t.Name.Local == "TimeCreated" && attribute.Name.Local == "SystemTime":
					if when, err := time.Parse(time.RFC3339Nano, attribute.Value); err == nil {
						event.Time = when
					}
				case t.Name.Local == "Data" && attribute.Name.Local == "Name":
					name = attribute.Value
				}
			}
			if t.Name.Local == "Event" {
				seen = true
			}
		case xml.CharData:
			text = append(text, t...)
		case xml.EndElement:
			value := strings.TrimSpace(string(text))
			leaf := len(children) > 0 && children[len(children)-1] == 0
			switch {
			case len(path) == 0:
			case inside(path, "System"):
				switch t.Name.Local {
				case "EventID":
					event.ID, _ = strconv.Atoi(value)
				case "Level":
					event.Level, _ = strconv.Atoi(value)
				}
			case t.Name.Local == "Data" && inside(path, "EventData"):
				if name != "" {
					event.Data[name] = value
				} else if value != "" {
					event.Loose = append(event.Loose, value)
				}
			case leaf && inside(path, "UserData") && value != "":
				// Records of this kind name each value by its own element.
				event.Data[t.Name.Local] = value
			}
			if len(path) > 0 {
				path, children = path[:len(path)-1], children[:len(children)-1]
			}
			text, name = text[:0], ""
		}
	}
	if !seen {
		return Event{}, errors.New("not a record from a Windows log")
	}
	return event, nil
}

// inside reports whether one of the open elements, other than the innermost,
// has the given name.
func inside(path []string, name string) bool {
	for i := 0; i < len(path)-1; i++ {
		if path[i] == name {
			return true
		}
	}
	return false
}

// Since is the piece of a question to a log that keeps only what was
// written in the last so many days.
func Since(days int) string {
	return "TimeCreated[timediff(@SystemTime) <= " + strconv.FormatInt(int64(days)*24*60*60*1000, 10) + "]"
}

// From is the piece of a question that keeps the records of one writer.
func From(provider string) string { return "Provider[@Name='" + provider + "']" }

// Numbered is the piece of a question that keeps records with one of the
// given numbers.
func Numbered(ids ...int) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = "EventID=" + strconv.Itoa(id)
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return "(" + strings.Join(parts, " or ") + ")"
}

// Where puts pieces together into a whole question.
func Where(pieces ...string) string {
	return "*[System[" + strings.Join(pieces, " and ") + "]]"
}
