// Package report writes a look at a PC as one file to keep or to send to
// someone who is helping: a web page to read, plain text to paste, or data
// for another tool.
//
// The web page is whole in itself. It has no scripts and loads nothing
// from anywhere, so opening it tells nobody anything. It wears the colours
// of LazaScope's own window, and keeps the long lists closed until they are
// opened.
package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"strings"

	"lazascope/internal/model"
	"lazascope/internal/rules"
	"lazascope/internal/view"
	"lazascope/internal/winpath"
)

// Fits reports whether a file name ends in one of the forms a report can
// take. Any other ending is refused, so that a report never lands in a file
// that will not open.
func Fits(name string) error {
	switch winpath.Ext(name) {
	case ".html", ".htm", ".txt", ".json":
		return nil
	}
	return errors.New("the name of the report must end in .html, .txt or .json")
}

// Render writes the report in the form a file name asks for: a web page for
// .html, plain text for .txt and data for .json.
func Render(b *view.Book, version, name string) ([]byte, error) {
	if err := Fits(name); err != nil {
		return nil, err
	}
	switch winpath.Ext(name) {
	case ".txt":
		return []byte(Text(b, version)), nil
	case ".json":
		return JSON(b, version), nil
	}
	return HTML(b, version), nil
}

// Careful is the warning every report carries: it is full of details that
// belong to the PC's owner.
const Careful = "This report names this PC, the account in use, the programs it runs and the addresses they talk to. Read it before you send it to anyone."

// Limits says what the report must not be taken for.
const Limits = "LazaScope is not an antivirus. It reads what Windows reports and removes nothing. \"Worth a look\" means unusual, not harmful, and a clean report is not proof that nothing is wrong: software that hides inside the core of Windows can hide from this too."

// tagline is the line under the name, as in the window.
const tagline = "What starts. What runs. What is worth a second look."

// style dresses the web page in the colours of the window (see theme.go in
// internal/winui): a dark sheet with a thin light rim, Segoe UI, round lights,
// and colour only where it means something. Printed, it turns light, as
// paper needs.
const style = `
:root{color-scheme:dark;--page:#070707;--sheet:#121212;--edge:rgba(255,255,255,.16);--ink:#f3f3f3;--soft:#c2c2c2;--quiet:#a9a9a9;
--panel:rgba(0,0,0,.25);--panel-edge:rgba(255,255,255,.1);--rule:rgba(255,255,255,.1);--rule-faint:rgba(255,255,255,.05);
--well:rgba(0,0,0,.32);--hover:rgba(255,255,255,.05);--chosen:rgba(255,255,255,.1);
--good:#5fcb80;--warn:#f2b33d;--bad:#ff5449;--ring:rgba(255,255,255,.44);--red:#ff8f85;--amber:#f2b33d;--green:#6fd08c;--grey:#b8b8b8;
--mono:"Cascadia Mono",Consolas,monospace}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--page);color:var(--ink);font:15px/1.5 "Segoe UI",system-ui,sans-serif}
main{max-width:1060px;margin:24px auto;padding:28px 32px 18px;background:var(--sheet);border:1px solid var(--edge);border-radius:8px}
h1,h2,h3,h4{margin:0;line-height:1.3}
h1{font-size:26px}
h2{font-size:19px;margin:36px 0 4px}
h3{font-size:16px}
p{margin:6px 0}
ul{margin:6px 0;padding-left:20px}
.tagline{margin:2px 0 0;color:var(--quiet);font-size:14px}
.soft{color:var(--soft)}
.quiet{color:var(--quiet);font-size:13px}
.first{color:var(--red)}.look{color:var(--amber)}.fine{color:var(--green)}.info{color:var(--grey)}
.glance{list-style:none;margin:12px 0 0;padding:8px 18px;background:var(--panel);border:1px solid var(--panel-edge);border-radius:8px}
.glance li{display:grid;grid-template-columns:14px 230px minmax(0,1fr);column-gap:14px;align-items:baseline;padding:7px 0}
.glance .facts{grid-column:2/4;color:var(--soft);font-size:13px}
.lamp{width:12px;height:12px;border-radius:50%;align-self:center;-webkit-print-color-adjust:exact;print-color-adjust:exact}
.lamp.red{background:var(--bad)}.lamp.amber{background:var(--warn)}.lamp.green{background:var(--good)}.lamp.grey{border:2px solid var(--ring)}
.item{padding:16px 0 12px;border-top:1px solid var(--rule)}
.item h3{display:flex;flex-wrap:wrap;justify-content:space-between;gap:2px 16px;overflow-wrap:anywhere}
.where{font-size:13px;font-weight:400;color:var(--quiet)}
.finding{display:grid;grid-template-columns:112px minmax(0,1fr);column-gap:16px;margin:10px 0 0}
.finding .check{margin:0;font-size:14px;font-weight:600}
.finding .title{margin:0;font-weight:600}
.finding p{overflow-wrap:anywhere}
.label{color:var(--soft)}
details.more{margin:10px 0 0 128px}
details.more>summary{width:max-content;color:var(--soft);cursor:pointer}
details.more>summary::marker{color:var(--quiet)}
dl{display:grid;grid-template-columns:minmax(120px,220px) minmax(0,1fr);gap:3px 14px;margin:8px 0;font-size:13.5px}
dt{color:var(--soft)}
dd{margin:0;overflow-wrap:anywhere}
.rule{margin:3px 0;color:var(--quiet);font-size:13px}
details.section{border-top:1px solid var(--rule)}
details.section:last-of-type{border-bottom:1px solid var(--rule)}
details.section>summary{padding:10px 2px;cursor:pointer}
details.section>summary::marker{color:var(--quiet)}
.num{margin-right:6px;color:var(--quiet);font-variant-numeric:tabular-nums}
.intro{margin:0 0 10px;color:var(--soft);font-size:14px}
.list{margin:0 0 16px;font-size:13.5px;background:var(--panel);border:1px solid var(--panel-edge);border-radius:8px}
.head,.list summary{display:grid;grid-template-columns:var(--columns);gap:10px;padding:6px 14px}
.head{color:var(--soft);font-weight:600;border-bottom:1px solid var(--rule)}
.list details+details{border-top:1px solid var(--rule-faint)}
.list summary{cursor:pointer;list-style:none}
.list summary::-webkit-details-marker{display:none}
.list summary:hover{background:var(--hover)}
.list details[open]>summary{background:var(--chosen)}
.list summary span{overflow-wrap:anywhere;white-space:pre-wrap}
.detail{padding:8px 14px 12px;border-top:1px solid var(--rule-faint)}
.detail h4{font-size:13.5px;margin:10px 0 2px}
.detail p{margin:3px 0}
.detail .aside{color:var(--quiet);font-size:12.5px}
code{display:block;margin:4px 0;padding:4px 8px;font:12.5px/1.45 var(--mono);background:var(--well);border:1px solid var(--panel-edge);border-radius:6px;overflow-wrap:anywhere;white-space:pre-wrap}
footer{margin-top:36px;padding-top:12px;border-top:1px solid var(--rule);color:var(--quiet);font-size:13px}
footer p{margin:4px 0}
summary:focus-visible{outline:2px solid #fff;outline-offset:2px}
@media (max-width:760px){main{margin:0;padding:20px 16px;border:0;border-radius:0}.glance li{grid-template-columns:14px minmax(0,1fr)}.glance .verdict,.glance .facts{grid-column:2}
.finding{grid-template-columns:minmax(0,1fr)}details.more{margin-left:0}dl{grid-template-columns:minmax(0,1fr)}dd{margin-bottom:6px}.list{overflow-x:auto}.head,.list summary{min-width:720px}}
@media print{:root{color-scheme:light;--page:#fff;--sheet:#fff;--edge:#fff;--ink:#111;--soft:#444;--quiet:#555;--panel:#fff;--panel-edge:#bbb;--rule:#ccc;--rule-faint:#e6e6e6;
--well:#f3f3f3;--hover:transparent;--chosen:#f3f3f3;--red:#b3261e;--amber:#8a5a00;--green:#1e7a3e;--grey:#555;--bad:#d43b30;--warn:#e0a11b;--good:#2e9d57;--ring:#888}
main{max-width:none;margin:0;padding:0;border:0}.glance,.finding{break-inside:avoid}}
`

// class names the level of a row or a finding for the style sheet: the
// colour of its first word, as in the window's lists.
func class(level view.Level) string {
	switch level {
	case view.First:
		return "first"
	case view.Look:
		return "look"
	case view.Fine:
		return "fine"
	case view.Info, view.Unknown:
		return "info"
	}
	return ""
}

func severity(s rules.Severity) view.Level {
	switch s {
	case rules.High:
		return view.First
	case rules.Medium:
		return view.Look
	}
	return view.Info
}

func lamp(light rules.Light) string {
	switch light {
	case rules.Green:
		return "green"
	case rules.Amber:
		return "amber"
	case rules.Red:
		return "red"
	}
	return "grey"
}

// tone is the colour of a light's words, as on the window's overview.
func tone(light rules.Light) string {
	switch light {
	case rules.Green:
		return "fine"
	case rules.Amber:
		return "look"
	case rules.Red:
		return "first"
	}
	return "info"
}

// title names the report by its PC and its day.
func title(b *view.Book) string {
	return strings.TrimSpace("LazaScope report: " + b.Snapshot.Computer + ", " + b.Snapshot.Taken.Format("2 January 2006"))
}

// lists returns the six lists a report carries, in the order of the window's
// section buttons, each with its number there: 02 Protection to 07 Health.
func lists(b *view.Book) []*view.Page {
	return b.Pages()[:model.Areas]
}

// tab names the list of an area as the window's section button does, such
// as "03 Start-up". Advice that sends the reader to "03 Start-up" finds it
// under that name in the report too.
func tab(b *view.Book, area model.Area) string {
	if area < model.Protection || area >= model.Areas {
		return area.String()
	}
	return fmt.Sprintf("%02d %s", int(area)+2, lists(b)[area].Name)
}

// item is one thing the findings are about, such as a start-up entry or a
// setting, with every finding about it, the most serious first.
type item struct {
	subject  string
	area     model.Area
	findings []rules.Finding
}

// items gathers the findings by what they are about. The findings come
// most serious first, and each item keeps the place of its most serious
// finding, so the order of the whole stays the same.
func items(findings []rules.Finding) []item {
	var list []item
	at := map[string]int{}
	for _, f := range findings {
		key := f.Ref
		if key == "" {
			key = f.Area.String() + "\x00" + f.Subject
		}
		i, ok := at[key]
		if !ok {
			i = len(list)
			at[key] = i
			list = append(list, item{subject: f.Subject, area: f.Area})
		}
		list[i].findings = append(list[i].findings, f)
	}
	return list
}

// evidence is what is known about an item, from all its findings, with the
// fingerprint of each file after the file. A fact that an earlier finding
// about the item already gave is not given again. Within one finding every
// fact stays: two hardware errors in the same minute are two errors.
func (it item) evidence(s *model.Snapshot) []rules.Fact {
	var out []rules.Fact
	given := map[rules.Fact]bool{}
	for _, f := range it.findings {
		var these []rules.Fact
		for _, fact := range withPrints(s, f.Facts) {
			if !given[fact] {
				these = append(these, fact)
			}
		}
		for _, fact := range these {
			given[fact] = true
		}
		out = append(out, these...)
	}
	return out
}

// tally says how many findings there are and about how many things.
func tally(findings, things int) string {
	n := count(findings, "finding", "findings")
	if things != findings {
		n += " about " + count(things, "thing", "things")
	}
	return n + "."
}

// sentences splits a paragraph after each full stop, question mark or
// exclamation mark that a space and a capital letter follow. "Look up
// file... to read" stays whole.
func sentences(text string) []string {
	var out []string
	start := 0
	for i := 0; i+2 < len(text); i++ {
		if (text[i] == '.' || text[i] == '?' || text[i] == '!') && text[i+1] == ' ' && text[i+2] >= 'A' && text[i+2] <= 'Z' {
			out = append(out, text[start:i+1])
			start = i + 2
		}
	}
	return append(out, text[start:])
}

// leans reports whether a sentence leans on the one before it, so that the
// two must be kept or left out together.
func leans(sentence string) bool {
	for _, word := range []string{"That ", "This ", "It ", "Then ", "They "} {
		if strings.HasPrefix(sentence, word) {
			return true
		}
	}
	return false
}

// fresh returns the sentences of a piece of advice that an earlier finding
// about the same item has not already given, and notes them as given. Most
// rules end their advice with how to switch the thing off, and an item
// flagged three times needs to read that once.
func fresh(advice string, given map[string]bool) string {
	parts := sentences(strings.TrimSpace(advice))
	drop := make([]bool, len(parts))
	for i, part := range parts {
		drop[i] = given[part]
	}
	for i := len(parts) - 1; i > 0; i-- {
		if !drop[i] && leans(parts[i]) {
			drop[i-1] = false
		}
	}
	var kept []string
	for i, part := range parts {
		given[part] = true
		if !drop[i] && part != "" {
			kept = append(kept, part)
		}
	}
	return strings.Join(kept, " ")
}

// ruleLine names the rule behind a finding and the ATT&CK techniques it is
// a trace of.
func ruleLine(f rules.Finding) string {
	line := "Rule: " + f.Rule
	if attack := rules.Attack(f.Attack); attack != "" {
		line += ". MITRE ATT&CK " + rules.AttackVersion + ": " + attack
	}
	return line
}

// HTML writes the report as one web page that needs nothing else: the
// overview's lights, what is worth a look, and then every list, closed.
func HTML(b *view.Book, version string) []byte {
	var w strings.Builder
	e := html.EscapeString
	fmt.Fprintf(&w, "<!doctype html>\n<html lang=\"en-GB\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>%s</title>\n<style>%s</style>\n</head>\n<body>\n<main>\n", e(title(b)), style)
	fmt.Fprintf(&w, "<header>\n<h1>LazaScope</h1>\n<p class=\"tagline\">%s</p>\n</header>\n", e(tagline))

	fmt.Fprintf(&w, "<h2>This PC at a glance</h2>\n<p class=\"soft\">%s</p>\n", e(b.Summary))
	if b.Compared != "" {
		// What a comparison or a watch showed.
		fmt.Fprintf(&w, "<p class=\"soft\">%s</p>\n", e(b.Compared))
		if len(b.Changes) > 0 {
			w.WriteString("<details class=\"more\"><summary>What has changed or gone</summary>\n<ul>\n")
			for _, change := range b.Changes {
				fmt.Fprintf(&w, "<li>%s</li>\n", e(change))
			}
			w.WriteString("</ul>\n</details>\n")
		}
	}
	fmt.Fprintf(&w, "<p class=\"quiet\">%s</p>\n<ul class=\"glance\">\n", e(Careful))
	for _, glance := range b.Glances {
		fmt.Fprintf(&w, "<li><span class=\"lamp %s\"></span><b>%s</b><span class=\"verdict %s\">%s</span><span class=\"facts\">%s</span></li>\n",
			lamp(glance.Light), e(glance.Area.String()), tone(glance.Light), e(glance.Verdict), e(glance.Facts))
	}
	w.WriteString("</ul>\n")

	fmt.Fprintf(&w, "<h2>%s (%d)</h2>\n<p class=\"soft\">%s</p>\n", e(b.Worth.Title), len(b.Findings), e(b.Worth.Intro))
	if len(b.Findings) == 0 {
		w.WriteString("<p>Nothing on this PC stood out to the rules. That is not a promise that nothing is wrong: LazaScope only knows the signs it was taught.</p>\n")
	} else {
		all := items(b.Findings)
		fmt.Fprintf(&w, "<p class=\"quiet\">%s</p>\n", e(tally(len(b.Findings), len(all))))
		for _, it := range all {
			fmt.Fprintf(&w, "<article class=\"item\">\n<h3>%s<span class=\"where\">%s</span></h3>\n", e(it.subject), e(tab(b, it.area)))
			given := map[string]bool{}
			for _, f := range it.findings {
				level := class(severity(f.Severity))
				fmt.Fprintf(&w, "<div class=\"finding\">\n<p class=\"check %s\">%s</p>\n<div>\n<p class=\"title\">%s</p>\n<p>%s</p>\n", level, e(f.Severity.String()), e(f.Title), e(f.Reason))
				if advice := fresh(f.Advice, given); advice != "" {
					fmt.Fprintf(&w, "<p><span class=\"label\">What you can do:</span> %s</p>\n", e(advice))
				}
				w.WriteString("</div>\n</div>\n")
			}
			w.WriteString("<details class=\"more\"><summary>Details</summary>\n")
			if facts := it.evidence(b.Snapshot); len(facts) > 0 {
				w.WriteString("<dl>")
				for _, fact := range facts {
					fmt.Fprintf(&w, "<dt>%s</dt><dd>%s</dd>", e(fact.Label), e(fact.Value))
				}
				w.WriteString("</dl>\n")
			}
			for _, f := range it.findings {
				fmt.Fprintf(&w, "<p class=\"rule\">%s</p>\n", e(ruleLine(f)))
			}
			w.WriteString("</details>\n</article>\n")
		}
	}
	if len(b.Worth.Unseen) > 0 {
		w.WriteString("<h2>What could not be read</h2>\n<ul>\n")
		for _, note := range b.Worth.Unseen {
			fmt.Fprintf(&w, "<li>%s</li>\n", e(note))
		}
		w.WriteString("</ul>\n")
	}

	w.WriteString("<h2>Everything LazaScope read</h2>\n<p class=\"soft\">Every list, whether or not a rule flagged anything in it, under the names of the window's sections. Open a list to see its rows, and a row to see what is known about it.</p>\n")
	for i, page := range lists(b) {
		fmt.Fprintf(&w, "<details class=\"section\" id=\"%s\"><summary><span class=\"num\">%02d</span><b>%s</b> (%d) <span class=\"soft\">%s</span></summary>\n<p class=\"intro\">%s</p>\n",
			e(strings.ToLower(page.Name)), i+2, e(page.Name), len(page.Rows), e(page.Title), e(page.Intro))
		if len(page.Rows) == 0 {
			w.WriteString("<p class=\"quiet\">Nothing to list.</p>\n</details>\n")
			continue
		}
		fmt.Fprintf(&w, "<div class=\"list\" style=\"--columns:%s\">\n<div class=\"head\">", columns(page.Columns))
		for _, column := range page.Columns {
			fmt.Fprintf(&w, "<span>%s</span>", e(column.Title))
		}
		w.WriteString("</div>\n")
		for _, row := range page.Rows {
			w.WriteString("<details><summary>")
			for i, cell := range row.Cells {
				tint := ""
				if i == 0 {
					tint = class(row.Level)
					if tint == "" && row.Off {
						tint = "info"
					}
				}
				if tint != "" {
					fmt.Fprintf(&w, "<span class=\"%s\">%s</span>", tint, e(cell))
				} else {
					fmt.Fprintf(&w, "<span>%s</span>", e(cell))
				}
			}
			w.WriteString("</summary><div class=\"detail\">")
			excerpted := false
			for _, line := range row.Detail {
				switch line.Style {
				case view.Excerpt:
					// Lines copied out of a file may hold a password or a key.
					// The report is made to be sent, so they stay out of it.
					if !excerpted {
						w.WriteString("<p class=\"aside\">LazaScope's own window shows lines copied from the script or command here. They are left out of this report, in case they hold a password.</p>")
						excerpted = true
					}
				case view.Link:
					// The web page holds no addresses, so that it can neither fetch
					// nor lead anywhere. The fingerprint beside it is enough to look
					// the file up.
				case view.Heading:
					fmt.Fprintf(&w, "<h4>%s</h4>", e(line.Text))
				case view.Command:
					fmt.Fprintf(&w, "<code>%s</code>", e(line.Text))
				case view.Aside:
					fmt.Fprintf(&w, "<p class=\"aside\">%s</p>", e(line.Text))
				default:
					fmt.Fprintf(&w, "<p>%s</p>", e(line.Text))
				}
			}
			w.WriteString("</div></details>\n")
		}
		w.WriteString("</div>\n</details>\n")
	}
	fmt.Fprintf(&w, "<footer>\n<p>%s</p>\n<p>Made by LazaScope %s on %s. This page holds no scripts and loads nothing from the internet.</p>\n</footer>\n</main>\n</body>\n</html>\n",
		e(Limits), e(version), e(b.Snapshot.Taken.Format("2 January 2006 at 15:04")))
	return []byte(w.String())
}

// columns turns the widths of a page's columns into shares of the width of
// the web page. The last column of a page takes what the others leave.
func columns(list []view.Column) string {
	const whole = 976 // the width the window lays its lists out in
	used := 0
	for _, column := range list {
		used += column.Width
	}
	var shares []string
	for _, column := range list {
		width := column.Width
		if width == 0 {
			width = max(whole-used, 120)
		}
		shares = append(shares, fmt.Sprintf("minmax(0,%dfr)", width))
	}
	return strings.Join(shares, " ")
}

func count(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

const rule = "------------------------------------------------------------------------"

// Text writes the report as plain text, for pasting where a web page
// cannot go. It follows the web page: the lights, what is worth a look, then
// every list.
func Text(b *view.Book, version string) string {
	var w strings.Builder
	line := func(format string, values ...any) { fmt.Fprintf(&w, format+"\r\n", values...) }
	heading := func(title string) {
		line("")
		line("%s", strings.ToUpper(title))
		line(rule)
	}
	line("LazaScope report")
	line("Made by LazaScope %s on %s", version, b.Snapshot.Taken.Format("2 January 2006 at 15:04"))
	line(rule)
	line("")
	line("%s", b.Summary)
	if b.Compared != "" {
		line("%s", b.Compared)
		for _, change := range b.Changes {
			line("  %s", change)
		}
	}
	line("%s", Careful)

	heading("At a glance")
	for _, glance := range b.Glances {
		line("%-28s %s", glance.Area.String(), glance.Verdict)
		if glance.Facts != "" {
			line("%-28s %s", "", glance.Facts)
		}
	}

	heading(fmt.Sprintf("Worth a look (%d)", len(b.Findings)))
	if len(b.Findings) == 0 {
		line("Nothing on this PC stood out to the rules.")
	} else {
		all := items(b.Findings)
		line("%s", tally(len(b.Findings), len(all)))
		for _, it := range all {
			line("")
			line("%s, under %s", it.subject, tab(b, it.area))
			given := map[string]bool{}
			for _, f := range it.findings {
				line("  [%s] %s", f.Severity, f.Title)
				line("      Why: %s", f.Reason)
				if advice := fresh(f.Advice, given); advice != "" {
					line("      What you can do: %s", advice)
				}
			}
			line("  Details:")
			for _, fact := range it.evidence(b.Snapshot) {
				line("      %s: %s", fact.Label, fact.Value)
			}
			for _, f := range it.findings {
				line("      %s", ruleLine(f))
			}
		}
	}
	if len(b.Worth.Unseen) > 0 {
		heading("What could not be read")
		for _, note := range b.Worth.Unseen {
			line("%s", note)
		}
	}
	for i, page := range lists(b) {
		heading(fmt.Sprintf("%02d %s: %s (%d)", i+2, page.Name, page.Title, len(page.Rows)))
		if len(page.Rows) == 0 {
			line("Nothing to list.")
			continue
		}
		var titles []string
		for _, column := range page.Columns {
			titles = append(titles, column.Title)
		}
		line("%s", strings.Join(titles, " | "))
		for _, row := range page.Rows {
			// An empty cell would leave the line ending in nothing, and a
			// reader wondering whether something was cut off.
			cells := append([]string{}, row.Cells...)
			for i, cell := range cells {
				if strings.TrimSpace(cell) == "" {
					cells[i] = "-"
				}
			}
			line("%s", strings.Join(cells, " | "))
		}
	}
	line("")
	line(rule)
	line("%s", Limits)
	return w.String()
}

type jsonFinding struct {
	Rule     string            `json:"rule"`
	Severity string            `json:"severity"`
	Area     string            `json:"area"`
	Title    string            `json:"title"`
	Subject  string            `json:"subject"`
	Reason   string            `json:"reason"`
	Advice   string            `json:"advice"`
	Ref      string            `json:"ref"`              // which fact it is about
	Attack   []jsonTechnique   `json:"attack,omitempty"` // the MITRE ATT&CK techniques it is a trace of
	Evidence map[string]string `json:"evidence,omitempty"`
}

type jsonTechnique struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type jsonLight struct {
	Area    string `json:"area"`
	Light   string `json:"light"`
	Verdict string `json:"verdict"`
	Facts   string `json:"facts"`
}

// JSON writes the report as data for other tools to read: the lights, the
// findings, and every fact that was read.
//
// A finding's ref says which fact it is about. "startup:12" and
// "process:4321" are the ref of one start-up entry or running program.
// "file:" and "listen:" followed by a path in small letters stand for every
// running copy of that program and for the ports it waits on. A plain word
// such as "firewall" names a setting under protection.
func JSON(b *view.Book, version string) []byte {
	s := b.Snapshot
	type jsonComparison struct {
		With    string   `json:"with"`
		When    string   `json:"when"`
		Watched bool     `json:"watched"`
		Summary string   `json:"summary"`
		Changes []string `json:"changedOrGone"`
	}
	var comparison *jsonComparison
	if c := s.Compared; c != nil {
		comparison = &jsonComparison{c.With, stamp(c.When), c.Watched, b.Compared, append([]string{}, b.Changes...)}
	}
	document := struct {
		Tool          string          `json:"tool"`
		Generated     string          `json:"generated"`
		AttackVersion string          `json:"attackVersion"` // the version of MITRE ATT&CK the technique numbers are from
		TookMillis    int64           `json:"tookMilliseconds"`
		Computer      string          `json:"computer"`
		User          string          `json:"user"`
		Windows       string          `json:"windows"`
		Administrator bool            `json:"administratorRights"`
		Summary       string          `json:"summary"`
		Lights        []jsonLight     `json:"lights"`
		Findings      []jsonFinding   `json:"findings"`
		CouldNotRead  []string        `json:"couldNotRead"`
		Comparison    *jsonComparison `json:"comparison,omitempty"`
		Facts         jsonFacts       `json:"facts"`
	}{
		Tool: "LazaScope " + version, AttackVersion: rules.AttackVersion, Generated: stamp(s.Taken), TookMillis: s.Took.Milliseconds(),
		Computer: s.Computer, User: s.User, Windows: s.Windows, Administrator: s.Elevated, Summary: b.Summary,
		Lights: []jsonLight{}, Findings: []jsonFinding{}, CouldNotRead: append([]string{}, b.Worth.Unseen...), Comparison: comparison, Facts: facts(s),
	}
	for _, glance := range b.Glances {
		document.Lights = append(document.Lights, jsonLight{glance.Area.String(), lamp(glance.Light), glance.Verdict, glance.Facts})
	}
	for _, f := range b.Findings {
		finding := jsonFinding{Rule: f.Rule, Severity: strings.ToLower(f.Severity.String()), Area: f.Area.String(), Title: f.Title, Subject: f.Subject, Reason: f.Reason, Advice: f.Advice, Ref: f.Ref, Evidence: map[string]string{}}
		for _, technique := range rules.Techniques(f.Attack) {
			finding.Attack = append(finding.Attack, jsonTechnique{technique.ID, technique.Name})
		}
		for _, fact := range withPrints(b.Snapshot, f.Facts) {
			if have, ok := finding.Evidence[fact.Label]; ok {
				finding.Evidence[fact.Label] = have + "; " + fact.Value
			} else {
				finding.Evidence[fact.Label] = fact.Value
			}
		}
		document.Findings = append(document.Findings, finding)
	}
	// Written as people type it: an apostrophe or a > as itself, not as an
	// escape code. The data is never put into a web page as it is.
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(document); err != nil {
		return nil
	}
	return out.Bytes()
}

// printLabel is the label under which a file's fingerprint is given.
const printLabel = "Fingerprint of that file (SHA-256)"

// withPrints returns a finding's facts with the fingerprint of each file
// set after the file, where the look worked one out.
func withPrints(s *model.Snapshot, facts []rules.Fact) []rules.Fact {
	out := make([]rules.Fact, 0, len(facts)+1)
	for _, fact := range facts {
		out = append(out, fact)
		if fact.Label == "File" || fact.Label == "Started through" {
			if print := s.Fingerprint(fact.Value); print != "" {
				out = append(out, rules.Fact{Label: printLabel, Value: print})
			}
		}
	}
	return out
}
