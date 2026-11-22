// Package report writes a look at a PC as one file to keep or to send to
// someone who is helping: a web page to read, plain text to paste, or data
// for another tool.
//
// The web page is whole in itself. It has no scripts and loads nothing
// from anywhere, so opening it tells nobody anything.
package report

import (
	"encoding/json"
	"fmt"
	"html"
	"strings"

	"lazascope/internal/rules"
	"lazascope/internal/view"
)

// Careful is the warning every report carries: it is full of details that
// belong to the PC's owner.
const Careful = "This report names this PC, the account in use, the programs it runs and the addresses they talk to. Read it before you send it to anyone."

// Limits says what the report must not be taken for.
const Limits = "LazaScope is not an antivirus. It reads what Windows reports and removes nothing. \"Worth a look\" means unusual, not harmful, and a clean report is not proof that nothing is wrong: software that hides inside the core of Windows can hide from this too."

const style = `
:root{color-scheme:light}
*{box-sizing:border-box}
body{margin:0;background:#f4f4f2;color:#1b1b1b;font:15px/1.5 "Segoe UI",system-ui,sans-serif}
main{max-width:1080px;margin:0 auto;padding:32px 24px 64px}
h1{font-size:30px;margin:0 0 4px}
h2{font-size:21px;margin:44px 0 6px}
h2.part{margin-top:56px;padding-top:20px;border-top:2px solid #1b1b1b}
h3{font-size:16px;margin:0 0 6px}
p{margin:6px 0}
.quiet{color:#5c5c5c}
.careful{background:#fff6d6;border:1px solid #e3c85a;border-radius:8px;padding:10px 14px;margin:16px 0}
.lights{list-style:none;margin:12px 0;padding:0;background:#fff;border:1px solid #dcdcd8;border-radius:10px}
.lights li{display:grid;grid-template-columns:22px 230px 1fr;gap:4px 12px;padding:10px 14px;border-top:1px solid #ecece8;align-items:center}
.lights li:first-child{border-top:0}
.lights .facts{grid-column:2/4;color:#5c5c5c;font-size:14px}
.lamp{width:14px;height:14px;border-radius:50%;border:2px solid #9a9a9a}
.green .lamp{background:#2e9d57;border-color:#2e9d57}
.amber .lamp{background:#e0a11b;border-color:#e0a11b}
.red .lamp{background:#d43b30;border-color:#d43b30}
.finding{background:#fff;border:1px solid #dcdcd8;border-left:6px solid #9a9a9a;border-radius:8px;padding:14px 16px;margin:12px 0}
.finding.first{border-left-color:#d43b30}
.finding.look{border-left-color:#e0a11b}
.tag{display:inline-block;font-size:12px;font-weight:600;border-radius:4px;padding:1px 7px;margin-right:6px;background:#e4e4e0;vertical-align:1px}
.first .tag,.tag.first{background:#f9d6d2;color:#8c1d15}
.look .tag,.tag.look{background:#fbe7b6;color:#6e4b00}
.fine .tag,.tag.fine{background:#d5efdd;color:#17592f}
dl{display:grid;grid-template-columns:170px 1fr;gap:2px 12px;margin:10px 0 0;font-size:14px}
dt{color:#5c5c5c}
dd{margin:0;overflow-wrap:anywhere}
.list{background:#fff;border:1px solid #dcdcd8;border-radius:10px;margin:12px 0;font-size:14px}
.head,.list summary{display:grid;grid-template-columns:var(--columns);gap:10px;padding:6px 14px}
.head{font-weight:600;color:#5c5c5c;border-bottom:1px solid #dcdcd8}
.list details{border-top:1px solid #f0f0ec}
.list details:first-of-type{border-top:0}
.list summary{cursor:pointer;list-style:none}
.list summary::-webkit-details-marker{display:none}
.list summary:hover,.list details[open] summary{background:#f6f6f3}
.list summary span{overflow-wrap:anywhere;white-space:pre-wrap}
.detail{padding:6px 14px 14px 14px;border-top:1px dashed #e4e4e0;background:#fcfcfa}
.detail h4{font-size:14px;margin:10px 0 2px}
.detail p{margin:3px 0}
.detail .aside{color:#5c5c5c;font-size:13px}
code{font:13px/1.45 Consolas,"Cascadia Mono",monospace;background:#f0f0ec;border-radius:4px;padding:2px 6px;display:block;overflow-wrap:anywhere;white-space:pre-wrap}
footer{margin-top:56px;padding-top:16px;border-top:1px solid #dcdcd8;color:#5c5c5c;font-size:14px}
@media print{body{background:#fff}main{padding:0}.list summary:hover{background:none}.finding,.list,.lights{break-inside:avoid-page}}
`

// class names the level of a row or a finding for the style sheet.
func class(level view.Level) string {
	switch level {
	case view.First:
		return "first"
	case view.Look:
		return "look"
	case view.Fine:
		return "fine"
	}
	return "plain"
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

// title names the report by its PC and its day.
func title(b *view.Book) string {
	return strings.TrimSpace("LazaScope report: " + b.Snapshot.Computer + ", " + b.Snapshot.Taken.Format("2 January 2006"))
}

// HTML writes the report as one web page that needs nothing else.
func HTML(b *view.Book, version string) []byte {
	var w strings.Builder
	e := html.EscapeString
	fmt.Fprintf(&w, "<!doctype html>\n<html lang=\"en-GB\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>%s</title>\n<style>%s</style>\n</head>\n<body>\n<main>\n", e(title(b)), style)
	fmt.Fprintf(&w, "<h1>LazaScope report</h1>\n<p>%s</p>\n<p class=\"careful\">%s</p>\n", e(b.Summary), e(Careful))

	w.WriteString("<h2>At a glance</h2>\n<ul class=\"lights\">\n")
	for _, glance := range b.Glances {
		fmt.Fprintf(&w, "<li class=\"%s\"><span class=\"lamp\"></span><b>%s</b><span>%s</span><span class=\"facts\">%s</span></li>\n", lamp(glance.Light), e(glance.Area.String()), e(glance.Verdict), e(glance.Facts))
	}
	w.WriteString("</ul>\n")

	fmt.Fprintf(&w, "<h2>%s</h2>\n<p class=\"quiet\">%s</p>\n", e(b.Worth.Title), e(b.Worth.Intro))
	if len(b.Findings) == 0 {
		w.WriteString("<p>Nothing on this PC stood out to the rules. That is not a promise that nothing is wrong: LazaScope only knows the signs it was taught.</p>\n")
	}
	for _, f := range b.Findings {
		fmt.Fprintf(&w, "<div class=\"finding %s\">\n<h3><span class=\"tag\">%s</span>%s</h3>\n<p class=\"quiet\">%s: %s</p>\n<p>%s</p>\n<p><b>What you can do:</b> %s</p>\n",
			class(severity(f.Severity)), e(f.Severity.String()), e(f.Title), e(f.Area.String()), e(f.Subject), e(f.Reason), e(f.Advice))
		if len(f.Facts) > 0 {
			w.WriteString("<dl>")
			for _, fact := range f.Facts {
				fmt.Fprintf(&w, "<dt>%s</dt><dd>%s</dd>", e(fact.Label), e(fact.Value))
			}
			w.WriteString("</dl>\n")
		}
		fmt.Fprintf(&w, "<p class=\"quiet\">Rule: %s</p>\n</div>\n", e(f.Rule))
	}
	if len(b.Worth.Unseen) > 0 {
		w.WriteString("<h2>What could not be read</h2>\n<ul>\n")
		for _, note := range b.Worth.Unseen {
			fmt.Fprintf(&w, "<li>%s</li>\n", e(note))
		}
		w.WriteString("</ul>\n")
	}

	w.WriteString("<h2 class=\"part\">The facts</h2>\n<p class=\"quiet\">Everything LazaScope read, whether or not a rule flagged it. Select a row to open what is known about it.</p>\n")
	for _, page := range []*view.Page{&b.Protection, &b.Accounts, &b.Startup, &b.Running, &b.Connections} {
		fmt.Fprintf(&w, "<h2 id=\"%s\">%s</h2>\n<p class=\"quiet\">%s %s.</p>\n", e(strings.ToLower(page.Name)), e(page.Title), e(page.Intro), count(len(page.Rows), "row", "rows"))
		fmt.Fprintf(&w, "<div class=\"list\" style=\"--columns:%s\">\n<div class=\"head\">", columns(page.Columns))
		for _, column := range page.Columns {
			fmt.Fprintf(&w, "<span>%s</span>", e(column.Title))
		}
		w.WriteString("</div>\n")
		for _, row := range page.Rows {
			w.WriteString("<details><summary>")
			for i, cell := range row.Cells {
				if i == 0 && cell != "" {
					fmt.Fprintf(&w, "<span><span class=\"tag %s\">%s</span></span>", class(row.Level), e(cell))
				} else {
					fmt.Fprintf(&w, "<span>%s</span>", e(cell))
				}
			}
			w.WriteString("</summary><div class=\"detail\">")
			for _, line := range row.Detail {
				switch line.Style {
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
		w.WriteString("</div>\n")
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
// cannot go.
func Text(b *view.Book, version string) string {
	var w strings.Builder
	line := func(format string, values ...any) { fmt.Fprintf(&w, format+"\r\n", values...) }
	line("LazaScope report")
	line("Made by LazaScope %s on %s", version, b.Snapshot.Taken.Format("2006-01-02 15:04"))
	line(rule)
	line("")
	line("%s", b.Summary)
	line("%s", Careful)
	line("")
	line("AT A GLANCE")
	line(rule)
	for _, glance := range b.Glances {
		line("%-28s %s", glance.Area.String(), glance.Verdict)
		if glance.Facts != "" {
			line("%-28s %s", "", glance.Facts)
		}
	}
	line("")
	line("WORTH A LOOK (%d)", len(b.Findings))
	line(rule)
	if len(b.Findings) == 0 {
		line("Nothing on this PC stood out to the rules.")
	}
	for _, f := range b.Findings {
		line("[%s] %s", f.Severity, f.Title)
		line("    %s: %s", f.Area, f.Subject)
		line("    Why: %s", f.Reason)
		line("    What you can do: %s", f.Advice)
		for _, fact := range f.Facts {
			line("    %s: %s", fact.Label, fact.Value)
		}
		line("    Rule: %s", f.Rule)
		line("")
	}
	if len(b.Worth.Unseen) > 0 {
		line("WHAT COULD NOT BE READ")
		line(rule)
		for _, note := range b.Worth.Unseen {
			line("%s", note)
		}
		line("")
	}
	for _, page := range []*view.Page{&b.Protection, &b.Accounts, &b.Startup, &b.Running, &b.Connections} {
		line("%s (%d)", strings.ToUpper(page.Title), len(page.Rows))
		line(rule)
		var titles []string
		for _, column := range page.Columns {
			titles = append(titles, column.Title)
		}
		line("%s", strings.Join(titles, " | "))
		for _, row := range page.Rows {
			cells := append([]string{}, row.Cells...)
			if cells[0] == "" {
				cells[0] = "-"
			}
			line("%s", strings.Join(cells, " | "))
		}
		line("")
	}
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
	Ref      string            `json:"ref"` // which fact it is about
	Evidence map[string]string `json:"evidence,omitempty"`
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
	document := struct {
		Tool          string        `json:"tool"`
		Generated     string        `json:"generated"`
		TookMillis    int64         `json:"tookMilliseconds"`
		Computer      string        `json:"computer"`
		User          string        `json:"user"`
		Windows       string        `json:"windows"`
		Administrator bool          `json:"administratorRights"`
		Summary       string        `json:"summary"`
		Lights        []jsonLight   `json:"lights"`
		Findings      []jsonFinding `json:"findings"`
		CouldNotRead  []string      `json:"couldNotRead"`
		Facts         jsonFacts     `json:"facts"`
	}{
		Tool: "LazaScope " + version, Generated: stamp(s.Taken), TookMillis: s.Took.Milliseconds(),
		Computer: s.Computer, User: s.User, Windows: s.Windows, Administrator: s.Elevated, Summary: b.Summary,
		Lights: []jsonLight{}, Findings: []jsonFinding{}, CouldNotRead: append([]string{}, b.Worth.Unseen...), Facts: facts(s),
	}
	for _, glance := range b.Glances {
		document.Lights = append(document.Lights, jsonLight{glance.Area.String(), lamp(glance.Light), glance.Verdict, glance.Facts})
	}
	for _, f := range b.Findings {
		finding := jsonFinding{f.Rule, strings.ToLower(f.Severity.String()), f.Area.String(), f.Title, f.Subject, f.Reason, f.Advice, f.Ref, map[string]string{}}
		for _, fact := range f.Facts {
			if have, ok := finding.Evidence[fact.Label]; ok {
				finding.Evidence[fact.Label] = have + "; " + fact.Value
			} else {
				finding.Evidence[fact.Label] = fact.Value
			}
		}
		document.Findings = append(document.Findings, finding)
	}
	out, _ := json.MarshalIndent(document, "", "  ")
	return append(out, '\n')
}
