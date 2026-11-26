package view

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"lazascope/internal/model"
	"lazascope/internal/netconn"
	"lazascope/internal/phrase"
	"lazascope/internal/rules"
	"lazascope/internal/sigcheck"
)

// Analyst mode adds to each row the exact evidence behind it, in the form
// a security analyst copies into a ticket: full paths and registry places,
// numbers and codes as Windows gives them, times in UTC, and the numbers of
// the rules and ATT&CK techniques. The same pass gives each row the values
// the search box can ask about.

// AnalystHeading heads the evidence analyst mode adds to a row's details.
const AnalystHeading = "For analysts"

// utc writes a time the way logs and tickets do: in UTC, to the second.
func utc(t time.Time) string {
	if t.IsZero() {
		return "not known"
	}
	return t.UTC().Format("2006-01-02 15:04:05Z")
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// levelWord is the word the search uses for a level.
func levelWord(l Level) string {
	switch l {
	case First:
		return "first"
	case Look:
		return "look"
	case Info:
		return "know"
	case Fine:
		return "fine"
	case Unknown:
		return "unknown"
	}
	return "none"
}

// signedWord is the word the search uses for a file's signature.
func signedWord(f model.File) string {
	if f.Path == "" || !f.Exists {
		return ""
	}
	switch f.Signature.Status {
	case sigcheck.Signed:
		return "yes"
	case sigcheck.Unsigned:
		return "no"
	case sigcheck.Invalid:
		return "broken"
	}
	return ""
}

// vtWord is the word the search uses for what VirusTotal said of a file.
func vtWord(s *model.Snapshot, path string) string {
	r, ok := s.Reputation(path)
	switch {
	case !ok:
		return "notasked"
	case !r.Known:
		return "unknown"
	case r.Flags() > 0:
		return "flagged"
	}
	return "clean"
}

// raw is the evidence of one row, line by line.
type raw struct {
	lines  []Line
	fields map[string][]string
}

func (r *raw) line(format string, a ...any) {
	r.lines = append(r.lines, Line{Command, fmt.Sprintf(format, a...)})
}

func (r *raw) field(name string, values ...string) {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			r.fields[name] = append(r.fields[name], v)
		}
	}
}

// file adds the exact facts of a file.
func (r *raw) file(s *model.Snapshot, label string, f model.File) {
	if f.Path == "" {
		return
	}
	r.line("%s: %s", label, f.Path)
	r.field("path", f.Path)
	if !f.Exists {
		r.line("  exists: no")
		return
	}
	if f.Size > 0 || !f.Modified.IsZero() {
		r.line("  size: %d bytes; modified: %s", f.Size, utc(f.Modified))
	}
	if print := s.Fingerprint(f.Path); print != "" {
		r.line("  sha256: %s", print)
	}
	if f.Program {
		sig := f.Signature
		text := "  signature: " + map[sigcheck.Status]string{sigcheck.Signed: "valid", sigcheck.Unsigned: "none", sigcheck.Invalid: "invalid"}[sig.Status]
		if text == "  signature: " {
			text += "not checked"
		}
		switch sig.Source {
		case sigcheck.Embedded:
			text += "; in the file"
		case sigcheck.Catalogue:
			text += "; in a catalogue"
		}
		if sig.Signer != "" {
			text += "; signer: " + sig.Signer
		}
		if sig.Catalogue != "" {
			text += "; catalogue: " + sig.Catalogue
		}
		if sig.Code != 0 {
			text += fmt.Sprintf("; WinVerifyTrust: 0x%08X", sig.Code)
		}
		r.line("%s", text)
		var version []string
		for _, kv := range [][2]string{{"CompanyName", f.Company}, {"FileDescription", f.Description}, {"ProductName", f.Product}, {"FileVersion", f.Version}, {"OriginalFilename", f.Original}} {
			if kv[1] != "" {
				version = append(version, kv[0]+"="+kv[1])
			}
		}
		if len(version) > 0 {
			r.line("  version info: %s", strings.Join(version, "; "))
		}
	}
	r.field("signed", signedWord(f))
	r.field("maker", f.Maker(), f.Signature.Signer, f.Company)
	r.field("vt", vtWord(s, f.Path))
	if f.Opinion.Asked {
		r.line("  AMSI: %s", opinionWord(f.Opinion))
	}
	if rep, ok := s.Reputation(f.Path); ok {
		r.line("  VirusTotal: known=%s malicious=%d suspicious=%d undetected=%d harmless=%d label=%q asked=%s analysed=%s",
			yesNo(rep.Known), rep.Malicious, rep.Suspicious, rep.Undetected, rep.Harmless, rep.Label, utc(rep.Asked), utc(rep.Analysed))
	}
}

func opinionWord(o model.Opinion) string {
	switch {
	case o.Harmful && o.Name != "":
		return "harmful (" + o.Name + ")"
	case o.Harmful:
		return "harmful"
	}
	return "no objection"
}

// findings adds the rules that flagged a row, with their ATT&CK techniques.
func (b *builder) rawFindings(r *raw, refs ...string) {
	for _, ref := range refs {
		for _, f := range b.byRef[ref] {
			text := fmt.Sprintf("finding: %s (%s; ref %s)", f.Rule, levelWord(level(f.Severity)), f.Ref)
			if len(f.Attack) > 0 {
				text += "; ATT&CK " + strings.Join(f.Attack, ", ")
			}
			r.line("%s", text)
			r.field("rule", f.Rule)
			r.field("attack", f.Attack...)
		}
	}
}

// analyst gives every row of a book the exact evidence behind it, and the
// values the search can ask about.
func (b *builder) analyst(book *Book) {
	processes := map[uint32]model.Process{}
	for _, p := range b.s.Processes {
		processes[p.PID] = p
	}
	for page, name := range map[*Page]string{&book.Protection: "protection", &book.Startup: "start-up", &book.Running: "running", &book.Connections: "connections",
		&book.Accounts: "accounts", &book.Health: "health", &book.Worth: "worth a look", &book.VirusTotal: "virustotal", &book.Wallets: "wallets", &book.Timeline: "timeline", &book.Defences: "defences", &book.Devices: "devices"} {
		for i := range page.Rows {
			row := &page.Rows[i]
			r := &raw{fields: map[string][]string{"page": {name}, "level": {levelWord(row.Level)}, "new": {yesNo(row.Fresh)}, "windows": {yesNo(row.Windows)}}}
			b.evidence(row, r, processes)
			row.Raw, row.Fields = r.lines, r.fields
			var text []string
			text = append(text, row.Cells...)
			for _, line := range append(append([]Line{}, row.Detail...), r.lines...) {
				text = append(text, line.Text)
			}
			row.Text = strings.Join(text, "\n")
		}
	}
}

// evidence fills in what is known about one row.
func (b *builder) evidence(row *Row, r *raw, processes map[uint32]model.Process) {
	s := b.s
	kind, key, _ := strings.Cut(row.Ref, ":")
	if len(row.Cells) > 1 {
		r.field("name", row.Cells[1])
	}
	switch kind {
	case "startup":
		i, err := strconv.Atoi(key)
		if err != nil || i < 0 || i >= len(s.Startup) {
			return
		}
		e := s.Startup[i]
		r.field("name", e.Name, e.Title)
		r.field("kind", e.Kind.String())
		r.field("account", e.Account)
		r.field("command", e.Command)
		r.line("kind: %s", e.Kind)
		r.line("recorded in: %s", e.Where)
		r.line("name: %s", e.Name)
		if e.Command != "" {
			r.line("command: %s", e.Command)
		}
		if e.Subject != "" {
			r.line("set for: %s", e.Subject)
		}
		r.line("enabled: %s; all users: %s; running: %s; account: %s; trigger: %s", yesNo(e.Enabled), yesNo(e.AllUsers), yesNo(e.Running), orNone(e.Account), orNone(e.Trigger))
		if x := e.Extension; x != nil {
			r.line("extension: browser=%s; profile=%s; id=%s; version=%s; source=%s; every site=%s", x.Browser, x.Profile, x.ID, x.Version, x.Source, yesNo(x.EverySite))
			if len(x.May) > 0 {
				r.line("  may also: %s", strings.Join(x.May, "; "))
			}
			if x.Folder != "" {
				r.line("  folder: %s", x.Folder)
				r.field("path", x.Folder)
			}
		}
		r.file(s, "image", e.Program)
		if e.Target.Path != "" && !strings.EqualFold(e.Target.Path, e.Program.Path) {
			r.file(s, "target", e.Target)
		}
		if e.Said.Asked {
			r.line("AMSI on the command line: %s", opinionWord(e.Said))
		}
		b.rawFindings(r, row.Ref)
	case "process":
		pid, err := strconv.Atoi(key)
		p, ok := processes[uint32(pid)]
		if err != nil || !ok {
			return
		}
		r.field("pid", strconv.Itoa(int(p.PID)))
		r.field("parent", strconv.Itoa(int(p.Parent)))
		r.field("account", p.User)
		r.field("command", p.Command)
		r.field("kind", "process")
		parent := ""
		if q, ok := processes[p.Parent]; ok {
			parent = " (" + q.Name + ")"
		}
		if p.ParentGone {
			parent = " (closed since)"
		}
		r.line("pid: %d; parent: %d%s; session: %d", p.PID, p.Parent, parent, p.Session)
		r.line("user: %s; started: %s", orNone(p.User), utc(p.Started))
		switch {
		case p.Command != "":
			r.line("command: %s", p.Command)
		case p.CommandHidden:
			r.line("command: hidden from this account")
		}
		if len(p.Services) > 0 {
			r.line("services: %s", strings.Join(p.Services, ", "))
		}
		r.file(s, "image", p.File)
		if p.Said.Asked {
			r.line("AMSI on the command line: %s", opinionWord(p.Said))
		}
		refs := []string{row.Ref}
		if p.File.Path != "" {
			refs = append(refs, rules.FileRef(p.File.Path))
		}
		b.rawFindings(r, refs...)
	case "connection":
		i, err := strconv.Atoi(key)
		if err != nil || i < 0 || i >= len(s.Connections) {
			return
		}
		c := s.Connections[i]
		r.field("pid", strconv.Itoa(int(c.PID)))
		r.field("name", c.Process)
		r.field("port", strconv.Itoa(c.LocalPort))
		r.field("address", c.Local)
		r.field("reach", strings.ToLower(c.Reach.String()))
		r.field("kind", c.Protocol, map[bool]string{true: "listening", false: "connection"}[c.Listening])
		r.line("protocol: %s; state: %s; listening: %s", c.Protocol, orNone(c.State), yesNo(c.Listening))
		r.line("local: %s", netconn.Join(c.Local, c.LocalPort))
		if !c.Listening {
			r.field("port", strconv.Itoa(c.RemotePort))
			r.field("address", c.Remote)
			r.field("address", c.Names...)
			text := "remote: " + netconn.Join(c.Remote, c.RemotePort)
			if len(c.Names) > 0 {
				text += " (names from the DNS cache: " + strings.Join(c.Names, ", ") + ")"
			}
			r.line("%s", text)
		}
		r.line("reach: %s; pid: %d; process: %s", c.Reach, c.PID, c.Process)
		if len(c.Services) > 0 {
			r.line("services: %s", strings.Join(c.Services, ", "))
		}
		r.file(s, "image", c.File)
		if c.Listening && c.File.Path != "" {
			b.rawFindings(r, rules.ListenRef(c.File.Path))
		}
	case "topic":
		b.topicEvidence(key, r)
		b.rawFindings(r, key)
	case "finding":
		i, err := strconv.Atoi(key)
		if err != nil || i < 0 || i >= len(b.findings) {
			return
		}
		f := b.findings[i]
		r.field("name", f.Subject)
		r.field("rule", f.Rule)
		r.field("attack", f.Attack...)
		r.field("kind", f.Area.String())
		r.line("rule: %s; level: %s; area: %s; ref: %s", f.Rule, levelWord(level(f.Severity)), f.Area, f.Ref)
		for _, fact := range f.Facts {
			r.line("%s: %s", strings.ToLower(fact.Label), fact.Value)
			switch fact.Label {
			case "File", "Started through":
				r.field("path", fact.Value)
				if print := s.Fingerprint(fact.Value); print != "" {
					r.line("  sha256: %s", print)
				}
			case "Command":
				r.field("command", fact.Value)
			}
		}
		for _, t := range rules.Techniques(f.Attack) {
			r.line("ATT&CK %s: %s %s", rules.AttackVersion, t.ID, t.Name)
		}
	case "defence":
		i, err := strconv.Atoi(key)
		if err != nil || i < 0 || i >= len(s.Defences) {
			return
		}
		d := s.Defences[i]
		r.field("name", d.Name)
		r.line("defence: %s (%s); on: %s; part of Defender: %s; helps against ransomware: %s", d.Name, d.Key, d.On, yesNo(d.Defender), yesNo(d.Ransomware))
		if d.Note != "" {
			r.line("note: %s", d.Note)
		}
		b.rawFindings(r, "defences")
	case "device":
		i, err := strconv.Atoi(key)
		if err != nil || i < 0 || i >= len(s.DeviceUses) {
			return
		}
		d := s.DeviceUses[i]
		r.field("name", d.App)
		r.field("kind", d.Device)
		r.line("device: %s; app: %s; a program file: %s; allowed: %s", d.Device, d.App, yesNo(d.Program), d.Allowed)
		r.line("last started: %s; last stopped: %s; in use now: %s", utc(d.Start), utc(d.Stop), yesNo(d.InUse()))
		if d.Program {
			r.file(s, "image", d.File)
		}
		b.rawFindings(r, row.Ref)
	case "wallet":
		i, err := strconv.Atoi(key)
		if err != nil || i < 0 || i >= len(s.Wallets) {
			return
		}
		w := s.Wallets[i]
		r.field("name", w.Name)
		r.field("kind", w.Kind)
		r.field("path", w.Where)
		r.line("wallet: %s; kind: %s; where: %s", w.Name, w.Kind, w.Where)
		r.line("real by its number: %s; can hold keys: %s; copied by: %s; ref: %s", yesNo(w.Verified), yesNo(w.Keys), orNone(w.Synced), orNone(w.Ref))
		if w.Ref != "" {
			b.rawFindings(r, w.Ref)
		}
	case "phrase":
		i, err := strconv.Atoi(key)
		if s.Phrases == nil || err != nil || i < 0 || i >= len(s.Phrases.Found) {
			return
		}
		f := s.Phrases.Found[i]
		r.field("path", f.Path)
		r.field("kind", "recovery phrase")
		r.line("file: %s", f.Path)
		var starts []string
		for _, line := range f.Lines {
			starts = append(starts, strconv.Itoa(line))
		}
		r.line("runs of recovery words start on lines: %s; most words in a row: %d; longest complete phrase whose checksum holds: %d words; the word list itself: %s",
			strings.Join(starts, ", "), f.Words, f.Phrase, yesNo(f.List))
		r.line("found at: %s; the words were not kept", utc(s.Phrases.When))
	case "file":
		for _, e := range s.Startup {
			if strings.EqualFold(e.Works().Path, row.Path) {
				r.file(s, "file", e.Works())
				return
			}
		}
		for _, p := range s.Processes {
			if strings.EqualFold(p.File.Path, row.Path) {
				r.file(s, "file", p.File)
				return
			}
		}
	}
}

// topicEvidence adds the records behind a row about a setting or a log.
func (b *builder) topicEvidence(ref string, r *raw) {
	s, g, c := b.s, b.s.Guard, b.s.Condition
	switch {
	case ref == "antivirus":
		for _, p := range g.Antivirus {
			r.line("product: %s; on: %s; up to date: %s", p.Name, p.On, p.UpToDate)
		}
		r.line("Windows Security's verdict: %s", g.AntivirusHealth)
	case ref == "realtime":
		r.line("real-time protection: %s", g.RealTime)
		for _, when := range g.SwitchedOff {
			r.line("switched off (Defender event 5001) at %s", utc(when))
		}
	case ref == "tamper":
		r.line("tamper protection: %s", g.Tamper)
	case ref == "exclusions":
		r.line("readable: %s", yesNo(g.ExclusionsVisible))
		for _, e := range g.Exclusions {
			r.line("exclusion: %s = %s", e.Kind, e.Value)
		}
		for _, e := range g.LoggedExclusions {
			r.line("added (Defender event 5007) at %s: %s = %s", utc(e.When), e.Kind, e.Value)
		}
	case ref == "detections":
		r.line("log: Microsoft-Windows-Windows Defender/Operational, events 1116 and 1117, %d days", g.HistoryDays)
		for i, d := range g.Detections {
			if i == 200 {
				r.line("and %d more", len(g.Detections)-i)
				break
			}
			r.line("detection at %s: threat=%s; severity=%s; category=%s; action=%s; source=%s; process=%s; path=%s",
				utc(d.When), d.Threat, d.Severity, d.Category, orNone(d.Action), orNone(d.Source), orNone(d.Process), d.Path)
			r.field("path", d.Path)
		}
	case ref == "firewall":
		for _, p := range g.Firewall {
			r.line("profile %s: on: %s", p.Name, p.On)
		}
		for _, p := range g.FirewallProducts {
			r.line("product: %s; on: %s", p.Name, p.On)
		}
	case ref == "uac":
		r.line("UAC (EnableLUA): %s; administrators let through without asking: %s", g.UAC, g.UACSilent)
	case ref == "updates":
		r.line("last update installed: %s; build: %s", map[bool]string{true: utc(g.LastUpdate), false: "not known"}[g.UpdateKnown], orNone(g.Build))
	case strings.HasPrefix(ref, "disk:"):
		for _, v := range g.Volumes {
			if "disk:"+strings.ToUpper(v.Drive) == ref {
				r.line("volume %s: encrypted: %s; state: %s", v.Drive, v.Encrypted, orNone(v.State))
			}
		}
	case ref == "secureboot":
		r.line("Secure Boot: %s", g.SecureBoot)
	case ref == "hosts":
		r.line("file: %s; readable: %s", g.HostsPath, yesNo(g.HostsVisible))
		for _, e := range g.Hosts {
			r.line("entry: %s %s", e.Address, strings.Join(e.Names, " "))
		}
	case ref == "dns":
		for _, n := range g.NameServers {
			r.line("name server: %s; connection: %s; typed in by hand: %s", n.Address, n.Connection, yesNo(n.ByHand))
			r.field("address", n.Address)
		}
	case ref == "proxy":
		r.line("proxy read: %s; server: %s; set-up script: %s; whole PC: %s", yesNo(g.Proxy.Read), orNone(g.Proxy.Server), orNone(g.Proxy.Script), yesNo(g.Proxy.AllUsers))
	case strings.HasPrefix(ref, "admin:"):
		for _, a := range g.Admins {
			if rules.AdminRef(a.Name) == ref {
				r.line("account: %s; a group: %s; switched off: %s; built in: %s", a.Name, yesNo(a.Group), a.Disabled, orNone(a.BuiltIn))
				r.field("account", a.Name)
			}
		}
	case ref == "clipboard":
		r.line("clipboard settings read: %s; history: %s; sent to other devices: %s", yesNo(s.Clipboard.Read), s.Clipboard.History, s.Clipboard.Cloud)
	case ref == "swaptest":
		if t := s.SwapTest; t != nil {
			r.line("test at %s; tried: %s; swapped: %s", utc(t.When), strings.Join(t.Tried, ", "), yesNo(t.Swapped))
			if t.Swapped {
				r.line("kind: %s; swapped for: %s; by: %s (pid %d) %s", t.Kind, t.Into, orNone(t.By), t.PID, t.Path)
			}
		} else {
			r.line("not run")
		}
	case ref == "phrases":
		if p := s.Phrases; p != nil {
			r.line("search at %s; folders: %s", utc(p.When), strings.Join(p.Folders, "; "))
			r.line("files read: %d; only in the cloud, not read: %d; too large, not read: %d; could not be opened: %d; stopped at the limit of %d files: %s; stopped by hand: %s",
				p.Read, p.Cloud, p.Big, p.Locked, phrase.Limit, yesNo(p.Full), yesNo(p.Stopped))
			r.line("files with a run of recovery words: %d", len(p.Found))
			for _, folder := range p.Folders {
				r.field("path", folder)
			}
		} else {
			r.line("not run")
		}
	case ref == "backups":
		bk := s.Backups
		r.line("File History last ran: %s; OneDrive copies: %s; backup programs: %s", utc(bk.FileHistory), orNone(strings.Join(bk.OneDrive, ", ")), orNone(strings.Join(bk.Programs, ", ")))
	case ref == "clouds":
		for _, c := range s.Clouds {
			r.line("cloud folder: %s = %s", c.Service, c.Path)
			r.field("path", c.Path)
		}
	case ref == "guest":
		r.line("Guest account on: %s", g.Guest)
	case ref == "autosignin":
		r.line("automatic sign-in: %s; account: %s", g.AutoSignIn, orNone(g.AutoUser))
	case ref == "rdp":
		r.line("Remote Desktop on: %s; asks for a password first (NLA): %s", g.RemoteDesktop, g.RemoteNLA)
	case strings.HasPrefix(ref, "remote:"):
		for _, tool := range rules.RemoteTools(s) {
			if rules.RemoteRef(tool.Name) == ref {
				r.line("tool: %s; running: %s; starts by itself: %s; installed: %s", tool.Name, yesNo(tool.Running), yesNo(tool.Starts), yesNo(tool.Installed))
				for _, evidence := range tool.Evidence {
					r.line("  %s", evidence)
				}
			}
		}
	case ref == "hardware":
		for i, f := range c.Hardware {
			if i == 200 {
				r.line("and %d more", len(c.Hardware)-i)
				break
			}
			r.line("System log event %d at %s: part=%s; which=%s; corrected=%s; %s", f.ID, utc(f.When), f.Part, orNone(f.Where), yesNo(!f.Fatal), f.Words)
		}
	case ref == "crashes":
		for i, crash := range c.Crashes {
			if i == 200 {
				r.line("and %d more", len(c.Crashes)-i)
				break
			}
			r.line("stop at %s: code 0x%X %s", utc(crash.When), crash.Code, crash.Name)
		}
	case ref == "stops":
		for i, when := range c.PowerCuts {
			if i == 200 {
				break
			}
			r.line("unexpected stop noticed at %s", utc(when))
		}
	case ref == "disk":
		for i, f := range c.Disk {
			if i == 200 {
				r.line("and %d more", len(c.Disk)-i)
				break
			}
			r.line("System log event %d at %s: %s %s", f.ID, utc(f.When), orNone(f.Where), f.Words)
		}
		r.line("disk asked twice: %d times", c.Retries)
	case ref == "wiped":
		for _, w := range c.Wiped {
			r.line("log cleared at %s: log=%s; by=%s", utc(w.When), w.Log, orNone(w.By))
		}
	case strings.HasPrefix(ref, "space:"):
		for _, d := range c.Drives {
			if rules.SpaceRef(d.Letter) == ref {
				r.line("drive %s: size %d bytes; free %d bytes", d.Letter, d.Size, d.Free)
			}
		}
	}
}

func orNone(text string) string {
	if strings.TrimSpace(text) == "" {
		return "none"
	}
	return text
}
