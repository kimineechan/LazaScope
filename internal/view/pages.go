package view

import (
	"strconv"
	"strings"

	"lazascope/internal/model"
	"lazascope/internal/netconn"
	"lazascope/internal/rules"
	"lazascope/internal/winpath"
)

// partOfWindows reports whether a file is a part of Windows itself: kept
// where Windows keeps its own files, and signed by Microsoft as its own.
//
// Some parts of Windows carry two signatures, one in the file in the name
// "Microsoft Corporation" and one in a catalogue in the name "Microsoft
// Windows". The checker reports the one in the file, so that name counts
// too when the file is in the Windows folder. The name Microsoft signs
// other makers' drivers under does not: those are not parts of Windows.
func partOfWindows(f model.File, folders model.Folders) bool {
	if !rules.InWindows(f.Path, folders) || !f.Signature.Trusted() {
		return false
	}
	switch f.Signature.Signer {
	case "Microsoft Windows", "Microsoft Windows Publisher", "Microsoft Corporation", "Microsoft Windows Hardware Abstraction Layer Publisher":
		return true
	}
	return false
}

// windowsEntry reports whether a start-up entry is Windows' own: the file
// that does its work is a part of Windows, or it names no file and is one
// of the tasks Windows comes with. The list and the overview both count
// with this, so that their numbers agree.
func windowsEntry(e model.Startup, folders model.Folders) bool {
	works := e.Works()
	return partOfWindows(works, folders) || (works.Path == "" && e.Kind == model.ScheduledTask && strings.HasPrefix(strings.ToLower(e.Name), `\microsoft\windows\`))
}

// place returns a file's path when the file is there to be shown.
func place(f model.File) string {
	if f.Exists {
		return f.Path
	}
	return ""
}

// file adds what is known about a file to the lines of detail.
func file(lines []Line, f model.File) []Line {
	if f.Path == "" {
		return lines
	}
	lines = append(lines, Line{Text, "File:"}, Line{Command, f.Path})
	switch {
	case !f.Exists && f.Signature.Problem != "" && f.Signature.Problem != "The file does not exist.":
		return append(lines, Line{Text, f.Signature.Problem})
	case !f.Exists:
		return append(lines, Line{Text, "There is no file at that place."})
	case !f.Program:
		if rules.Script(f.Path) {
			return append(lines, Line{Text, "This is a script: a text file of commands, not a program. LazaScope checks signatures on programs only, and scripts almost never carry one."})
		}
		return append(lines, Line{Text, "This is not a program file, so there is no maker's signature to check."})
	}
	lines = fact(lines, "Signature", rules.Signature(f))
	lines = fact(lines, "The file says it is", rules.Claim(f))
	return fact(lines, "Version", f.Version)
}

func yes(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

func (b *builder) startup() Page {
	s := b.s
	page := Page{
		Name: "Start-up", Title: "What starts by itself",
		Intro:   "Every program, task, service and driver that Windows starts without being asked. Most of them belong to Windows or to software you installed.",
		Columns: []Column{{"Check", 112}, {"Name", 250}, {"Kind", 128}, {"Maker", 200}, {"File", 0}},
		Unseen:  b.unseen(model.StartsWithWindows),
	}
	for i, e := range s.Startup {
		ref := rules.StartupRef(i)
		works := e.Works()
		row := Row{Level: b.worst(ref), Path: place(works), Off: !e.Enabled}
		row.Windows = windowsEntry(e, s.Folders)
		check, maker := row.Level.String(), works.Maker()
		if !e.Enabled && check == "" {
			check = "Off"
		}
		if works.Path == "" {
			maker = "No file named"
		} else if works.Exists && !works.Program && rules.Script(works.Path) {
			maker = "Script file"
		}
		row.Cells = []string{check, e.Shown(), e.Kind.String(), maker, works.Path}

		lines := []Line{{Heading, e.Shown()}, {Text, e.Kind.Explain()}}
		if !e.Enabled {
			lines = append(lines, Line{Text, "This entry is switched off, so it does not start."})
		}
		lines = b.said(lines, ref)
		lines = append(lines, Line{Heading, "Details"})
		if e.Title != "" {
			lines = fact(lines, "Name in Windows", e.Name)
		}
		lines = fact(lines, "Recorded in", e.Where)
		lines = fact(lines, "Set for", e.Subject)
		lines = fact(lines, "Starts", e.Trigger)
		lines = fact(lines, "Runs as", e.Account)
		if e.Kind == model.Service || e.Kind == model.Driver {
			lines = fact(lines, "Running now", yes(e.Running))
		}
		lines = fact(lines, "About", e.Description)
		if e.Command != "" {
			lines = append(lines, Line{Text, "Command:"}, Line{Command, e.Command})
		}
		lines = file(lines, works)
		if e.Program.Path != "" && !winpath.Same(e.Program.Path, works.Path) {
			lines = append(lines, Line{Text, "Started through:"}, Line{Command, e.Program.Path})
		}
		if works.Path == "" {
			lines = append(lines, Line{Aside, "LazaScope could not work out which file this entry runs, so it could not check who made it."})
		}
		row.Detail = lines
		page.Rows = append(page.Rows, row)
	}
	byLevel(page.Rows)
	return page
}

func (b *builder) running() Page {
	s := b.s
	page := Page{
		Name: "Running", Title: "What is running now",
		Intro:   "Every running program, set under the program that started it. Many are parts of Windows, and one program often runs as several copies.",
		Columns: []Column{{"Check", 112}, {"Program", 330}, {"Number", 76}, {"Account", 170}, {"Maker", 0}},
		Unseen:  b.unseen(model.RunningNow),
	}
	names := map[uint32]string{}
	for _, p := range s.Processes {
		names[p.PID] = p.Name
	}
	for _, member := range model.Family(s.Processes) {
		p := member.Process
		refs := []string{rules.ProcessRef(p.PID)}
		if p.File.Path != "" {
			refs = append(refs, rules.FileRef(p.File.Path))
		}
		row := Row{Path: place(p.File), Windows: partOfWindows(p.File, s.Folders) || p.File.Path == ""}
		for _, ref := range refs {
			row.Level = max(row.Level, b.worst(ref))
		}
		maker, account := p.File.Maker(), p.User
		if p.File.Path == "" {
			maker = "Part of Windows itself"
		}
		if account == "" {
			account = "Not known"
		}
		row.Cells = []string{row.Level.String(), strings.Repeat("    ", member.Depth) + p.Name, strconv.Itoa(int(p.PID)), account, maker}

		lines := []Line{{Heading, p.Name}}
		if p.Self {
			lines = append(lines, Line{Text, "This is LazaScope itself, the program you are looking at. It is listed like any other program, but the rules do not judge it."})
		}
		lines = b.said(lines, refs...)
		lines = append(lines, Line{Heading, "Details"})
		switch {
		case p.Parent == 0:
			lines = fact(lines, "Started by", "Windows itself")
		case p.ParentGone:
			lines = fact(lines, "Started by", "a program that has since closed")
		default:
			lines = fact(lines, "Started by", names[p.Parent]+" (number "+strconv.Itoa(int(p.Parent))+")")
		}
		if !p.Started.IsZero() {
			lines = fact(lines, "Running since", p.Started.Format("2 January 2006, 15:04"))
		}
		lines = fact(lines, "Runs as", p.User)
		lines = fact(lines, "Services inside it", strings.Join(p.Services, ", "))
		switch {
		case p.Command != "":
			lines = append(lines, Line{Text, "Command:"}, Line{Command, p.Command})
		case p.CommandHidden && p.File.Path != "":
			lines = append(lines, Line{Aside, "The command that started this program can only be read with administrator rights."})
		}
		lines = file(lines, p.File)
		if p.File.Path == "" {
			lines = append(lines, Line{Aside, "This is a part of Windows that runs without a program file of its own."})
		}
		row.Detail = lines
		page.Rows = append(page.Rows, row)
	}
	return page
}

func (b *builder) connections() Page {
	s := b.s
	page := Page{
		Name: "Connections", Title: "What is talking to the network",
		Intro:   "Each connection a program has open, and each port a program is waiting on for others to connect. A port is a numbered door on the PC. Addresses are shown as numbers, because looking their names up would mean going online.",
		Columns: []Column{{"Check", 112}, {"Program", 220}, {"What", 156}, {"Address", 214}, {"Reach", 112}, {"Maker", 0}},
		Unseen:  b.unseen(model.Connections),
	}
	for _, c := range s.Connections {
		row := Row{Path: place(c.File), Windows: partOfWindows(c.File, s.Folders) || c.File.Path == ""}
		ref := ""
		if c.Listening && c.Protocol == "TCP" && c.Reach != model.ThisPC && c.File.Path != "" {
			ref = rules.ListenRef(c.File.Path)
			row.Level = b.worst(ref)
		}
		program := c.Process
		if len(c.Services) > 0 {
			program += " (" + strings.Join(c.Services, ", ") + ")"
		}
		what, address, reach := c.State+" to", netconn.Join(c.Remote, c.RemotePort), c.Reach.String()
		use := netconn.Service(c.RemotePort)
		lines := []Line{{Heading, c.Process + " is connected to " + address}}
		if c.Listening {
			what, address, use = "Waits for connections", c.Protocol+" port "+strconv.Itoa(c.LocalPort), netconn.Service(c.LocalPort)
			if c.Protocol == "UDP" {
				what = "Open to receive"
			}
			lines = []Line{{Heading, c.Process + " waits on " + address}}
			if c.Reach == model.ThisPC {
				lines = append(lines, Line{Text, "It waits on " + c.Local + ", an address only this PC itself can reach. Programs use this to talk to their own parts."})
			} else {
				reach = "The network"
				lines = append(lines, Line{Text, "It waits on " + c.Local + ", which other devices on the network can reach, as far as the firewall lets them."})
			}
		} else {
			if c.State == "Closing" {
				// Windows keeps a finished connection in its table for a
				// short while, sometimes after the program itself has gone.
				what = "Closing"
				lines = []Line{{Heading, c.Process + " had a connection to " + address + ", which is closing"}}
			}
			switch c.Reach {
			case model.ThisPC:
				lines = append(lines, Line{Text, "The other end is on this PC itself: two programs here talking to each other."})
			case model.LocalNetwork:
				lines = append(lines, Line{Text, "The other end is on your local network: another device at home or in the office, such as a router or a printer."})
			default:
				lines = append(lines, Line{Text, "The other end is out on the internet."})
			}
		}
		if use != "" {
			lines = append(lines, Line{Text, "That port is normally used for " + use + "."})
		}
		switch {
		case c.Listening && c.Reach == model.ThisPC:
			row.Group = "waits here"
		case c.Listening:
			row.Group = "waits"
		case c.Reach == model.Internet:
			row.Group = "internet"
		default:
			row.Group = "near"
		}
		row.Cells = []string{row.Level.String(), program, what, address, reach, c.File.Maker()}
		if c.File.Path == "" {
			row.Cells[5] = "Not known"
			if c.PID == 4 {
				row.Cells[5] = "Part of Windows itself"
			}
		}
		if ref != "" {
			lines = b.said(lines, ref)
		}
		lines = append(lines, Line{Heading, "Details"})
		lines = fact(lines, "This PC's end", netconn.Join(c.Local, c.LocalPort))
		if !c.Listening {
			lines = fact(lines, "The other end", netconn.Join(c.Remote, c.RemotePort))
		}
		lines = fact(lines, "Kind", c.Protocol)
		if c.PID != 0 {
			lines = fact(lines, "Process number", strconv.Itoa(int(c.PID)))
		}
		lines = fact(lines, "Services inside the program", strings.Join(c.Services, ", "))
		row.Detail = file(lines, c.File)
		page.Rows = append(page.Rows, row)
	}
	byLevel(page.Rows)
	return page
}

// topic makes a row about one setting: what it is, how it stands, and what
// the rules said of it. Without a finding, the row is fine when the state
// is known to be good and not known otherwise.
func (b *builder) topic(what, state string, good model.Answer, about string, ref string, more ...Line) Row {
	row := Row{Level: b.worst(ref)}
	if row.Level == Plain {
		switch good {
		case model.Yes:
			row.Level = Fine
		case model.NotKnown:
			row.Level = Unknown
		}
	}
	row.Cells = []string{row.Level.String(), what, state}
	lines := []Line{{Heading, what}, {Text, about}}
	lines = b.said(lines, ref)
	lines = append(lines, Line{Heading, "How it stands"}, Line{Text, state})
	row.Detail = append(lines, more...)
	return row
}

func state(a model.Answer, yes, no string) string {
	switch a {
	case model.Yes:
		return yes
	case model.No:
		return no
	}
	return "Not known"
}

func (b *builder) protection() Page {
	s, g := b.s, b.s.Guard
	page := Page{
		Name: "Protection", Title: "How this PC is protected",
		Intro:   "The settings that keep unwanted software out and limit what it can do. These are facts read from Windows. Nothing was tested by attacking the PC.",
		Columns: []Column{{"Check", 112}, {"What", 250}, {"How it stands", 0}},
		Unseen:  b.unseen(model.Protection),
	}
	add := func(row Row) { page.Rows = append(page.Rows, row) }

	// Antivirus.
	var products []string
	var more []Line
	anyOn := model.NotKnown
	for _, p := range g.Antivirus {
		text := p.Name + ": " + strings.ToLower(state(p.On, "On", "Off"))
		if p.On == model.Yes {
			text += ", " + strings.ToLower(state(p.UpToDate, "Up to date", "Out of date"))
			anyOn = model.Yes
		} else if anyOn == model.NotKnown && p.On == model.No {
			anyOn = model.No
		}
		products = append(products, text)
	}
	antivirus := strings.Join(products, ". ")
	if antivirus == "" {
		antivirus = state(g.AntivirusHealth, "Windows Security reports it as good", "Windows Security reports that it needs attention")
	}
	if g.AntivirusHealth != model.NotKnown {
		more = append(more, Line{Text, "Windows Security's own verdict: " + strings.ToLower(state(g.AntivirusHealth, "Good", "Needs attention")) + "."})
		anyOn = g.AntivirusHealth
	}
	add(b.topic("Antivirus", antivirus, anyOn, "Antivirus checks each file as it is opened or downloaded and stops the ones it knows to be harmful. Windows comes with one, Microsoft Defender.", "antivirus", more...))
	add(b.topic("Defender real-time protection", state(g.RealTime, "On", "Off"), g.RealTime, "Real-time protection is the part of Microsoft Defender that checks files the moment they are opened. With another antivirus installed, Defender steps aside and this is off.", ""))
	add(b.topic("Defender tamper protection", state(g.Tamper, "On", "Off"), g.Tamper, "Tamper Protection stops other programs from switching Microsoft Defender off or changing its settings.", "tamper"))

	// What Defender skips.
	switch {
	case !g.ExclusionsVisible:
		add(b.topic("Places Defender skips", "Can only be read with administrator rights", model.NotKnown, "An exclusion tells the antivirus not to look at a folder, a kind of file or a program. Windows hides this list from ordinary programs so that malware cannot read where it would be safe.", "exclusions"))
	case len(g.Exclusions) == 0:
		add(b.topic("Places Defender skips", "None", model.Yes, "An exclusion tells the antivirus not to look at a folder, a kind of file or a program.", "exclusions"))
	default:
		var lines []Line
		for _, e := range g.Exclusions {
			lines = append(lines, Line{Text, e.Kind + ":"}, Line{Command, e.Value})
		}
		add(b.topic("Places Defender skips", count(len(g.Exclusions), "exclusion", "exclusions"), model.Yes, "An exclusion tells the antivirus not to look at a folder, a kind of file or a program.", "exclusions", lines...))
	}

	// Firewall.
	var onFor, offFor []string
	firewall := g.FirewallHealth
	for _, p := range g.Firewall {
		switch p.On {
		case model.Yes:
			onFor = append(onFor, strings.ToLower(p.Name))
		case model.No:
			offFor = append(offFor, strings.ToLower(p.Name))
		}
	}
	text := "Not known"
	switch {
	case len(offFor) > 0 && len(onFor) > 0:
		text = "Windows Firewall is on for " + strings.Join(onFor, ", ") + ", but off for " + strings.Join(offFor, ", ")
	case len(offFor) > 0:
		text = "Windows Firewall is off"
	case len(onFor) > 0:
		text = "Windows Firewall is on for " + strings.Join(onFor, ", ")
		if firewall == model.NotKnown {
			firewall = model.Yes
		}
	}
	more = nil
	for _, p := range g.FirewallProducts {
		more = append(more, Line{Text, p.Name + ": " + strings.ToLower(state(p.On, "On", "Off")) + "."})
	}
	add(b.topic("Firewall", text, firewall, "The firewall decides which programs on other devices may start a connection to this PC. Windows keeps one set of rules for private networks such as home, one for public networks such as a café, and one for work networks.", "firewall", more...))

	// The prompt before full rights.
	uac, good := "Not known", g.UAC
	switch {
	case g.UAC == model.No:
		uac = "Off"
	case g.UAC == model.Yes && g.UACSilent == model.Yes:
		uac = "On, but set never to ask"
	case g.UAC == model.Yes:
		uac = "On, and asks before giving a program full rights"
	}
	add(b.topic("User Account Control", uac, good, "User Account Control is the prompt that asks \"Do you want to allow this app to make changes?\" before a program gets full rights over the PC. It is the moment at which a person can say no.", "uac"))

	// Updates.
	updates, updated := "Not known", model.NotKnown
	if g.UpdateKnown {
		updates = "Last update installed on " + g.LastUpdate.Format("2 January 2006") + ", " + ago(int(s.Taken.Sub(g.LastUpdate).Hours()/24))
		updated = model.Yes
	}
	more = nil
	if g.Build != "" {
		more = append(more, Line{Text, "Windows build " + g.Build + ". The last part of that number goes up with each monthly update."})
	}
	add(b.topic("Windows updates", updates, updated, "Microsoft fixes security holes in Windows every month. A PC that stops installing updates keeps the holes that are already publicly known.", "updates", more...))

	// Disks.
	for _, v := range g.Volumes {
		encrypted := v.State
		if encrypted == "" {
			encrypted = "Not known"
		}
		add(b.topic("Disk "+v.Drive+" encryption", encrypted, v.Encrypted, "Encryption (BitLocker, or Device encryption) scrambles a disk so that it can only be read after signing in. Without it, anyone who takes the disk can read every file on it.", rules.DiskRef(v.Drive)))
	}
	add(b.topic("Secure Boot", state(g.SecureBoot, "On", "Off"), g.SecureBoot, "Secure Boot lets the PC start only software signed by its maker or by Microsoft, which blocks malware that loads before Windows does. A PC made before about 2012 does not have it.", "secureboot"))

	// The hosts file.
	entries := 0
	more = []Line{{Text, "File:"}, {Command, g.HostsPath}}
	for _, entry := range g.Hosts {
		for _, name := range entry.Names {
			if !strings.EqualFold(name, "localhost") {
				entries++
				if entries <= 60 {
					more = append(more, Line{Command, entry.Address + "  " + name})
				}
			}
		}
	}
	hosts, readable := "No entries", model.Yes
	switch {
	case !g.HostsVisible:
		hosts, readable = "Could not be opened", model.NotKnown
	case entries > 0:
		hosts = count(entries, "entry", "entries")
	}
	add(b.topic("Hosts file", hosts, readable, "Before Windows asks the internet where a website is, it looks in a small text file called hosts. A line there can send a name to any address, or block it.", "hosts", more...))
	return page
}

func (b *builder) accounts() Page {
	g := b.s.Guard
	page := Page{
		Name: "Accounts", Title: "Who can get into this PC",
		Intro:   "The accounts with full rights over the PC, and the ways it can be used from somewhere else.",
		Columns: []Column{{"Check", 112}, {"What", 250}, {"How it stands", 0}},
		Unseen:  b.unseen(model.Accounts),
	}
	add := func(row Row) { page.Rows = append(page.Rows, row) }
	const administrators = "An administrator account can install software and change any setting. Anything that runs under it can ask for those rights too. Fewer administrator accounts mean fewer ways in."
	if !g.AdminsVisible {
		add(b.topic("Administrator accounts", "Could not be read", model.NotKnown, administrators, ""))
	}
	for _, a := range g.Admins {
		what, how := "Administrator account", a.Name
		switch {
		case a.Group:
			what, how = "Administrator group", a.Name+", a group: every account in it is an administrator"
		case a.Disabled == model.Yes:
			how += ", switched off"
		case a.Disabled == model.No:
			how += ", in use"
		}
		if a.BuiltIn != "" {
			how += " (the built-in " + a.BuiltIn + " account every PC has)"
		}
		add(b.topic(what, how, model.Yes, administrators, rules.AdminRef(a.Name)))
	}
	add(b.topic("Guest account", state(g.Guest, "On", "Off"), invert(g.Guest), "Guest is a built-in account with no password, which Windows keeps switched off.", "guest"))
	sign := state(g.AutoSignIn, "On", "Off")
	if g.AutoSignIn == model.Yes && g.AutoUser != "" {
		sign = "On, as " + g.AutoUser
	}
	add(b.topic("Automatic sign-in", sign, invert(g.AutoSignIn), "Automatic sign-in skips the password when the PC starts, so whoever switches it on is in.", "autosignin"))
	remote := state(g.RemoteDesktop, "On", "Off")
	if g.RemoteDesktop == model.Yes && g.RemoteNLA == model.No {
		remote = "On, and it shows the sign-in screen before asking for a password"
	}
	add(b.topic("Remote Desktop", remote, invert(g.RemoteDesktop), "Remote Desktop is built into Windows. It lets someone sign in to this PC from another device and use it as if they sat in front of it. It is off unless someone switches it on.", "rdp"))

	const remoteTools = "Remote-control programs let someone else see the screen and use the mouse and keyboard over the internet. They are honest tools, and also the first thing a fake support caller asks for."
	tools := rules.RemoteTools(b.s)
	if len(tools) == 0 {
		add(b.topic("Remote-control software", "None of the programs LazaScope knows by name was found", model.Yes, remoteTools, ""))
	}
	for _, tool := range tools {
		var how []string
		if tool.Running {
			how = append(how, "running now")
		}
		if tool.Starts {
			how = append(how, "starts by itself")
		}
		if tool.Installed {
			how = append(how, "installed")
		}
		var lines []Line
		for _, evidence := range tool.Evidence {
			lines = append(lines, Line{Text, evidence})
		}
		add(b.topic("Remote-control software", tool.Name+": "+strings.Join(how, ", "), model.Yes, remoteTools, rules.RemoteRef(tool.Name), lines...))
	}
	return page
}

// invert turns "is it on?" into "is that good?" for the things that are
// better off.
func invert(a model.Answer) model.Answer {
	switch a {
	case model.Yes:
		return model.No
	case model.No:
		return model.Yes
	}
	return model.NotKnown
}

func (b *builder) worth() Page {
	page := Page{
		Name: "Worth a look", Title: "What is worth a second look",
		Intro:   "Everything the written rules flagged, the most serious first. A flag is a reason to look, not a verdict: the same signs that mark an intruder also mark plenty of honest software.",
		Columns: []Column{{"How soon", 112}, {"Where", 190}, {"What was found", 380}, {"About", 0}},
	}
	for _, gap := range b.s.Gaps {
		page.Unseen = append(page.Unseen, gap.What)
	}
	for _, f := range b.findings {
		row := Row{Level: level(f.Severity)}
		row.Cells = []string{f.Severity.String(), f.Area.String(), f.Title, f.Subject}
		lines := []Line{{Heading, f.Title}, {Text, f.Reason}, {Heading, "What you can do"}, {Text, f.Advice}}
		if len(f.Facts) > 0 {
			lines = append(lines, Line{Heading, "The facts"})
		}
		for _, fact := range f.Facts {
			switch fact.Label {
			case "Command", "File", "Started through":
				lines = append(lines, Line{Text, fact.Label + ":"}, Line{Command, fact.Value})
				if fact.Label == "File" && row.Path == "" {
					row.Path = fact.Value
				}
			default:
				lines = append(lines, Line{Text, fact.Label + ": " + fact.Value})
			}
		}
		lines = append(lines, Line{Aside, "Rule: " + f.Rule})
		row.Detail = lines
		page.Rows = append(page.Rows, row)
	}
	return page
}

// facts sums an area up in a line for the overview.
func (b *builder) facts(area model.Area) string {
	s, g := b.s, b.s.Guard
	switch area {
	case model.Protection:
		var parts []string
		on := model.NotKnown
		for _, p := range g.Antivirus {
			if p.On == model.Yes {
				on = model.Yes
			} else if on == model.NotKnown && p.On == model.No {
				on = model.No
			}
		}
		if on == model.NotKnown {
			on = g.AntivirusHealth
		}
		if on != model.NotKnown {
			parts = append(parts, "Antivirus "+strings.ToLower(state(on, "On", "Off")))
		}
		firewall := g.FirewallHealth
		for _, p := range g.Firewall {
			if p.On == model.No {
				firewall = model.No
			} else if p.On == model.Yes && firewall == model.NotKnown {
				firewall = model.Yes
			}
		}
		if firewall != model.NotKnown {
			parts = append(parts, "Firewall "+strings.ToLower(state(firewall, "On", "Off")))
		}
		if g.UpdateKnown {
			parts = append(parts, "Last update "+ago(int(s.Taken.Sub(g.LastUpdate).Hours()/24)))
		}
		if len(parts) == 0 {
			return ""
		}
		return strings.Join(parts, ". ") + "."
	case model.StartsWithWindows:
		if len(s.Startup) == 0 {
			return ""
		}
		other, off := 0, 0
		for _, e := range s.Startup {
			if !windowsEntry(e, s.Folders) {
				other++
			}
			if !e.Enabled {
				off++
			}
		}
		text := count(len(s.Startup), "thing is set to start by itself", "things are set to start by themselves")
		if off > 0 {
			text += ", " + strconv.Itoa(off) + " of them switched off"
		}
		return text + ". " + count(other, "is", "are") + " not part of Windows."
	case model.RunningNow:
		if len(s.Processes) == 0 {
			return ""
		}
		other := 0
		for _, p := range s.Processes {
			if p.File.Path != "" && !partOfWindows(p.File, s.Folders) {
				other++
			}
		}
		return count(len(s.Processes), "program is", "programs are") + " running. " + count(other, "of them is", "of them are") + " not part of Windows."
	case model.Connections:
		if len(s.Connections) == 0 {
			return ""
		}
		out, waiting := 0, map[string]bool{}
		for _, c := range s.Connections {
			switch {
			case !c.Listening && c.Reach == model.Internet && c.State != "Closing":
				out++
			case c.Listening && c.Reach != model.ThisPC:
				waiting[strconv.Itoa(int(c.PID))] = true
			}
		}
		return count(out, "connection", "connections") + " to the internet. " + count(len(waiting), "program waits", "programs wait") + " for connections from the network."
	case model.Accounts:
		var parts []string
		if g.AdminsVisible {
			active := 0
			for _, a := range g.Admins {
				if a.Disabled != model.Yes {
					active++
				}
			}
			parts = append(parts, count(active, "administrator account", "administrator accounts")+" in use")
		}
		if g.RemoteDesktop != model.NotKnown {
			parts = append(parts, "Remote Desktop "+strings.ToLower(state(g.RemoteDesktop, "On", "Off")))
		}
		if tools := rules.RemoteTools(s); len(tools) > 0 {
			parts = append(parts, count(len(tools), "remote-control program", "remote-control programs"))
		} else if len(s.Processes) > 0 {
			parts = append(parts, "No remote-control software found")
		}
		if len(parts) == 0 {
			return ""
		}
		return strings.Join(parts, ". ") + "."
	}
	return ""
}
