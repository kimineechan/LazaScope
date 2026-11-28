package rules

import (
	"lazascope/internal/i18n"
	"strconv"
	"strings"

	"lazascope/internal/model"
	"lazascope/internal/netconn"
	"lazascope/internal/winpath"
)

// aboutProcess gathers the evidence that goes with a running program.
func aboutProcess(s *model.Snapshot, p model.Process) []Fact {
	facts := []Fact{{"Program", p.Name + " (process " + strconv.Itoa(int(p.PID)) + ")"}}
	add := func(label, value string) {
		if value != "" {
			facts = append(facts, Fact{label, value})
		}
	}
	add("File", p.File.Path)
	if p.File.Exists && p.File.Program {
		add("Signature", Signature(p.File))
		add("The file says it is", Claim(p.File))
	}
	if p.CommandHidden {
		add("Command", strings.ToUpper(model.Withheld(s.Elevated, false)[:1])+model.Withheld(s.Elevated, false)[1:])
	} else {
		add("Command", p.Command)
	}
	add("Runs as", p.User)
	if !p.Started.IsZero() {
		add("Running since", p.Started.Format("2 January 2006 at 15:04"))
	}
	if len(p.Services) > 0 {
		add(i18n.T("Services inside it"), strings.Join(p.Services, ", "))
	}
	return facts
}

const seeRunning = "You can see it in Task Manager (Ctrl + Shift + Esc) on the Details tab: right-click it and choose Open file location. "

var runningRules = []Rule{
	{
		ID: "running-altered", Area: model.RunningNow, Severity: High,
		Title: i18n.T("A running program was changed after its maker signed it"),
		Why:   i18n.T("A digital signature breaks if a single byte of the file changes. A running program that no longer matches its signature has been altered since it left its maker."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			for _, p := range once(s.Processes) {
				r.at(FileRef(p.File.Path))
				if p.File.Exists && p.File.Signature.Changed() {
					found = append(found, r.find(p.Name,
						"This running program carries a maker's signature, but the file no longer matches it. Something changed the file after it was signed. A damaged download or a badly made patch can do that, and so can unwanted code that hides inside another program.",
						i18n.T("Reinstall the program from its maker's website and scan the PC with your antivirus."), aboutProcess(s, p)...))
				}
			}
			return
		},
	},
	{
		ID: "running-system-name", Area: model.RunningNow, Severity: High,
		Title: i18n.T("A running program is named like a part of Windows, but is not where Windows keeps it"),
		Why:   i18n.T("Windows' own programs, such as svchost.exe, run from the Windows folder. A running program with one of those names from anywhere else is a classic disguise: in Task Manager it looks like one more piece of Windows."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			for _, p := range once(s.Processes) {
				r.at(FileRef(p.File.Path))
				if Disguised(p.File.Path, s.Folders) {
					found = append(found, r.find(p.Name,
						p.Name+" is the name of a part of Windows, and the real one runs from "+s.Folders.Windows+". This one is running from "+winpath.Dir(p.File.Path)+". A program that borrows a Windows name in another folder is usually trying not to be noticed."+stillMicrosoft(p.File),
						seeRunning+"Unless you started it yourself, treat it as suspect: scan the file with your antivirus and ask someone who knows Windows well.", aboutProcess(s, p)...))
				} else if of, ok := Lookalike(p.File.Path); ok {
					found = append(found, r.find(p.Name,
						p.Name+" is spelt almost like "+of+", a part of Windows, but it is not that file. Names one letter away from a Windows name are chosen to be misread.",
						seeRunning+"Unless you know what this program is, treat it as suspect: scan the file with your antivirus and ask someone who knows Windows well.", aboutProcess(s, p)...))
				}
			}
			return
		},
	},
	{
		ID: "running-temp-folder", Area: model.RunningNow, Severity: Medium,
		Title: i18n.T("A program is running from a temporary or download folder"),
		Why:   i18n.T("Installed software runs from Program Files. Temporary and download folders are where files land from the internet and where installers unpack. An installer or a portable tool you just opened runs from there for a while. Malware runs from there because any program may write to those folders."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			for _, p := range once(s.Processes) {
				r.at(FileRef(p.File.Path))
				kind, ok := Temporary(p.File.Path, s.Folders)
				if !ok {
					continue
				}
				f := r.find(p.Name,
					i18n.T("It is running from ")+kind+": "+p.File.Path+". An installer or a portable tool you opened a moment ago looks like this. So does something that was downloaded and started without being installed.",
					seeRunning+i18n.T("If you just ran an installer or a downloaded tool, this is it and nothing needs doing. If you do not recognise it, scan the file with your antivirus."), aboutProcess(s, p)...)
				if p.File.Exists && p.File.Program && !p.File.Signature.Trusted() {
					f.Severity = High
					f.Reason += " The file is also not signed by a known maker."
				}
				found = append(found, f)
			}
			return
		},
	},
	{
		ID: "running-antivirus-objects", Area: model.RunningNow, Severity: High,
		Title: i18n.T("The antivirus objects to a command that is running"),
		Why:   i18n.T("LazaScope hands the commands that scripting tools were started with to the antivirus installed on this PC and asks what it makes of them. When the antivirus calls them harmful, that is the judgement of a product made for exactly this. An antivirus can still be wrong, most often about tools people write themselves."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			for _, p := range s.Processes {
				if !p.Said.Harmful || p.Self {
					continue
				}
				r.at(ProcessRef(p.PID))
				reason := Engine(s) + ", asked just now, calls the commands " + p.Name + " was started with harmful"
				if p.Said.Name != "" {
					reason += " and names them " + p.Said.Name
				}
				found = append(found, r.find(p.Name, reason+". That is the antivirus's judgement and not LazaScope's. The antivirus watches scripting tools as they work, so it has most likely stopped these commands already. That they are still on a running program's line is what makes this worth looking at first.",
					i18n.T("Look at what started it: the Running now page shows each program under the one that launched it. Open Windows Security from the Start menu, look at Protection history and run a full scan."), aboutProcess(s, p)...))
			}
			return
		},
	},
	{
		ID: "running-scrambled-command", Area: model.RunningNow, Severity: Medium,
		Title: i18n.T("A scripting tool is running a scrambled command"),
		Why:   i18n.T("PowerShell, cmd and their relatives run whatever they are handed. Attackers hide their instructions by encoding them, breaking the words up, or fetching the real commands from the internet. Some developer and management tools pass encoded commands too, so this is worth a look rather than proof of anything."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			// A shell that only passes a scrambled command on to the tool it
			// starts shows the same text twice. The tool that carries it out
			// is the one to flag, so the messenger is left out.
			carried := map[uint32][]string{} // by parent: what its flagged children were told
			for _, p := range s.Processes {
				if p.CommandHidden || p.Command == "" || p.Self || len(Scrambled(p.File.Path, p.Command)) == 0 {
					continue
				}
				if told := told(p.Command); told != "" {
					carried[p.Parent] = append(carried[p.Parent], told)
				}
			}
			for _, p := range s.Processes {
				r.at(ProcessRef(p.PID))
				if p.CommandHidden || p.Command == "" || p.Self {
					continue
				}
				signs := Scrambled(p.File.Path, p.Command)
				if len(signs) == 0 || relays(p.Command, carried[p.PID]) {
					continue
				}
				f := r.find(p.Name,
					p.Name+" carries out whatever commands it is given, and the commands it is running now are hidden. "+strings.Join(signs, " ")+" Some developer tools and management software do this for ordinary reasons.",
					i18n.T("Look at what started it: the Running now page shows each program under the one that launched it. If it belongs to a tool you use, nothing needs doing. If nothing explains it, show it to someone who knows Windows well."), aboutProcess(s, p)...)
				if Hidden(p.File.Path, p.Command) {
					f.Reason += " It was also told to work without showing a window."
				}
				found = append(found, f)
			}
			return
		},
	},
}

// told returns what a command line tells its program, without the program
// itself, with every run of spaces made one.
func told(command string) string {
	text := strings.TrimSpace(command)
	if strings.HasPrefix(text, `"`) {
		if end := strings.IndexByte(text[1:], '"'); end >= 0 {
			text = text[end+2:]
		}
	} else if cut := strings.IndexAny(text, " \t"); cut >= 0 {
		text = text[cut:]
	} else {
		text = ""
	}
	return strings.Join(strings.Fields(text), " ")
}

// relays reports whether a command line holds, word for word, everything
// one of the programs it started was told. Such a program is a messenger.
func relays(command string, children []string) bool {
	whole := strings.Join(strings.Fields(command), " ")
	for _, child := range children {
		if len(child) >= 24 && strings.Contains(whole, child) {
			return true
		}
	}
	return false
}

// once returns the running programs with each program file kept one time,
// so that a browser with forty processes makes one finding and not forty.
func once(list []model.Process) []model.Process {
	seen := map[string]bool{}
	var kept []model.Process
	for _, p := range list {
		// The program taking the look is listed like any other but not judged:
		// whoever is reading this started it.
		if p.File.Path == "" || p.Self {
			continue
		}
		if key := strings.ToLower(p.File.Path); !seen[key] {
			seen[key] = true
			kept = append(kept, p)
		}
	}
	return kept
}

var connectionRules = []Rule{
	{
		ID: "listener-unsigned", Area: model.Connections, Severity: Medium,
		Title: i18n.T("An unsigned program is waiting for incoming connections"),
		Why:   i18n.T("A program that waits for connections lets other devices start a conversation with this PC. That is how file sharing and games work, and it is also how a back door works. When the program has no valid signature, nobody can say who made it."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			// One finding for each program, with all the ports it waits on.
			ports := map[string][]string{}
			first := map[string]model.Connection{}
			var order []string
			for _, c := range s.Connections {
				if !c.Listening || c.Protocol != "TCP" || c.Reach == model.ThisPC {
					continue // ports only this PC can reach are no door for anyone else
				}
				if !c.File.Exists || !c.File.Program || c.File.Signature.Trusted() {
					continue
				}
				key := strings.ToLower(c.File.Path)
				if _, seen := first[key]; !seen {
					first[key] = c
					order = append(order, key)
				}
				port := strconv.Itoa(c.LocalPort)
				if use := netconn.Service(c.LocalPort); use != "" {
					port += " (" + use + ")"
				}
				if !contains(ports[key], port) {
					ports[key] = append(ports[key], port)
				}
			}
			for _, key := range order {
				c := first[key]
				r.at(ListenRef(c.File.Path))
				found = append(found, r.find(c.Process,
					c.Process+" is waiting for other devices to connect to it on port "+list(ports[key], 6)+", and it is not signed by a known maker. Programs you build or run for development often look like this. So does a back door.",
					i18n.T("If this is a program you run on purpose, such as a game server or a development tool, nothing needs doing. If you do not recognise it, find it on the Running now page and look at what started it. Windows Firewall decides whether other devices can actually reach it."),
					Fact{"Program", c.Process + " (process " + strconv.Itoa(int(c.PID)) + ")"}, Fact{"File", c.File.Path}, Fact{"Signature", Signature(c.File)},
					Fact{"Waits on", c.Protocol + " port " + strings.Join(ports[key], ", ")}, Fact{"The file says it is", Claim(c.File)}))
			}
			return
		},
	},
}

func contains(values []string, value string) bool {
	for _, have := range values {
		if have == value {
			return true
		}
	}
	return false
}
