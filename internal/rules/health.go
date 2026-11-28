package rules

import (
	"fmt"
	"lazascope/internal/i18n"
	"strconv"
	"strings"
	"time"

	"lazascope/internal/model"
	"lazascope/internal/netconn"
)

// Day writes a date the way the rest of LazaScope does, in the time zone
// the look was taken in.
func Day(s *model.Snapshot, when time.Time) string {
	return when.In(s.Taken.Location()).Format("2 January 2006")
}

// Moment writes a date with the time of day.
func Moment(s *model.Snapshot, when time.Time) string {
	return when.In(s.Taken.Location()).Format("2 January 2006 at 15:04")
}

// Ago says how long before the look something happened, counted in days
// of the calendar: late last night is yesterday, not today.
func Ago(s *model.Snapshot, when time.Time) string {
	zone := s.Taken.Location()
	midnight := func(t time.Time) time.Time {
		t = t.In(zone)
		return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, zone)
	}
	// Half a day is added before the division, because a day on which the
	// clocks change is an hour shorter or longer than the rest.
	switch days := int((midnight(s.Taken).Sub(midnight(when)).Hours() + 12) / 24); {
	case days <= 0:
		return "today"
	case days == 1:
		return "yesterday"
	default:
		return strconv.Itoa(days) + " days ago"
	}
}

// Size writes a number of bytes the way File Explorer does.
func Size(bytes uint64) string {
	const gb = 1 << 30
	switch {
	case bytes >= 10*gb:
		return strconv.FormatUint(bytes/gb, 10) + " GB"
	case bytes >= gb:
		return strconv.FormatFloat(float64(bytes)/gb, 'f', 1, 64) + " GB"
	}
	return strconv.FormatUint(bytes/(1<<20), 10) + " MB"
}

// SpaceRef refers to the free room on a drive.
func SpaceRef(drive string) string { return "space:" + strings.ToUpper(drive) }

// each returns the different values of a list, in the order first met.
func each(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

// stopCode writes a blue screen's code with its name.
func stopCode(c model.Crash) string {
	text := fmt.Sprintf("0x%X", c.Code)
	if c.Name != "" {
		text += ", " + c.Name
	}
	return text
}

const period = "in the last 90 days"

var healthRules = []Rule{
	{
		ID: "hardware-errors", Area: model.Health, Severity: Medium, Topic: "hardware",
		Title: i18n.T("The hardware has been reporting errors"),
		Why:   i18n.T("Processors, memory and other parts check themselves as they work, and Windows writes down every error they report, including the ones that were corrected on the spot. A healthy PC reports none. A part that keeps reporting them is usually failing, overheating or being run harder than it was made for, and it is a common cause of crashes that look like software trouble."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			faults := s.Condition.Hardware
			if len(faults) == 0 {
				return
			}
			var parts, spots []string
			fatal := 0
			var facts []Fact
			for i, fault := range faults {
				parts, spots = append(parts, fault.Part), append(spots, fault.Where)
				if fault.Fatal {
					fatal++
				}
				if i < 6 {
					facts = append(facts, Fact{Moment(s, fault.When), fault.Words})
				}
			}
			parts, spots = each(parts), each(spots)
			reason := "Windows logged " + plural(len(faults), "hardware error", "hardware errors") + " " + i18n.T(period) + ", the latest on " + Day(s, faults[0].When) + "."
			switch {
			case len(parts) == 1 && len(faults) == 1:
				reason += " It was reported by " + parts[0] + "."
			case len(parts) == 1:
				reason += " Every one was reported by " + parts[0] + "."
			default:
				reason += " They were reported by " + list(parts, 3) + "."
			}
			if len(faults) >= 3 && len(spots) > 0 && len(spots) <= 2 {
				reason += " The records all name the same spot (" + list(spots, 2) + "), which points at one faulty part and not at chance."
			}
			switch {
			case fatal == 0 && len(faults) == 1:
				reason += " It was corrected as it happened, so nothing was lost at that moment."
			case fatal == 0:
				reason += " All were corrected as they happened, so nothing was lost at those moments."
			default:
				reason += " " + strconv.Itoa(fatal) + " could not be corrected, and Windows had to stop."
			}
			reason += " A healthy PC logs none."
			if crashes := len(s.Condition.Crashes); crashes > 0 {
				reason += " This PC also stopped with a blue screen " + plural(crashes, "time", "times") + " in the same period, which fits."
			}
			f := r.find(plural(len(faults), "hardware error", "hardware errors"), reason,
				i18n.T("Back up anything you cannot afford to lose. Make sure the vents are clear, and undo any overclocking or undervolting. Check the PC maker's website for a newer BIOS (the built-in software that starts the PC). If the errors keep coming, the part needs repairing or replacing, under warranty if the PC still has one. The maker will want to see these records: they are in Event Viewer under Windows Logs > System, with the source WHEA-Logger."), facts...)
			switch {
			case fatal > 0:
				f.Severity = High
			case len(faults) < 3:
				f.Severity = Low
			}
			return []Finding{f}
		},
	},
	{
		ID: "blue-screens", Area: model.Health, Severity: Medium, Topic: "crashes",
		Title: i18n.T("Windows has been stopping with a blue screen"),
		Why:   i18n.T("A blue screen is Windows stopping itself because carrying on could damage data. One can be a passing fault. Several mean something is wrong underneath: a failing part, a faulty driver, or now and then software that reaches into the core of Windows."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			crashes := s.Condition.Crashes
			if len(crashes) == 0 {
				return
			}
			var codes []string
			var facts []Fact
			for i, crash := range crashes {
				codes = append(codes, strconv.Itoa(int(crash.Code)))
				if i < 8 {
					facts = append(facts, Fact{Moment(s, crash.When), "Stop code " + stopCode(crash)})
				}
			}
			different := len(each(codes))
			reason := "Windows stopped with a blue screen " + plural(len(crashes), "time", "times") + " " + i18n.T(period) + ", the latest on " + Day(s, crashes[0].When) + " (stop code " + stopCode(crashes[0]) + ")."
			switch {
			case len(crashes) == 1:
				reason += " One crash can be a passing fault."
			case different >= 3:
				reason += " The stop code differs from crash to crash (" + strconv.Itoa(different) + " different ones). That is typical of failing hardware, such as memory or the processor. A faulty driver tends to give the same code each time."
			case different == 1:
				reason += " Every crash gave the same stop code, which more often points at one driver or one program than at failing hardware."
			}
			if len(s.Condition.Hardware) > 0 {
				reason += " Windows also logged hardware errors in the same period. Start with those."
			}
			f := r.find(plural(len(crashes), "blue screen", "blue screens"), reason,
				i18n.T("Install any waiting Windows updates and the newest drivers from the PC maker. Then test the memory: search the Start menu for Windows Memory Diagnostic. If hardware errors are listed on this page, deal with those first. A repair shop or the PC maker can read the saved crash file, C:\\Windows\\MEMORY.DMP, to name the cause."), facts...)
			if len(crashes) == 1 {
				f.Severity = Low
			}
			return []Finding{f}
		},
	},
	{
		ID: "disk-faults", Area: model.Health, Severity: Medium, Topic: "disk",
		Title: i18n.T("A disk has reported faults"),
		Why:   i18n.T("A disk that can no longer read part of itself, or whose filing system is damaged, says so in Windows' log before it fails outright. That warning is the time to copy files off it."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			faults := s.Condition.Disk
			if len(faults) == 0 {
				return
			}
			var facts []Fact
			failing := false
			for i, fault := range faults {
				failing = failing || fault.Fatal
				if i < 6 {
					facts = append(facts, Fact{Moment(s, fault.When), fault.Words})
				}
			}
			f := r.find(plural(len(faults), "disk fault", "disk faults"),
				"Windows logged "+plural(len(faults), "disk fault", "disk faults")+" "+period+", the latest on "+Day(s, faults[0].When)+": "+faults[0].Words+" A disk that reports bad spots or a damaged filing system is one to stop trusting.",
				i18n.T("Copy your files somewhere else now, before anything else. Then let Windows check the disk: in File Explorer, right-click the drive and choose Properties > Tools > Check. If the faults keep coming, replace the disk."), facts...)
			if failing {
				f.Severity = High
				f.Reason += " One record says the disk itself expects to fail."
			}
			return []Finding{f}
		},
	},
	{
		ID: "sudden-stops", Area: model.Health, Severity: Low, Topic: "stops",
		Title: i18n.T("The PC has gone off without shutting down"),
		Why:   i18n.T("When a PC loses power, freezes and is held down by its power button, or overheats and cuts out, Windows notes at the next start that it was never shut down. Now and then is normal for a laptop. Often is a sign of overheating or a failing battery or power supply, and each sudden stop risks damaging whatever was being saved."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			stops := s.Condition.PowerCuts
			if len(stops) < 3 {
				return
			}
			var facts []Fact
			for i, when := range stops {
				if i < 6 {
					facts = append(facts, Fact{i18n.T("Noticed when Windows started"), Moment(s, when)})
				}
			}
			return []Finding{r.find(plural(len(stops), "sudden stop", "sudden stops"),
				i18n.T("This PC went off without shutting down ")+plural(len(stops), "time", "times")+" "+period+", with no blue screen. The power went, the battery ran out, the PC froze and was held down by its power button, or it overheated and cut out. The latest was noticed when Windows started on "+Day(s, stops[0])+".",
				i18n.T("If you remember holding the power button down, that is all this is. If the PC goes off by itself when it is working hard, it is probably overheating: clear the vents and stand it on a hard surface."), facts...)}
		},
	},
	{
		ID: "disk-nearly-full", Area: model.Health, Severity: Low,
		Title: i18n.T("The Windows disk is nearly full"),
		Why:   i18n.T("Windows needs free room for updates and for its own working files. With little left, updates fail, which leaves security holes open, and the PC becomes slow and unreliable."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			for _, drive := range s.Condition.Drives {
				if !strings.HasPrefix(strings.ToUpper(s.Folders.Windows), strings.ToUpper(drive.Letter)) || drive.Size == 0 {
					continue
				}
				const gb = 1 << 30
				if drive.Free >= 20*gb || drive.Free*10 >= drive.Size {
					continue
				}
				r.at(SpaceRef(drive.Letter))
				found = append(found, r.find("Drive "+drive.Letter,
					"Drive "+drive.Letter+", which holds Windows, has "+Size(drive.Free)+" free of "+Size(drive.Size)+". Windows updates need several gigabytes of free room to install.",
					i18n.T("Open Settings > System > Storage to see what takes the room, and let Windows clean up what is not needed. Empty the Recycle Bin and the Downloads folder first."),
					Fact{"Free", Size(drive.Free)}, Fact{"Size", Size(drive.Size)}))
			}
			return
		},
	},
	{
		ID: "log-cleared", Area: model.Health, Severity: Medium, Topic: "wiped",
		Title: i18n.T("A Windows log was wiped"),
		Why:   i18n.T("The logs are where Windows writes down what happened on the PC: sign-ins, crashes, what was installed. Clearing one is rare in everyday use. Some clean-up tools do it, and so does someone who wants to remove the traces of what they did."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			wipes := s.Condition.Wiped
			if len(wipes) == 0 {
				return
			}
			var facts []Fact
			var logs []string
			for i, wipe := range wipes {
				logs = append(logs, wipe.Log)
				if i < 6 {
					by := ""
					if wipe.By != "" {
						by = ", by the account " + wipe.By
					}
					facts = append(facts, Fact{Moment(s, wipe.When), "The " + wipe.Log + " log was cleared" + by})
				}
			}
			latest := wipes[0]
			reason := "The " + latest.Log + " log was cleared on " + Day(s, latest.When)
			if latest.By != "" {
				reason += " by the account " + latest.By
			}
			reason += "."
			if len(wipes) > 1 {
				reason = plural(len(wipes), "time", "times") + " " + i18n.T(period) + " a Windows log was cleared (" + list(each(logs), 4) + "). The latest: " + strings.ToLower(reason[:1]) + reason[1:]
			}
			return []Finding{r.find(plural(len(wipes), "cleared log", "cleared logs"),
				reason+" Whatever the log held before that moment is gone, including anything LazaScope would have read from it.",
				i18n.T("If you ran a clean-up tool or cleared the log yourself, nothing needs doing. If not, ask who else uses this PC, and look at what else here dates from around that time."), facts...)}
		},
	},
}

// TestSample reports whether a name Defender gave is that of the harmless
// sample antivirus makers agree on for testing.
func TestSample(threat string) bool {
	lower := strings.ToLower(threat)
	return strings.Contains(lower, "mptest") || strings.Contains(lower, "eicar")
}

// sourced says, for a detection that came from a program asking the
// antivirus, which program asked.
func sourced(d model.Detection) string {
	if !strings.EqualFold(d.Source, "AMSI") || d.Process == "" {
		return ""
	}
	return ". Found when " + d.Process + " asked the antivirus about some content"
}

// The rules about what Microsoft Defender's own log says.
var historyRules = []Rule{
	{
		ID: "defender-found-something", Area: model.Protection, Severity: Medium, Topic: "detections",
		Title: i18n.T("Microsoft Defender found something not long ago"),
		Why:   i18n.T("When the antivirus stops a file, it did its job, and the file is usually gone. It is still worth knowing that it happened and where the file came from, because whatever brought one unwanted file may bring another. Antivirus is also sometimes wrong, most often about tools people build themselves."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			g := s.Guard
			if !g.HistoryRead || len(g.Detections) == 0 {
				return
			}
			// The makers of antivirus agree on a harmless sample for testing
			// that an antivirus works. Finding it is not finding anything.
			var real []model.Detection
			for _, d := range g.Detections {
				if !TestSample(d.Threat) {
					real = append(real, d)
				}
			}
			if len(real) == 0 {
				var tests []Fact
				for i, d := range g.Detections {
					if i < 8 {
						tests = append(tests, Fact{"Found on " + Moment(s, d.When), d.Threat + sourced(d)})
					}
				}
				f := r.find(i18n.T("A test of the antivirus"), "Microsoft Defender's own log shows "+plural(len(g.Detections), "detection", "detections")+" "+period+", and each is the harmless sample that antivirus makers agree on for checking that an antivirus works. Somebody, or some program, tested the antivirus on this PC, and it passed. Nothing harmful was found.",
					i18n.T("Nothing needs doing. LazaScope's own tests do this, and so do some security tools."), tests...)
				f.Severity = Low
				return []Finding{f}
			}
			tested := len(g.Detections) - len(real)
			g.Detections = real
			var facts []Fact
			for i, d := range g.Detections {
				if i >= 8 {
					break
				}
				text := d.Threat
				if d.Severity != "" {
					text += " (" + d.Severity + ")"
				}
				if d.Path != "" {
					text += ", in " + d.Path
				}
				if d.Action != "" {
					text += ". Defender's action: " + d.Action
				}
				facts = append(facts, Fact{"Found on " + Moment(s, d.When), text + sourced(d)})
			}
			if tested > 0 {
				facts = append(facts, Fact{"Left out", plural(tested, "detection", "detections") + " of the harmless sample used to test an antivirus"})
			}
			latest := g.Detections[0]
			what := latest.Threat
			if latest.Path != "" {
				what += " in " + latest.Path
			}
			reason := i18n.T("Microsoft Defender's own log shows that it found ") + what + " on " + Day(s, latest.When) + " (" + Ago(s, latest.When) + ")."
			if len(g.Detections) > 1 {
				reason = "Microsoft Defender's own log shows " + strconv.Itoa(len(g.Detections)) + " detections " + i18n.T(period) + ". The latest was " + what + ", on " + Day(s, latest.When) + " (" + Ago(s, latest.When) + ")."
			}
			if latest.Action != "" {
				reason += " Defender's action was: " + latest.Action + "."
			}
			reason += " A detection means the antivirus did its job. It does not mean that anything unwanted is on the PC now."
			subject := latest.Threat
			if len(g.Detections) > 1 {
				subject = strconv.Itoa(len(g.Detections)) + " detections"
			}
			f := r.find(subject, reason,
				openSecurity+i18n.T("Under Virus and threat protection > Protection history, check that each item says Quarantined or Removed. Think back to what was downloaded or opened that day. If a name mentions a password stealer (PWS, Stealer, Spy), change your important passwords from another device. Antivirus is sometimes wrong about programs people build themselves and about tools that change Windows settings, so a detection can be a false alarm."), facts...)
			if int(s.Taken.Sub(latest.When).Hours()/24) > 30 {
				f.Severity = Low
			}
			return []Finding{f}
		},
	},
	{
		ID: "defender-exclusions-logged", Area: model.Protection, Severity: Medium, Topic: "exclusions",
		Title: i18n.T("Microsoft Defender's log shows places it was told to skip"),
		Why:   i18n.T("Windows hides the list of what Microsoft Defender skips from programs without administrator rights, so that malware cannot read where it would be safe. Defender's own log is not hidden, and it records every time something is added to that list or taken off it."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			g := s.Guard
			if g.ExclusionsVisible || len(g.LoggedExclusions) == 0 {
				return // with the list itself in hand, the rule for the list speaks
			}
			var facts []Fact
			var values []string
			broad := ""
			for _, e := range g.LoggedExclusions {
				facts = append(facts, Fact{e.Kind, e.Value + ", added on " + Moment(s, e.When)})
				values = append(values, e.Value)
				if wide(e.Exclusion, s.Folders) && broad == "" {
					broad = e.Value
				}
			}
			f := r.find(plural(len(values), i18n.T("exclusion in Defender's log"), i18n.T("exclusions in Defender's log")),
				i18n.T("The list of what Microsoft Defender skips cannot be read without administrator rights. Defender's own log can, and it shows this being added to the list and not taken off since: ")+list(values, 5)+". Anything placed there, or matching it, is not checked. The log does not reach back for ever, so there may be older exclusions that it no longer shows.",
				openSecurity+i18n.T("Under Virus and threat protection > Manage settings > Exclusions you can see the list as it stands, and remove any you did not add yourself. Looking again as administrator shows the list here too."), facts...)
			if broad != "" {
				f.Severity = High
				f.Reason += " The exclusion " + broad + " is very wide: it covers places where downloads and temporary files land."
			}
			return []Finding{f}
		},
	},
	{
		ID: "defender-switched-off", Area: model.Protection, Severity: Low, Topic: "realtime",
		Title: i18n.T("Defender's real-time protection was switched off for a while"),
		Why:   i18n.T("Real-time protection is the part of the antivirus that checks files as they are opened. People switch it off to install something the antivirus objects to. Malware tries to switch it off for the same reason, and Windows switches it back on by itself after a while."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			g := s.Guard
			// An old switching off and on again is history, not news.
			if len(g.SwitchedOff) == 0 || !defenderInUse(g) || s.Taken.Sub(g.SwitchedOff[0]) > 30*24*time.Hour {
				return
			}
			var facts []Fact
			for i, when := range g.SwitchedOff {
				if i < 6 {
					facts = append(facts, Fact{"Switched off", Moment(s, when)})
				}
			}
			latest := g.SwitchedOff[0]
			reason := i18n.T("Microsoft Defender's log shows that its real-time protection was switched off on ") + Day(s, latest) + " (" + Ago(s, latest) + ")"
			if len(g.SwitchedOff) > 1 {
				reason += ", and " + plural(len(g.SwitchedOff)-1, "more time", "more times") + " " + i18n.T(period)
			}
			reason += "."
			if g.RealTime == model.Yes {
				reason += " It is on now."
			}
			return []Finding{r.find(i18n.T("Real-time protection"), reason+" While it was off, files were not checked as they were opened.",
				i18n.T("If you switched it off yourself, nothing needs doing. If you did not, look at what was installed or opened on that day, and run a full scan from Windows Security."), facts...)}
		},
	},
}

// The rules about where this PC's questions and web traffic go.
var networkRules = []Rule{
	{
		ID: "dns-set-by-hand", Area: model.Protection, Severity: Medium, Topic: "dns",
		Title: i18n.T("Website names are looked up through a server someone typed in"),
		Why:   i18n.T("Before a program can reach a website, the PC asks a name server (a DNS server) for the site's address. Whoever runs that server sees every name that is looked up, and can answer with the address of a fake copy. A PC normally asks whatever its router tells it to. Some people set a public service such as Cloudflare or Quad9 by hand. Malware has been known to set a server of its own."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			var odd []string
			var facts []Fact
			for _, server := range s.Guard.NameServers {
				// A server on the local network is the router or a filter someone
				// set up at home. A well-known public service is a choice.
				if !server.ByHand || netconn.Reach(server.Address) != model.Internet || netconn.Resolver(server.Address) != "" {
					continue
				}
				odd = append(odd, server.Address)
				facts = append(facts, Fact{"Name server", server.Address + ", typed in for the connection " + server.Connection})
			}
			if len(odd) == 0 {
				return
			}
			return []Finding{r.find(list(odd, 4),
				i18n.T("This PC is set by hand to ask ")+list(odd, 4)+" for the addresses of websites. That is not the router, and not one of the public services LazaScope knows by name (Cloudflare, Google, Quad9, OpenDNS, AdGuard). Whoever runs it can see which sites this PC looks up, and decides where each name leads.",
				i18n.T("If you, your workplace or your internet provider set this, nothing needs doing: filtering and privacy services work this way. If nobody did, set it back to automatic. On Windows 11: Settings > Network & internet, the connection's properties, DNS server assignment, Edit, Automatic (DHCP). On Windows 10: press Windows key + R, type ncpa.cpl, open the connection's Properties, then Internet Protocol Version 4 (TCP/IPv4), Properties, and choose Obtain DNS server address automatically; do the same for Version 6."), facts...)}
		},
	},
	{
		ID: "proxy-set", Area: model.Protection, Severity: Medium, Topic: "proxy",
		Title: i18n.T("Web traffic is sent through a go-between"),
		Why:   i18n.T("A proxy is a go-between: the browser and other programs hand their web traffic to it, and it passes the traffic on. Workplaces and schools use one to filter, and some ad blockers and security programs run one on the PC itself. Whatever sits in that place can read what passes through it, and with a certificate of its own on the PC it can read secure pages too. Unwanted software sets a proxy for exactly that reason."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			p := s.Guard.Proxy
			if p.Server == "" && p.Script == "" {
				return
			}
			var facts []Fact
			reason := ""
			if p.Server != "" {
				facts = append(facts, Fact{"Proxy", p.Server})
				reason = i18n.T("This account's web traffic is set to go through ") + p.Server + "."
				// A proxy on this PC itself is a program here. Say which, if it is waiting there.
				server := p.Server
				if cut := strings.Index(server, "="); cut >= 0 {
					if parts := strings.FieldsFunc(server[cut+1:], func(r rune) bool { return r == ';' || r == ' ' }); len(parts) > 0 {
						server = parts[0]
					}
				}
				host, port := netconn.HostPort(server)
				// Reach only calls an address "this PC": a name it cannot read
				// as an address counts as somewhere else.
				if strings.EqualFold(host, "localhost") || (host != "" && netconn.Reach(host) == model.ThisPC) {
					reason += " That address is this PC itself, so the go-between is a program running here."
					for _, c := range s.Connections {
						if c.Listening && c.Protocol == "TCP" && strconv.Itoa(c.LocalPort) == port && c.Process != "" {
							reason += " " + c.Process + " is waiting on that port."
							facts = append(facts, Fact{i18n.T("Waiting on that port"), c.Process}, Fact{"File", c.File.Path})
							break
						}
					}
				}
			}
			if p.Script != "" {
				facts = append(facts, Fact{"Set-up script", p.Script})
				if reason != "" {
					reason += " "
				}
				reason += "A script at " + p.Script + " decides which go-between is used for which site."
			}
			if p.AllUsers {
				reason += " The setting is one for every account on this PC."
			}
			subject := p.Server
			if subject == "" {
				subject = p.Script
			}
			return []Finding{r.find(subject, reason+" Whatever sits there can see the web traffic that passes through it.",
				i18n.T("If your workplace or school set this, or you run a filter or a debugging tool that works this way, nothing needs doing. If not, switch it off: open Settings > Network & Internet > Proxy, and turn off Use a proxy server and Use setup script. Then find out which program set it, starting with what is listed under Worth a look."), facts...)}
		},
	},
}
