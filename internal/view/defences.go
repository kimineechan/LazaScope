package view

import (
	"sort"
	"strconv"
	"strings"

	"lazascope/internal/model"
	"lazascope/internal/rules"
)

// defenceText says what each defence does and where to switch it on.
var defenceText = map[string][2]string{
	"pua": {"Stops programs that are not quite malware but behave badly: adware, toolbars and bundled extras that install themselves alongside what you wanted.",
		"Windows Security, App and browser control, Reputation-based protection settings, Potentially unwanted app blocking."},
	"smartscreen": {"Warns before opening a downloaded program that few people have run, which is how much new malware arrives.",
		"Windows Security, App and browser control, Reputation-based protection settings, Check apps and files."},
	"cfa": {"Ransomware protection: only programs Windows trusts may change the files in Documents, Pictures, Desktop and the other folders that matter. Anything else is stopped and reported.",
		"Windows Security, Virus and threat protection, Ransomware protection, Controlled folder access. A program you trust that gets stopped can be allowed on the same page."},
	"network": {"Stops any program on the PC, not only the browser, from reaching sites Microsoft knows serve scams and malware.",
		"There is no switch for it in Windows Security. In PowerShell run as administrator: Set-MpPreference -EnableNetworkProtection Enabled"},
	"cloud": {"Lets Defender ask Microsoft about a file it has not seen before, which catches new malware within seconds instead of after the next update.",
		"Windows Security, Virus and threat protection, Manage settings, Cloud-delivered protection."},
	"hvci": {"Memory integrity keeps the most trusted part of Windows walled off, so that a bad driver cannot be loaded into it. A few old drivers do not work with it; Windows says which before switching it on.",
		"Windows Security, Device security, Core isolation details, Memory integrity. It needs a restart."},
	"lsa": {"Guards the part of Windows that holds the passwords of signed-in accounts, so that tools that copy them out of memory fail.",
		"Windows Security, Device security, Core isolation details, Local Security Authority protection. It needs a restart. Older Windows 10 has no switch for it."},
	"samples": {"Lets Defender send Microsoft a copy of a suspicious program it has not seen before, never documents, so that it can be studied and blocked everywhere.",
		"Windows Security, Virus and threat protection, Manage settings, Automatic sample submission."},
	"drivers": {"Stops drivers that are known to have weaknesses from loading. Attackers bring such drivers along to switch antivirus off.",
		"Windows Security, Device security, Core isolation details, Microsoft Vulnerable Driver Blocklist."},
}

// defences lists the protections Windows and Defender have, and what the
// PC shows of backups: how ready it is for ransomware.
func (b *builder) defences() Page {
	s := b.s
	page := Page{
		Name: "Defences", Title: "Protections this PC already has",
		Intro:   "The protections that come with Windows and Microsoft Defender, whether each is on, and what the PC shows of backups. Everything here is free and already on the PC; most are one switch in Windows Security.",
		Columns: []Column{{"Check", 124}, {"Protection", 330}, {"How it stands", 0}},
	}
	for i, d := range s.Defences {
		row := Row{Ref: "defence:" + strconv.Itoa(i)}
		state := strings.ToUpper(d.On.String()[:1]) + d.On.String()[1:]
		switch {
		case !rules.Applies(s, d):
			row.Level, state = Plain, "Not in use: another antivirus is in charge"
		case d.On == model.Yes:
			row.Level, state = Fine, "On"
		case d.On == model.No:
			row.Level, state = Info, "Off"
		default:
			row.Level, state = Unknown, "Not known"
		}
		if d.Ransomware {
			state += ". Helps against ransomware"
		}
		row.Cells = []string{row.Level.String(), d.Name, state}
		text := defenceText[d.Key]
		lines := []Line{{Heading, d.Name}, {Text, text[0]}, {Heading, "How it stands"}, {Text, state + "."}}
		if d.On == model.No && rules.Applies(s, d) {
			lines = append(lines, Line{Heading, "How to switch it on"}, Line{Text, text[1]})
		}
		row.Detail = lines
		page.Rows = append(page.Rows, row)
	}
	// Backups, and the verdict on ransomware.
	bk := s.Backups
	var have []string
	if !bk.FileHistory.IsZero() {
		have = append(have, "File History last ran on "+bk.FileHistory.In(location(s)).Format("2 January 2006"))
	}
	if len(bk.OneDrive) > 0 {
		have = append(have, "OneDrive copies "+and(bk.OneDrive))
	}
	if len(bk.Programs) > 0 {
		have = append(have, "backup programs: "+strings.Join(bk.Programs, ", "))
	}
	backups := "None found"
	good := model.No
	if len(have) > 0 {
		backups, good = strings.Join(have, "; "), model.Yes
	}
	if !rules.BackedUp(s) && len(have) > 0 {
		good = model.NotKnown // File History, but not lately
	}
	row := b.topic("Copies of your files (backups)", backups, good,
		"A copy of your files kept somewhere else is what gets them back after ransomware, a dead disk or a theft. LazaScope looks for File History, OneDrive's backup of Documents, Desktop and Pictures, and backup programs it knows by name. It cannot see a copy you make by hand.", "backups")
	if good == model.No {
		row.Level, row.Cells[0] = Look, Look.String()
	}
	page.Rows = append(page.Rows, row)
	page.Rows = append(page.Rows, b.topic("Ready for ransomware", map[bool]string{true: "Not ready: see Worth a look", false: "Something limits the harm"}[len(b.byRef["ransomware"]) > 0],
		map[bool]model.Answer{true: model.No, false: model.Yes}[len(b.byRef["ransomware"]) > 0],
		"Controlled folder access stops ransomware changing your files; a backup gives them back if it does. Either one limits the harm.", "ransomware"))
	return page
}

// devices lists the programs that used the camera and the microphone, the
// latest first.
func (b *builder) devices() Page {
	s := b.s
	page := Page{
		Name: "Camera and microphone", Title: "Which programs used the camera and the microphone",
		Intro:   "Windows notes, for its privacy settings, when each program last started and stopped using the camera or the microphone. This is that record for this account, the latest first.",
		Columns: []Column{{"Check", 124}, {"Program", 300}, {"Device", 120}, {"Last used", 200}, {"Allowed", 0}},
	}
	order := make([]int, len(s.DeviceUses))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(i, j int) bool { return s.DeviceUses[order[i]].Start.After(s.DeviceUses[order[j]].Start) })
	for _, i := range order {
		d := s.DeviceUses[i]
		ref := rules.DeviceRef(i)
		row := Row{Ref: ref, Level: b.worst(ref), When: d.Start}
		if d.Program && d.File.Exists {
			row.Path = d.File.Path
		}
		last := d.Start.In(location(s)).Format("2006-01-02 15:04")
		if d.InUse() {
			last = "In use now, since " + d.Start.In(location(s)).Format("15:04")
		}
		name := d.App
		if d.Program {
			name = winpathBase(d.App)
		} else {
			name, _, _ = strings.Cut(d.App, "_")
		}
		allowed := map[model.Answer]string{model.Yes: "Yes", model.No: "No", model.NotKnown: "Not known"}[d.Allowed]
		check := ""
		if row.Level != Plain {
			check = row.Level.String()
		}
		row.Cells = []string{check, name, strings.ToUpper(d.Device[:1]) + d.Device[1:], last, allowed}
		lines := []Line{{Heading, name}, {Text, "Last started using the " + d.Device + " on " + d.Start.In(location(s)).Format("2 January 2006 at 15:04:05") + "."}}
		if !d.Stop.IsZero() && !d.InUse() {
			lines = append(lines, Line{Text, "Stopped at " + d.Stop.In(location(s)).Format("15:04:05") + ", after " + d.Stop.Sub(d.Start).Round(1e9).String() + "."})
		}
		if d.Program {
			lines = append(lines, Line{Text, "Program:"}, Line{Command, d.App})
			lines = b.file(lines, d.File)
		} else {
			lines = append(lines, Line{Text, "An app from the Microsoft Store: " + d.App + "."})
		}
		lines = b.said(lines, ref)
		row.Detail = lines
		page.Rows = append(page.Rows, row)
	}
	return page
}

func winpathBase(path string) string {
	if i := strings.LastIndex(path, `\`); i >= 0 {
		return path[i+1:]
	}
	return path
}
