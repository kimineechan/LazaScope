package rules

import (
	"lazascope/internal/i18n"
	"strconv"
	"strings"
	"time"

	"lazascope/internal/model"
	"lazascope/internal/sigcheck"
)

// DefenderInCharge reports whether Microsoft Defender is the antivirus at
// work. When another antivirus is, Defender stands aside, and its own
// protections do not apply.
func DefenderInCharge(s *model.Snapshot) bool { return s.Guard.RealTime == model.Yes }

// Applies reports whether a defence matters on this PC.
func Applies(s *model.Snapshot, d model.Defence) bool { return !d.Defender || DefenderInCharge(s) }

// BackedUp reports whether the PC shows a copy of the account's files being
// kept: File History in the last 30 days, folders OneDrive copies, or a
// backup program.
func BackedUp(s *model.Snapshot) bool {
	b := s.Backups
	recent := !b.FileHistory.IsZero() && s.Taken.Sub(b.FileHistory) < 30*24*time.Hour
	return recent || len(b.OneDrive) > 0 || len(b.Programs) > 0
}

// DeviceRef refers to one record of a program using the camera or the microphone.
func DeviceRef(index int) string { return "device:" + strconv.Itoa(index) }

var defenceRules = []Rule{
	{
		ID: "defences-off", Area: model.Protection, Severity: Low, Topic: "defences",
		Title: i18n.T("Protections this PC already has are switched off"),
		Why:   i18n.T("Windows and Microsoft Defender come with protections that stay off until someone switches them on, or that someone switched off. Each costs nothing and is already on the PC."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			var off []string
			var facts []Fact
			for _, d := range s.Defences {
				if d.On == model.No && Applies(s, d) {
					off = append(off, d.Name)
					facts = append(facts, Fact{d.Name, "Off"})
				}
			}
			if len(off) == 0 {
				return
			}
			found = append(found, r.find(count(len(off), "protection", "protections")+" off",
				"This PC already has these protections, but they are switched off: "+listed(off)+".",
				"The Protections to switch on page, reached from the Overview, says what each one does and where to switch it on. Most are a switch in Windows Security.", facts...))
			return
		},
	},
	{
		ID: "ransomware-not-ready", Area: model.Protection, Severity: Medium, Topic: "ransomware",
		Title: i18n.T("Nothing would stop ransomware, or give the files back"),
		Why:   i18n.T("Ransomware locks every file it can reach and asks for money to unlock them. Two things limit the harm: Controlled folder access, which stops unknown programs from changing the folders that matter, and a copy of the files kept somewhere else. This PC shows neither."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			guarded := false
			for _, d := range s.Defences {
				if d.Key == "cfa" && d.On == model.Yes && Applies(s, d) {
					guarded = true
				}
			}
			if guarded || BackedUp(s) || len(s.Defences) == 0 {
				return
			}
			found = append(found, r.find("Files and backups",
				i18n.T("Controlled folder access is off, and LazaScope found no copy of the account's files being kept: File History has not run in the last 30 days, OneDrive does not copy Documents, Desktop or Pictures, and no backup program is installed. If ransomware got in, there would be nothing to go back to."),
				"Keep a copy of your files somewhere ransomware cannot reach: File History to a drive you unplug afterwards, or OneDrive's folder backup. Then switch on Controlled folder access: Windows Security, Virus and threat protection, Ransomware protection.",
				Fact{i18n.T("Controlled folder access"), "Off"}, Fact{"Backups found", "None"}))
			return
		},
	},
	{
		ID: "device-in-use", Area: model.Accounts, Severity: Low, Topic: "devices",
		Title: i18n.T("A program is using the camera or the microphone now"),
		Why:   i18n.T("Windows notes when each program starts and stops using the camera or the microphone. One that has started and not stopped is using it now: a video call, or something else."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			for i, d := range s.DeviceUses {
				if !d.InUse() {
					continue
				}
				r.at(DeviceRef(i))
				name := deviceApp(d)
				found = append(found, r.find(name+", "+d.Device,
					name+" has been using the "+d.Device+" since "+d.Start.In(location(s)).Format("15:04 on 2 January")+", going by Windows' own record.",
					"If you are not on a call or recording, close the program. To see and change which programs may use the "+d.Device+", open Settings, then Privacy and security (Privacy on Windows 10), then "+strings.ToUpper(d.Device[:1])+d.Device[1:]+".",
					Fact{"Program", d.App}, Fact{"Device", d.Device}))
			}
			return
		},
	},
	{
		ID: "device-used-unsigned", Area: model.Accounts, Severity: Medium,
		Title: i18n.T("A program with no maker's signature used the camera or the microphone"),
		Why:   i18n.T("Spying tools watch and listen through the camera and the microphone. The video-call and recording programs people use are signed by their makers; a program without a signature that used either is worth a look."),
		check: func(s *model.Snapshot, r *Rule) (found []Finding) {
			for i, d := range s.DeviceUses {
				f := d.File
				if !d.Program || !f.Exists || !f.Program || f.Signature.Status == sigcheck.Signed || f.Signature.Status == sigcheck.Unknown ||
					s.Taken.Sub(d.Start) > 90*24*time.Hour {
					continue
				}
				r.at(DeviceRef(i))
				finding := r.find(winpathBase(d.App)+", "+d.Device,
					d.App+" used the "+d.Device+", last on "+d.Start.In(location(s)).Format("2 January 2006 at 15:04")+", and its file carries no maker's signature.",
					"If you do not know this program, take its permission away: Settings, Privacy and security (Privacy on Windows 10), "+strings.ToUpper(d.Device[:1])+d.Device[1:]+". Then find where it came from under 03 Start-up and 04 Running, and scan the PC with your antivirus.",
					Fact{"Program", d.App}, Fact{"Device", d.Device}, Fact{"File", f.Path}, Fact{"Signature", Signature(f)})
				if d.Device == "camera" {
					finding.Attack = []string{"T1125"}
				} else {
					finding.Attack = []string{"T1123"}
				}
				found = append(found, finding)
			}
			return
		},
	},
}

// deviceApp names the program in a record, by its file's name or its app's.
func deviceApp(d model.DeviceUse) string {
	if d.Program {
		return winpathBase(d.App)
	}
	name, _, _ := strings.Cut(d.App, "_")
	return name
}

func winpathBase(path string) string {
	if i := strings.LastIndex(path, `\`); i >= 0 {
		return path[i+1:]
	}
	return path
}

// count says a number of things in words, such as "3 protections".
func count(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}
