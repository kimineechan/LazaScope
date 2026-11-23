package rules

import (
	"strings"
	"testing"
	"time"

	"lazascope/internal/model"
)

// Made-up records of the kinds Windows' own log holds.

func coreError(daysAgo int, spot string, fatal bool) model.Fault {
	return model.Fault{When: now.AddDate(0, 0, -daysAgo), Fatal: fatal, Part: "the processor", Where: spot, ID: 19,
		Words: "A corrected hardware error has occurred. Reported by component: Processor Core. Error Type: Internal parity error. Processor " + spot + "."}
}

func crash(daysAgo int, code uint32, name string) model.Crash {
	return model.Crash{When: now.AddDate(0, 0, -daysAgo), Code: code, Name: name}
}

func found(daysAgo int, threat, path, action string) model.Detection {
	return model.Detection{When: now.AddDate(0, 0, -daysAgo), Threat: threat, Severity: "Severe", Category: "Trojan", Path: path, Action: action}
}

func logged(daysAgo int, kind, value string) model.LoggedExclusion {
	return model.LoggedExclusion{When: now.AddDate(0, 0, -daysAgo), Exclusion: model.Exclusion{Kind: kind, Value: value}}
}

func condition(do func(c *model.Condition)) func(*model.Snapshot) {
	return func(s *model.Snapshot) { do(&s.Condition) }
}

func guard(do func(g *model.Guard)) func(*model.Snapshot) {
	return func(s *model.Snapshot) { do(&s.Guard) }
}

func init() {
	changes = append(changes, []change{
		// PC health: hardware.
		{"the processor reported one error that was corrected", condition(func(c *model.Condition) { c.Hardware = []model.Fault{coreError(12, "APIC ID 12", false)} }), "hardware-errors:low"},
		{"one processor core reported eleven corrected errors", condition(func(c *model.Condition) {
			for i := 0; i < 11; i++ {
				c.Hardware = append(c.Hardware, coreError(9+i*7, []string{"APIC ID 12", "APIC ID 13"}[i%2], false))
			}
		}), "hardware-errors:medium"},
		{"a hardware error that Windows could not correct", condition(func(c *model.Condition) { c.Hardware = []model.Fault{coreError(2, "APIC ID 4", true)} }), "hardware-errors:high"},
		{"corrected errors from memory and from a PCI Express part", condition(func(c *model.Condition) {
			c.Hardware = []model.Fault{
				{When: now.AddDate(0, 0, -1), Part: "the memory", ID: 47, Words: "A corrected hardware error has occurred. Component: Memory."},
				{When: now.AddDate(0, 0, -3), Part: "a part on the PCI Express bus, such as a graphics card, an SSD or a network card", ID: 17, Words: "A corrected hardware error has occurred. Component: PCI Express Root Port."},
				{When: now.AddDate(0, 0, -5), Part: "the memory", ID: 47, Words: "A corrected hardware error has occurred. Component: Memory."},
			}
		}), "hardware-errors:medium"},

		// PC health: crashes.
		{"one blue screen", condition(func(c *model.Condition) { c.Crashes = []model.Crash{crash(30, 0x50, "PAGE_FAULT_IN_NONPAGED_AREA")} }), "blue-screens:low"},
		{"five blue screens, each with a different stop code", condition(func(c *model.Condition) {
			c.Crashes = []model.Crash{crash(1, 0x50, "PAGE_FAULT_IN_NONPAGED_AREA"), crash(2, 0x3B, "SYSTEM_SERVICE_EXCEPTION"), crash(2, 0x1E, "KMODE_EXCEPTION_NOT_HANDLED"), crash(5, 0x20001, "HYPERVISOR_ERROR"), crash(9, 0x777, "")}
		}), "blue-screens:medium"},
		{"three blue screens with the same stop code", condition(func(c *model.Condition) {
			c.Crashes = []model.Crash{crash(1, 0xD1, "DRIVER_IRQL_NOT_LESS_OR_EQUAL"), crash(4, 0xD1, "DRIVER_IRQL_NOT_LESS_OR_EQUAL"), crash(8, 0xD1, "DRIVER_IRQL_NOT_LESS_OR_EQUAL")}
		}), "blue-screens:medium"},
		{"hardware errors and blue screens together", condition(func(c *model.Condition) {
			c.Hardware = []model.Fault{coreError(3, "APIC ID 12", false), coreError(4, "APIC ID 12", false), coreError(9, "APIC ID 12", false)}
			c.Crashes = []model.Crash{crash(3, 0x50, "PAGE_FAULT_IN_NONPAGED_AREA"), crash(4, 0x1A, "MEMORY_MANAGEMENT")}
		}), "blue-screens:medium hardware-errors:medium"},

		// PC health: disks.
		{"a disk reports a spot it cannot read", condition(func(c *model.Condition) {
			c.Disk = []model.Fault{{When: now.AddDate(0, 0, -6), Part: "a disk", Where: `\Device\Harddisk0\DR0`, ID: 7, Words: `The device, \Device\Harddisk0\DR0, has a bad block.`}}
		}), "disk-faults:medium"},
		{"a disk says it expects to fail", condition(func(c *model.Condition) {
			c.Disk = []model.Fault{{When: now.AddDate(0, 0, -1), Fatal: true, Part: "a disk", ID: 52, Words: "The driver has detected that device has predicted that it will fail."}}
		}), "disk-faults:high"},
		{"a disk had to be asked twice, forty times", condition(func(c *model.Condition) { c.Retries = 40 }), ""},
		{"the Windows disk has 4 GB left", condition(func(c *model.Condition) { c.Drives[0].Free = 4 << 30 }), "disk-nearly-full:low"},
		{"a small Windows disk that is 85 per cent full", condition(func(c *model.Condition) { c.Drives[0] = model.Drive{Letter: "C:", Size: 100 << 30, Free: 15 << 30} }), ""},
		{"a large Windows disk with 19 GB left", condition(func(c *model.Condition) { c.Drives[0] = model.Drive{Letter: "C:", Size: 1000 << 30, Free: 19 << 30} }), "disk-nearly-full:low"},
		{"a second disk that is completely full", condition(func(c *model.Condition) { c.Drives[1].Free = 0 }), ""},

		// PC health: stops and logs.
		{"the PC went off without shutting down twice", condition(func(c *model.Condition) { c.PowerCuts = []time.Time{now.AddDate(0, 0, -3), now.AddDate(0, 0, -20)} }), ""},
		{"the PC went off without shutting down four times", condition(func(c *model.Condition) {
			c.PowerCuts = []time.Time{now.AddDate(0, 0, -3), now.AddDate(0, 0, -8), now.AddDate(0, 0, -20), now.AddDate(0, 0, -40)}
		}), "sudden-stops:low"},
		{"the System log was cleared", condition(func(c *model.Condition) {
			c.Wiped = []model.Wipe{{When: now.AddDate(0, 0, -2), Log: "System", By: "sam"}}
		}), "log-cleared:medium"},
		{"three logs were cleared in one go", condition(func(c *model.Condition) {
			c.Wiped = []model.Wipe{{When: now.AddDate(0, 0, -2), Log: "Security", By: "sam"}, {When: now.AddDate(0, 0, -2), Log: "System", By: "sam"}, {When: now.AddDate(0, 0, -2), Log: "Application"}}
		}), "log-cleared:medium"},
		{"Windows' log could not be read at all", condition(func(c *model.Condition) { *c = model.Condition{Drives: c.Drives} }), ""},

		// Protection: what Defender's own log says.
		{"Defender stopped a download yesterday", guard(func(g *model.Guard) {
			g.Detections = []model.Detection{found(1, "Trojan:Win32/Example.A!ml", `C:\Users\sam\Downloads\free.exe`, "Quarantine")}
		}), "defender-found-something:medium"},
		{"Defender found two things, the last two months ago", guard(func(g *model.Guard) {
			g.Detections = []model.Detection{found(61, "PUA:Win32/Example", `C:\Users\sam\Downloads\toolbar.exe`, "Remove"), found(80, "Trojan:Win32/Example.B", `C:\Users\sam\AppData\Local\Temp\a.tmp`, "")}
		}), "defender-found-something:low"},
		{"Defender's log holds nothing, because it could not be read", guard(func(g *model.Guard) {
			g.HistoryRead, g.Detections = false, []model.Detection{found(1, "Trojan:Win32/Example.A!ml", `C:\x.exe`, "")}
		}), ""},
		{"the list of exclusions is hidden, and Defender's log shows one", guard(func(g *model.Guard) {
			g.ExclusionsVisible, g.LoggedExclusions = false, []model.LoggedExclusion{logged(100, "Folder or file", `C:\programdata\sync`)}
		}), "defender-exclusions-logged:medium"},
		{"the list is hidden, and the log shows the Downloads folder being excluded", guard(func(g *model.Guard) {
			g.ExclusionsVisible, g.LoggedExclusions = false, []model.LoggedExclusion{logged(3, "Folder or file", `C:\Users\sam\Downloads`), logged(3, "Program", "miner.exe")}
		}), "defender-exclusions-logged:high"},
		{"the list can be read and holds what the log shows", guard(func(g *model.Guard) {
			g.Exclusions = []model.Exclusion{{Kind: "Folder or file", Value: `D:\Projects\game`}}
			g.LoggedExclusions = []model.LoggedExclusion{logged(40, "Folder or file", `d:\projects\game`)}
		}), "defender-exclusions:medium"},
		{"the list can be read and is empty, though the log shows an old exclusion", guard(func(g *model.Guard) {
			g.LoggedExclusions = []model.LoggedExclusion{logged(200, "Folder or file", `D:\Old`)}
		}), ""},
		{"real-time protection was switched off last week and is on again", guard(func(g *model.Guard) { g.SwitchedOff = []time.Time{now.AddDate(0, 0, -7), now.AddDate(0, 0, -30)} }), "defender-switched-off:low"},
		{"real-time protection was switched off two months ago", guard(func(g *model.Guard) { g.SwitchedOff = []time.Time{now.AddDate(0, 0, -61)} }), ""},
		{"Defender stepped aside for another antivirus", guard(func(g *model.Guard) {
			g.Antivirus = []model.SecurityProduct{{Name: "Microsoft Defender Antivirus", On: model.No}, {Name: "Other Antivirus", On: model.Yes, UpToDate: model.Yes}}
			g.RealTime, g.Tamper, g.SwitchedOff = model.No, model.No, []time.Time{now.AddDate(0, 0, -7)}
		}), ""},
	}...)
}

// What the new findings say, word for word where it matters.
func TestHealthWording(t *testing.T) {
	s := healthy()
	for i := 0; i < 11; i++ {
		s.Condition.Hardware = append(s.Condition.Hardware, coreError(9+i*7, []string{"APIC ID 12", "APIC ID 13"}[i%2], false))
	}
	s.Condition.Crashes = []model.Crash{crash(10, 0x50, "PAGE_FAULT_IN_NONPAGED_AREA"), crash(13, 0x3B, "SYSTEM_SERVICE_EXCEPTION"), crash(14, 0x20001, "HYPERVISOR_ERROR")}
	findings := Check(s)
	if len(findings) != 2 {
		t.Fatalf("got %s", outcome(findings))
	}
	hardware, crashes := findings[0], findings[1]
	for _, want := range []string{
		"Windows logged 11 hardware errors in the last 90 days, the latest on 13 November 2026.",
		"Every one was reported by the processor.",
		"The records all name the same spot (APIC ID 12 and APIC ID 13), which points at one faulty part and not at chance.",
		"All were corrected as they happened",
		"This PC also stopped with a blue screen 3 times in the same period, which fits.",
	} {
		if !strings.Contains(hardware.Reason, want) {
			t.Errorf("the reason lacks %q:\n%s", want, hardware.Reason)
		}
	}
	if hardware.Area != model.Health || hardware.Subject != "11 hardware errors" || len(hardware.Facts) != 6 || hardware.Facts[0].Label != "13 November 2026 at 12:00" {
		t.Errorf("the hardware finding: %+v", hardware)
	}
	for _, want := range []string{
		"Windows stopped with a blue screen 3 times in the last 90 days, the latest on 12 November 2026 (stop code 0x50, PAGE_FAULT_IN_NONPAGED_AREA).",
		"The stop code differs from crash to crash (3 different ones).",
		"Windows also logged hardware errors in the same period. Start with those.",
	} {
		if !strings.Contains(crashes.Reason, want) {
			t.Errorf("the reason lacks %q:\n%s", want, crashes.Reason)
		}
	}
	if crashes.Facts[2].Value != "Stop code 0x20001, HYPERVISOR_ERROR" {
		t.Errorf("the third crash was written %q", crashes.Facts[2].Value)
	}

	// The health light goes amber with them, and no other light moves.
	lights := Lights(s, findings)
	for area, light := range lights {
		want := Green
		if model.Area(area) == model.Health {
			want = Amber
		}
		if light != want {
			t.Errorf("the %s light is %v", model.Area(area), light)
		}
	}
	// A log that could not be read leaves the health light on only as far
	// as the disks could be measured, and with nothing measured it is grey.
	s = healthy()
	s.Condition = model.Condition{}
	if light := Lights(s, Check(s))[model.Health]; light != Grey {
		t.Errorf("with nothing read, the health light is %v", light)
	}
}

func TestDefenderHistoryWording(t *testing.T) {
	s := healthy()
	s.Guard.Detections = []model.Detection{found(1, "Trojan:Win32/Example.A!ml", `C:\Users\sam\Downloads\free.exe`, "Quarantine")}
	f := Check(s)[0]
	want := "Microsoft Defender's own log shows that it found Trojan:Win32/Example.A!ml in C:\\Users\\sam\\Downloads\\free.exe on 21 November 2026 (yesterday). Defender's action was: Quarantine. A detection means the antivirus did its job. It does not mean that anything unwanted is on the PC now."
	if f.Reason != want {
		t.Errorf("got  %s\nwant %s", f.Reason, want)
	}
	if f.Subject != "Trojan:Win32/Example.A!ml" || f.Facts[0].Label != "Found on 21 November 2026 at 12:00" || f.Facts[0].Value != `Trojan:Win32/Example.A!ml (Severe), in C:\Users\sam\Downloads\free.exe. Defender's action: Quarantine` {
		t.Errorf("the finding: %+v", f)
	}

	// With the list in hand, the date the log gives is added to the fact.
	s = healthy()
	s.Guard.Exclusions = []model.Exclusion{{Kind: "Folder or file", Value: `C:\programdata\sync`}}
	s.Guard.LoggedExclusions = []model.LoggedExclusion{logged(108, "Folder or file", `C:\ProgramData\Sync`)}
	f = Check(s)[0]
	if f.Rule != "defender-exclusions" || f.Facts[0].Value != `C:\programdata\sync, added on 6 August 2026 at 12:00 according to Defender's own log` {
		t.Errorf("the exclusion with its date: %+v", f.Facts)
	}

	// Without it, the log speaks alone and says what it cannot know.
	s.Guard.ExclusionsVisible, s.Guard.Exclusions = false, nil
	f = Check(s)[0]
	if f.Rule != "defender-exclusions-logged" || !strings.Contains(f.Reason, "not taken off since: C:\\ProgramData\\Sync.") || !strings.Contains(f.Reason, "there may be older exclusions") {
		t.Errorf("the logged exclusion: %s: %s", f.Rule, f.Reason)
	}
}

func TestSmallHealthHelpers(t *testing.T) {
	for bytes, want := range map[uint64]string{0: "0 MB", 300 << 20: "300 MB", 1 << 30: "1.0 GB", 4<<30 + 512<<20: "4.5 GB", 10 << 30: "10 GB", 936 << 30: "936 GB"} {
		if got := Size(bytes); got != want {
			t.Errorf("Size(%d) = %q, want %q", bytes, got, want)
		}
	}
	s := healthy()
	for days, want := range map[int]string{0: "today", 1: "yesterday", 2: "2 days ago", 40: "40 days ago"} {
		if got := Ago(s, now.AddDate(0, 0, -days)); got != want {
			t.Errorf("%d days back is %q, want %q", days, got, want)
		}
	}
	// Late last night is yesterday, though fewer than 24 hours have passed.
	if got := Ago(s, now.Add(-13*time.Hour)); got != "yesterday" {
		t.Errorf("13 hours before noon is %q, want yesterday", got)
	}
	if got := Ago(s, now.Add(-11*time.Hour)); got != "today" {
		t.Errorf("11 hours before noon is %q, want today", got)
	}
	if got := strings.Join(each([]string{"a", "", "b", "a"}), ","); got != "a,b" {
		t.Errorf("each gave %q", got)
	}
	if got := SpaceRef("c:"); got != "space:C:" {
		t.Errorf("SpaceRef gave %q", got)
	}
}
