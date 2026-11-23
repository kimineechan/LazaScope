package protect

import (
	"testing"
	"time"

	"lazascope/internal/eventlog"
)

var day = time.Date(2026, 8, 6, 0, 55, 32, 0, time.UTC)

func changed(at time.Time, old, new string) eventlog.Event {
	data := map[string]string{}
	if old != "" {
		data["Old Value"] = old
	}
	if new != "" {
		data["New Value"] = new
	}
	return eventlog.Event{Time: at, ID: settingChanged, Data: data}
}

const paths = `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\`

func TestExclusionOf(t *testing.T) {
	for _, test := range []struct{ value, kind, what string }{
		{paths + `C:\programdata\sync = 0x0`, "Folder or file", `C:\programdata\sync`},
		{`HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions\.tmp = 0x0`, "File type", ".tmp"},
		{`HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes\game.exe = 0x0`, "Program", "game.exe"},
		{`HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths\D:\Build = 0x0`, "Folder or file", `D:\Build`},
		{`HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\IpAddresses\10.0.0.5 = 0x0`, "Network address", "10.0.0.5"},
		// A folder whose own name holds " = " keeps all of it.
		{paths + `C:\a = b\c = 0x0`, "Folder or file", `C:\a = b\c`},
		// Settings that are not exclusions, and lists this program does not know.
		{`HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TPExclusions = 0x0`, "", ""},
		{`HKLM\SOFTWARE\Microsoft\Windows Defender\Features\EcsConfigs\MpFC_Nis_WdFilterProcessExclusions = 0x1`, "", ""},
		{`HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Unheard\thing = 0x0`, "", ""},
		{`HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\ = 0x0`, "", ""},
		{``, "", ""},
	} {
		got, ok := exclusionOf(test.value)
		if ok != (test.kind != "") || got.Kind != test.kind || got.Value != test.what {
			t.Errorf("exclusionOf(%q) = %+v, %v", test.value, got, ok)
		}
	}
}

func TestLoggedExclusions(t *testing.T) {
	// Handed over newest first, as Windows gives them.
	records := []eventlog.Event{
		changed(day.Add(72*time.Hour), `HKLM\SOFTWARE\Microsoft\Windows Defender\UX Configuration\Toast = 0x1`, `HKLM\SOFTWARE\Microsoft\Windows Defender\UX Configuration\Toast = 0x0`),
		changed(day.Add(50*time.Hour), "", paths+`D:\Games = 0x0`),                   // added again later
		changed(day.Add(48*time.Hour), paths+`D:\Games = 0x0`, ""),                   // taken off
		changed(day.Add(30*time.Hour), paths+`C:\Temp\x = 0x0`, ""),                  // taken off, and not added again
		changed(day.Add(24*time.Hour), "", paths+`C:\Temp\x = 0x0`),                  // added
		changed(day.Add(2*time.Hour), "", paths+`D:\Games = 0x0`),                    // added
		changed(day.Add(time.Hour), "", paths+`C:\PROGRAMDATA\Sync = 0x0`),           // the same place a second time, in other letters
		changed(day, "", paths+`C:\programdata\sync = 0x0`),                          // added
		{Time: day.Add(time.Minute), ID: realTimeOff, Data: map[string]string{}},     // not a change of setting
		changed(day.Add(-time.Hour), `HKLM\X\Windows Defender\Exclusions\Paths`, ``), // not an exclusion
	}
	got := LoggedExclusions(records)
	if len(got) != 2 {
		t.Fatalf("got %d exclusions: %+v", len(got), got)
	}
	if got[0].Value != `C:\programdata\sync` || !got[0].When.Equal(day) || got[0].Kind != "Folder or file" {
		t.Errorf("the first is %+v", got[0])
	}
	if got[1].Value != `D:\Games` || !got[1].When.Equal(day.Add(50*time.Hour)) {
		t.Errorf("the one taken off and added again is %+v", got[1])
	}
	if len(LoggedExclusions(nil)) != 0 {
		t.Error("no records gave exclusions")
	}
}

func found1116(at time.Time, number, threat, path string) eventlog.Event {
	return eventlog.Event{Time: at, ID: found, Data: map[string]string{"Detection ID": number, "Threat Name": threat, "Severity Name": "Severe", "Category Name": "Trojan", "Path": path, "Process Name": `C:\Windows\explorer.exe`, "Action Name": "Not Applicable"}}
}

func TestDetections(t *testing.T) {
	records := []eventlog.Event{
		{Time: day.Add(49 * time.Hour), ID: acted, Data: map[string]string{"Detection ID": "{B}", "Threat Name": "Behavior:Win32/Example", "Action Name": "Quarantine", "Path": `file:_C:\Users\sam\AppData\Local\Temp\tool.exe; process:_pid:4242`}},
		found1116(day.Add(48*time.Hour), "{B}", "Behavior:Win32/Example", `file:_C:\Users\sam\AppData\Local\Temp\tool.exe; process:_pid:4242`),
		found1116(day.Add(5*time.Hour), "{A}", "Trojan:Win32/Example.A!ml", `file:_C:\Users\sam\Downloads\free.exe`),
		{Time: day, ID: foundByScan, Data: map[string]string{"Threat Name": "PUA:Win32/Old", "Path": `containerfile:_C:\Users\sam\Downloads\bundle.zip`}},
		{Time: day, ID: found, Data: map[string]string{"Detection ID": "{C}"}}, // nothing named: left out
		changed(day, "", paths+`C:\x = 0x0`),
	}
	// The same find written a second time, half a minute later, is one find.
	records = append(records, found1116(day.Add(5*time.Hour+30*time.Second), "{A2}", "Trojan:Win32/Example.A!ml", `file:_C:\Users\sam\Downloads\free.exe`))
	got := Detections(records)
	if len(got) != 3 {
		t.Fatalf("got %d detections: %+v", len(got), got)
	}
	newest := got[0]
	if newest.Threat != "Behavior:Win32/Example" || newest.Action != "Quarantine" || newest.Path != `C:\Users\sam\AppData\Local\Temp\tool.exe; process:_pid:4242` || !newest.When.Equal(day.Add(48*time.Hour)) {
		t.Errorf("the newest is %+v", newest)
	}
	if !got[1].When.Equal(day.Add(5*time.Hour + 30*time.Second)) {
		t.Errorf("of two records of one find, the time kept is %v", got[1].When)
	}
	if got[1].Threat != "Trojan:Win32/Example.A!ml" || got[1].Action != "" || got[1].Path != `C:\Users\sam\Downloads\free.exe` || got[1].Severity != "Severe" || got[1].Process != `C:\Windows\explorer.exe` {
		t.Errorf("the second is %+v", got[1])
	}
	if got[2].Threat != "PUA:Win32/Old" || got[2].Path != `C:\Users\sam\Downloads\bundle.zip` {
		t.Errorf("the oldest is %+v", got[2])
	}
}

func TestSwitchedOff(t *testing.T) {
	got := SwitchedOff([]eventlog.Event{{Time: day, ID: realTimeOff}, changed(day, "", ""), {Time: day.Add(time.Hour), ID: realTimeOff}})
	if len(got) != 2 || !got[0].Equal(day.Add(time.Hour)) {
		t.Errorf("got %v", got)
	}
}
