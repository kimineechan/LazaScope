package eventlog

import (
	"testing"
	"time"
)

// Records as Windows hands them over, with made-up values.
const (
	hardware = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-WHEA-Logger' Guid='{c26c4f3c-3f66-4e99-8f8a-39405cfed220}'/><EventID>19</EventID><Version>0</Version><Level>3</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2026-11-14T10:11:12.1234567Z'/><EventRecordID>4242</EventRecordID><Channel>System</Channel><Computer>STUDY-PC</Computer><Security UserID='S-1-5-19'/></System><EventData><Data Name='ErrorSource'>1</Data><Data Name='ApicId'>32</Data><Data Name='MCABank'>0</Data><Data Name='MciStat'>0x90000040000f0005</Data><Data Name='ErrorType'>9</Data></EventData></Event>`

	classic = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='disk'/><EventID Qualifiers='49156'>7</EventID><Level>2</Level><TimeCreated SystemTime='2026-10-02T08:00:00.000000000Z'/><Channel>System</Channel></System><EventData><Data>\Device\Harddisk1\DR1</Data><Binary>0300</Binary></EventData></Event>`

	cleared = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Eventlog'/><EventID>104</EventID><Level>4</Level><TimeCreated SystemTime='2026-11-01T21:30:00.5Z'/><Channel>System</Channel></System><UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'><SubjectUserName>sam</SubjectUserName><SubjectDomainName>STUDY-PC</SubjectDomainName><Channel>Application</Channel><BackupPath></BackupPath></LogFileCleared></UserData></Event>`

	spaced = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Windows Defender'/><EventID>1116</EventID><Level>3</Level><TimeCreated SystemTime='2026-11-17T19:05:44.0Z'/></System><EventData><Data Name='Threat Name'>Trojan:Win32/Example.A!ml</Data><Data Name='Severity Name'>Severe</Data><Data Name='Path'>file:_C:\Users\sam\Downloads\free &amp; easy.exe</Data><Data Name='Threat ID'>2147700000</Data></EventData></Event>`
)

func TestParse(t *testing.T) {
	e, err := Parse(hardware)
	if err != nil {
		t.Fatal(err)
	}
	if e.Provider != "Microsoft-Windows-WHEA-Logger" || e.ID != 19 || e.Level != Warning {
		t.Errorf("read as %q, %d, level %d", e.Provider, e.ID, e.Level)
	}
	if want := time.Date(2026, 11, 14, 10, 11, 12, 123456700, time.UTC); !e.Time.Equal(want) {
		t.Errorf("time read as %v, want %v", e.Time, want)
	}
	if e.Value("ApicId") != "32" || e.Value("ErrorType") != "9" || e.Value("Missing") != "" {
		t.Errorf("values read as %v", e.Data)
	}
	if n, ok := e.Number("ApicId"); !ok || n != 32 {
		t.Errorf("ApicId as a number: %d, %v", n, ok)
	}
	if n, ok := e.Number("MciStat"); !ok || n != 0x90000040000f0005 {
		t.Errorf("a number written in sixteens: %x, %v", n, ok)
	}
	if _, ok := e.Number("Missing"); ok {
		t.Error("a value that is not there was read as a number")
	}

	// An older kind of record: its number carries an attribute, and its
	// values have no names.
	e, err = Parse(classic)
	if err != nil {
		t.Fatal(err)
	}
	if e.Provider != "disk" || e.ID != 7 || e.Level != Error || len(e.Loose) != 1 || e.Loose[0] != `\Device\Harddisk1\DR1` {
		t.Errorf("the older kind was read as %+v", e)
	}

	// A record that names each value by its own element.
	e, err = Parse(cleared)
	if err != nil {
		t.Fatal(err)
	}
	if e.ID != 104 || e.Value("Channel") != "Application" || e.Value("SubjectUserName") != "sam" {
		t.Errorf("the cleared-log record was read as %+v", e)
	}

	// Names with spaces in them, and text that XML has to write differently.
	e, err = Parse(spaced)
	if err != nil {
		t.Fatal(err)
	}
	if e.Value("Threat Name") != "Trojan:Win32/Example.A!ml" || e.Value("Path") != `file:_C:\Users\sam\Downloads\free & easy.exe` {
		t.Errorf("the antivirus record was read as %v", e.Data)
	}

	for _, broken := range []string{"", "not XML at all", "<Other><System/></Other>"} {
		if _, err := Parse(broken); err == nil {
			t.Errorf("%q was taken for a record", broken)
		}
	}
	// A record cut short still gives what came before the cut, and no fault.
	if e, err := Parse(hardware[:400]); err != nil || e.ID != 19 {
		t.Errorf("a record cut short: %+v, %v", e, err)
	}
}

func TestQuestions(t *testing.T) {
	got := Where(From("Microsoft-Windows-WHEA-Logger"), Since(90))
	want := "*[System[Provider[@Name='Microsoft-Windows-WHEA-Logger'] and TimeCreated[timediff(@SystemTime) <= 7776000000]]]"
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	if got := Where(From("disk"), Numbered(7, 52)); got != "*[System[Provider[@Name='disk'] and (EventID=7 or EventID=52)]]" {
		t.Errorf("got %s", got)
	}
	if got := Numbered(104); got != "EventID=104" {
		t.Errorf("got %s", got)
	}
}
