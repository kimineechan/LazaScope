package startup

import (
	"strings"
	"testing"
)

const sampleTask = `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>Example Ltd</Author>
    <Description>Keeps Example up to date.</Description>
    <URI>\Example\Update</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled></LogonTrigger>
    <CalendarTrigger>
      <StartBoundary>2026-01-01T09:00:00</StartBoundary>
      <Repetition><Interval>PT1H</Interval></Repetition>
      <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>
    </CalendarTrigger>
    <BootTrigger><Enabled>false</Enabled></BootTrigger>
    <LogonTrigger><Enabled>true</Enabled></LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>"C:\Program Files\Example\update.exe"</Command>
      <Arguments>/silent /check</Arguments>
    </Exec>
    <ComHandler>
      <ClassId>{11111111-2222-3333-4444-555555555555}</ClassId>
      <Data>ignored</Data>
    </ComHandler>
  </Actions>
</Task>`

func TestParseTask(t *testing.T) {
	task, err := ParseTask(sampleTask)
	if err != nil {
		t.Fatal(err)
	}
	if task.Author != "Example Ltd" || task.Description != "Keeps Example up to date." {
		t.Errorf("author %q, description %q", task.Author, task.Description)
	}
	if !task.Enabled || !task.Hidden || !task.Highest || task.Account != "S-1-5-18" {
		t.Errorf("enabled %v, hidden %v, highest %v, account %q", task.Enabled, task.Hidden, task.Highest, task.Account)
	}
	// The trigger that is switched off is left out, and the two alike are
	// said once.
	if got := strings.Join(task.Triggers, " | "); got != "When someone signs in | Daily, then every 1 hour" {
		t.Errorf("triggers: %q", got)
	}
	if len(task.Actions) != 2 {
		t.Fatalf("got %d actions, want 2", len(task.Actions))
	}
	if a := task.Actions[0]; a.Command != `"C:\Program Files\Example\update.exe"` || a.Arguments != "/silent /check" || a.Class != "" {
		t.Errorf("the program action: %+v", a)
	}
	if a := task.Actions[1]; a.Class != "{11111111-2222-3333-4444-555555555555}" || a.Command != "" {
		t.Errorf("the component action: %+v", a)
	}
}

func TestParseTaskVariants(t *testing.T) {
	// A task that is switched off, runs as a group and has no triggers.
	task, err := ParseTask(`<Task><Principals><Principal><GroupId>S-1-5-32-545</GroupId></Principal></Principals>
		<Settings><Enabled>false</Enabled></Settings><Actions><Exec><Command>thing.exe</Command></Exec></Actions></Task>`)
	if err != nil {
		t.Fatal(err)
	}
	if task.Enabled || task.Hidden || task.Highest || task.Account != "S-1-5-32-545" || len(task.Triggers) != 0 || len(task.Actions) != 1 {
		t.Errorf("got %+v", task)
	}
	// With no Settings at all a task counts as enabled, as it does to Windows.
	if task, err := ParseTask(`<Task><Actions/></Task>`); err != nil || !task.Enabled || len(task.Actions) != 0 {
		t.Errorf("an empty task: %+v, %v", task, err)
	}
	for _, broken := range []string{"", "not xml at all", "<Task><Actions>", "<Task></Tusk>"} {
		if _, err := ParseTask(broken); err == nil {
			t.Errorf("%q was read without complaint", broken)
		}
	}
}

func TestSpan(t *testing.T) {
	for written, want := range map[string]string{
		"PT5M":    "5 minutes",
		"PT1H":    "1 hour",
		"P1D":     "1 day",
		"PT1H30M": "1 hour 30 minutes",
		"P1DT12H": "1 day 12 hours",
		"PT30S":   "30 seconds",
		"P2M":     "2 months",
		"pt10m":   "10 minutes",
		"":        "",
		"5M":      "",
		"PT0M":    "",
		"PTXM":    "",
		"P1Y":     "",
	} {
		if got := Span(written); got != want {
			t.Errorf("Span(%q) = %q, want %q", written, got, want)
		}
	}
}

const sampleManifest = `<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10" xmlns:uap5="http://schemas.microsoft.com/appx/manifest/uap/windows10/5" xmlns:desktop="http://schemas.microsoft.com/appx/manifest/desktop/windows10">
  <Applications>
    <Application Id="Main" Executable="app/Main.exe" EntryPoint="Windows.FullTrustApplication">
      <Extensions>
        <uap5:Extension Category="windows.appExecutionAlias" Executable="app/alias.exe" />
        <uap5:Extension Category="windows.startupTask" Executable="app\Helper.exe" EntryPoint="Windows.FullTrustApplication">
          <uap5:StartupTask TaskId="HelperStartup" Enabled="true" DisplayName="Helper" />
        </uap5:Extension>
        <desktop:Extension Category="windows.startupTask">
          <desktop:StartupTask TaskId="MainStartup" Enabled="false" DisplayName="Main" />
        </desktop:Extension>
      </Extensions>
    </Application>
  </Applications>
</Package>`

func TestStartupExecutable(t *testing.T) {
	for _, test := range []struct {
		task, executable string
		declared         bool
	}{
		{"HelperStartup", `app\Helper.exe`, true},
		{"helperstartup", `app\Helper.exe`, true},
		{"MainStartup", `app\Main.exe`, true}, // named on the application, not the extension
		{"Other", "", false},
	} {
		executable, declared := StartupExecutable([]byte(sampleManifest), test.task)
		if executable != test.executable || declared != test.declared {
			t.Errorf("%s: got %q, %v; want %q, %v", test.task, executable, declared, test.executable, test.declared)
		}
	}
	if _, declared := StartupExecutable([]byte("<Package><Applications>"), "X"); declared {
		t.Error("a manifest cut short declares nothing")
	}
	if _, declared := StartupExecutable(nil, "X"); declared {
		t.Error("an empty manifest declares nothing")
	}
}
