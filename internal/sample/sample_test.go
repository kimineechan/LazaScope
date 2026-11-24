package sample_test

import (
	"sort"
	"strings"
	"testing"

	"lazascope/internal/model"
	"lazascope/internal/rules"
	"lazascope/internal/sample"
	"lazascope/internal/view"
)

// The made-up PC is the whole program end to end, without Windows: its
// facts go through the rules and come out as pages. What it flags is fixed
// here, so that a change to a rule that alters it is noticed.
func TestTheMadeUpPC(t *testing.T) {
	s := sample.PC()
	findings := rules.Check(s)
	var got []string
	for _, f := range findings {
		got = append(got, f.Rule+" ("+strings.ToLower(f.Severity.String())+"): "+f.Subject)
	}
	sort.Strings(got)
	want := []string{
		`blue-screens (worth a look): 2 blue screens`,
		`clipboard-history-wallets (good to know): Clipboard history`,
		`defender-exclusions-logged (look first): 1 exclusion in Defender's log`,
		`defender-found-something (worth a look): Trojan:Win32/Wacatac.B!ml`,
		`disk-not-encrypted (good to know): Drive C:`,
		`extension-fake-wallet (look first): MetaMask Wallet Pro`,
		`extension-not-from-store (worth a look): Shopping Helper Pro`,
		`hardware-errors (worth a look): 4 hardware errors`,
		`hosts-entries (good to know): 2 sites blocked`,
		`remote-tool (worth a look): AnyDesk`,
		`running-temp-folder (worth a look): FabrikamLauncherSetup.exe`,
		`startup-antivirus-objects (look first): \Updater\Check`,
		`startup-missing-file (good to know): ContosoPrintTool`,
		`startup-scrambled-command (look first): \Updater\Check`,
		`startup-script (worth a look): Open study apps.cmd`,
		`startup-system-name (look first): Windows Host Service`,
		`startup-unsigned (worth a look): PhotoSorter`,
		`startup-unsigned (worth a look): Windows Host Service`,
		`startup-virustotal-flags (good to know): PhotoSorter`,
		`startup-virustotal-flags (look first): Windows Host Service`,
		`updates-old (worth a look): Windows Update`,
		`wallet-files-unencrypted (good to know): Electrum`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("the made-up PC is flagged for:\n%s\n\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	lights := rules.Lights(s, findings)
	if lights != [model.Areas]rules.Light{model.Protection: rules.Red, model.StartsWithWindows: rules.Red, model.RunningNow: rules.Amber, model.Connections: rules.Green, model.Accounts: rules.Amber, model.Health: rules.Amber} {
		t.Errorf("lights: %v", lights)
	}

	book := view.Build(s, findings)
	for _, page := range book.Pages() {
		if len(page.Rows) == 0 {
			t.Errorf("the %s page of the made-up PC is empty", page.Name)
		}
	}
	if len(book.Startup.Rows) != len(s.Startup) || len(book.Running.Rows) != len(s.Processes) || len(book.Connections.Rows) != len(s.Connections) {
		t.Error("a page has lost or gained rows")
	}
	// Nothing about it may point at a real person or a real address: the
	// addresses are from the ranges set aside for examples.
	for _, c := range s.Connections {
		if c.Remote == "" {
			continue
		}
		if !strings.HasPrefix(c.Remote, "203.0.113.") && !strings.HasPrefix(c.Remote, "198.51.100.") && !strings.HasPrefix(c.Remote, "192.168.") {
			t.Errorf("the address %s is not one set aside for examples", c.Remote)
		}
	}
}
