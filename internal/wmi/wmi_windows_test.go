//go:build windows

package wmi

import (
	"os"
	"testing"
	"time"
)

// TestOperatingSystem asks WMI a question every Windows can answer, about
// itself. It runs only when LAZASCOPE_LIVE=1.
func TestOperatingSystem(t *testing.T) {
	if os.Getenv("LAZASCOPE_LIVE") != "1" {
		t.Skip("set LAZASCOPE_LIVE=1 to ask this PC's WMI")
	}
	rows, err := Query(`root\cimv2`, "SELECT Caption, BuildNumber, NumberOfProcesses FROM Win32_OperatingSystem", []string{"Caption", "BuildNumber", "NumberOfProcesses"}, 10*time.Second)
	if err != nil || len(rows) != 1 {
		t.Fatalf("got %v, %v", rows, err)
	}
	caption, _ := rows[0]["Caption"].(string)
	processes, _ := rows[0]["NumberOfProcesses"].(int64)
	if caption == "" || processes < 10 {
		t.Errorf("an odd answer: %v", rows[0])
	}
	t.Logf("%v", rows[0])
	prefs, err := Query(`root\Microsoft\Windows\Defender`, "SELECT PUAProtection, EnableControlledFolderAccess, EnableNetworkProtection, MAPSReporting, SubmitSamplesConsent FROM MSFT_MpPreference",
		[]string{"PUAProtection", "EnableControlledFolderAccess", "EnableNetworkProtection", "MAPSReporting", "SubmitSamplesConsent"}, 10*time.Second)
	t.Logf("Defender's settings: %v, %v", prefs, err)
}
