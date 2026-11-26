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

// TestNumberList reads a list of numbers: the protections Windows' Device
// Guard report says are running, the same list System Information shows.
// It runs only when LAZASCOPE_LIVE=1.
func TestNumberList(t *testing.T) {
	if os.Getenv("LAZASCOPE_LIVE") != "1" {
		t.Skip("set LAZASCOPE_LIVE=1 to ask this PC's WMI")
	}
	rows, err := Query(`root\Microsoft\Windows\DeviceGuard`, "SELECT SecurityServicesConfigured, SecurityServicesRunning, VirtualizationBasedSecurityStatus FROM Win32_DeviceGuard",
		[]string{"SecurityServicesConfigured", "SecurityServicesRunning", "VirtualizationBasedSecurityStatus"}, 10*time.Second)
	if err != nil || len(rows) != 1 {
		t.Fatalf("got %v, %v", rows, err)
	}
	for _, name := range []string{"SecurityServicesConfigured", "SecurityServicesRunning"} {
		list, ok := rows[0][name].([]int64)
		if !ok {
			t.Fatalf("%s was read as %#v, not as a list of numbers", name, rows[0][name])
		}
		for _, n := range list {
			if n < 0 || n > 64 {
				t.Errorf("%s holds an unlikely number: %v", name, list)
			}
		}
	}
	if _, ok := rows[0]["VirtualizationBasedSecurityStatus"].(int64); !ok {
		t.Errorf("a single number beside the lists was read as %#v", rows[0]["VirtualizationBasedSecurityStatus"])
	}
	t.Logf("%v", rows[0])
}
