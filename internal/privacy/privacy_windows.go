//go:build windows

package privacy

import (
	"strings"
	"time"

	"lazascope/internal/model"
	"lazascope/internal/reg"
	"lazascope/internal/winpath"
	"lazascope/internal/wmi"
)

const (
	defender = `SOFTWARE\Microsoft\Windows Defender`
	policy   = `SOFTWARE\Policies\Microsoft\Windows Defender`
	guard    = defender + `\Windows Defender Exploit Guard`
)

// number reads a setting, preferring the one a policy sets.
func number(paths [][2]string) (uint32, bool) {
	for _, p := range paths {
		if n, ok := reg.Number(reg.Machine, p[0], reg.Native, p[1]); ok {
			return n, true
		}
	}
	return 0, false
}

// Defences reads whether each defence Windows has is switched on. A
// setting that Windows does not record reads as not known.
func Defences() []model.Defence {
	var out []model.Defence
	add := func(key, name string, on model.Answer, isDefender, ransomware bool) {
		out = append(out, model.Defence{Key: key, Name: name, On: on, Defender: isDefender, Ransomware: ransomware})
	}
	answer := func(n uint32, ok bool, on func(uint32) bool) model.Answer {
		if !ok {
			return model.NotKnown
		}
		return model.Say(on(n))
	}
	n, ok := number([][2]string{{policy, "PUAProtection"}, {defender, "PUAProtection"}})
	add("pua", "Potentially unwanted app blocking", answer(n, ok, func(v uint32) bool { return v == 1 }), true, false)

	// SmartScreen's "Check apps and files" is on unless it was set to Off.
	smart := model.NotKnown
	if v, ok := reg.Text(reg.Machine, `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer`, reg.Native, "SmartScreenEnabled"); ok {
		smart = model.Say(!strings.EqualFold(strings.TrimSpace(v), "Off"))
	}
	if v, ok := reg.Number(reg.Machine, `SOFTWARE\Policies\Microsoft\Windows\System`, reg.Native, "EnableSmartScreen"); ok {
		smart = model.Say(v != 0)
	}
	add("smartscreen", "Check apps and files (SmartScreen)", smart, false, true)

	n, ok = number([][2]string{{`SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access`, "EnableControlledFolderAccess"}, {guard + `\Controlled Folder Access`, "EnableControlledFolderAccess"}})
	add("cfa", "Controlled folder access", answer(n, ok, func(v uint32) bool { return v == 1 }), true, true)
	if !ok {
		out[len(out)-1].On = model.No // Windows records it once it has been switched on
	}

	n, ok = number([][2]string{{`SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection`, "EnableNetworkProtection"}, {guard + `\Network Protection`, "EnableNetworkProtection"}})
	add("network", "Network protection", answer(n, ok, func(v uint32) bool { return v == 1 }), true, true)
	if !ok {
		out[len(out)-1].On = model.No
	}

	n, ok = number([][2]string{{policy + `\Spynet`, "SpynetReporting"}, {defender + `\Spynet`, "SpynetReporting"}})
	add("cloud", "Cloud-delivered protection", answer(n, ok, func(v uint32) bool { return v != 0 }), true, true)

	// Defender's own settings, read the way Get-MpPreference reads them. Where
	// WMI answers, its answer replaces what the registry suggested.
	if rows, err := wmi.Query(`root\Microsoft\Windows\Defender`,
		"SELECT PUAProtection, EnableControlledFolderAccess, EnableNetworkProtection, MAPSReporting, SubmitSamplesConsent FROM MSFT_MpPreference",
		[]string{"PUAProtection", "EnableControlledFolderAccess", "EnableNetworkProtection", "MAPSReporting", "SubmitSamplesConsent"}, 8*time.Second); err == nil && len(rows) == 1 {
		set := func(key, property string, on func(int64) bool) {
			value, ok := rows[0][property].(int64)
			if !ok {
				return
			}
			for i := range out {
				if out[i].Key == key {
					out[i].On = model.Say(on(value))
				}
			}
		}
		set("pua", "PUAProtection", func(v int64) bool { return v == 1 })
		set("cfa", "EnableControlledFolderAccess", func(v int64) bool { return v == 1 })
		set("network", "EnableNetworkProtection", func(v int64) bool { return v == 1 })
		set("cloud", "MAPSReporting", func(v int64) bool { return v != 0 })
		if value, ok := rows[0]["SubmitSamplesConsent"].(int64); ok {
			add("samples", "Automatic sample submission", model.Say(value == 1 || value == 3), true, false)
		}
	}

	n, ok = reg.Number(reg.Machine, `SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity`, reg.Native, "Enabled")
	add("hvci", "Memory integrity", answer(n, ok, func(v uint32) bool { return v == 1 }), false, false)

	n, ok = reg.Number(reg.Machine, `SYSTEM\CurrentControlSet\Control\Lsa`, reg.Native, "RunAsPPL")
	lsa := answer(n, ok, func(v uint32) bool { return v == 1 || v == 2 })
	if !ok {
		lsa = model.No // off until set
	}
	add("lsa", "Local Security Authority protection", lsa, false, false)

	n, ok = reg.Number(reg.Machine, `SYSTEM\CurrentControlSet\Control\CI\Config`, reg.Native, "VulnerableDriverBlocklistEnable")
	add("drivers", "Microsoft Vulnerable Driver Blocklist", answer(n, ok, func(v uint32) bool { return v == 1 }), false, false)
	return out
}

// Collect reads the backups: when File History last ran, which of the
// account's folders OneDrive copies, and the backup programs installed.
func Collect(programs []model.Installed, clouds []model.CloudFolder) model.Backups {
	var b model.Backups
	if k, err := reg.Open(reg.User, `Software\Microsoft\Windows\CurrentVersion\FileHistory`, reg.Native); err == nil {
		if data, ok := k.Bytes("ProtectedUpToTime"); ok {
			b.FileHistory = filetime(data)
		}
		k.Close()
	}
	for _, folder := range []struct{ name, value string }{{"Documents", "Personal"}, {"Desktop", "Desktop"}, {"Pictures", "My Pictures"}} {
		path, _ := reg.Text(reg.User, `Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`, reg.Native, folder.value)
		for _, c := range clouds {
			if c.Service == "OneDrive" && path != "" && winpath.Under(path, c.Path) {
				b.OneDrive = append(b.OneDrive, folder.name)
			}
		}
	}
	seen := map[string]bool{}
	for _, p := range programs {
		if BackupProgram(p.Name) && !seen[p.Name] {
			seen[p.Name] = true
			b.Programs = append(b.Programs, p.Name)
		}
	}
	return b
}

// Devices reads which programs used the camera and the microphone, from
// the records behind Windows' privacy settings for this account.
func Devices() []model.DeviceUse {
	var out []model.DeviceUse
	for _, device := range []struct{ key, name string }{{"webcam", "camera"}, {"microphone", "microphone"}} {
		base := `Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\` + device.key
		root, err := reg.Open(reg.User, base, reg.Native)
		if err != nil {
			continue
		}
		read := func(k *reg.Key, app string, program bool) {
			use := model.DeviceUse{Device: device.name, App: app, Program: program, Allowed: model.NotKnown}
			if v, ok := k.Text("Value"); ok {
				use.Allowed = model.Say(strings.EqualFold(v, "Allow"))
			}
			if data, ok := k.Bytes("LastUsedTimeStart"); ok {
				use.Start = filetime(data)
			}
			if data, ok := k.Bytes("LastUsedTimeStop"); ok {
				use.Stop = filetime(data)
			}
			if !use.Start.IsZero() {
				out = append(out, use)
			}
		}
		for _, name := range root.Subkeys() {
			if strings.EqualFold(name, "NonPackaged") {
				continue
			}
			if k, err := root.Sub(name); err == nil {
				read(k, name, false)
				k.Close()
			}
		}
		if programs, err := root.Sub("NonPackaged"); err == nil {
			for _, name := range programs.Subkeys() {
				if k, err := programs.Sub(name); err == nil {
					read(k, programPath(name), true)
					k.Close()
				}
			}
			programs.Close()
		}
		root.Close()
	}
	return out
}
