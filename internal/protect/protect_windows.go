//go:build windows

package protect

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"lazascope/internal/com"
	"lazascope/internal/eventlog"
	"lazascope/internal/model"
	"lazascope/internal/pcinfo"
	"lazascope/internal/reg"
	"lazascope/internal/sysdll"
	"lazascope/internal/winpath"
)

var (
	wscapi   = sysdll.Load("wscapi.dll")
	netapi32 = sysdll.Load("netapi32.dll")
	kernel32 = sysdll.Load("kernel32.dll")
	shell32  = sysdll.Load("shell32.dll")

	providerHealth = wscapi.NewProc("WscGetSecurityProviderHealth")
	groupMembers   = netapi32.NewProc("NetLocalGroupGetMembers")
	userList       = netapi32.NewProc("NetUserEnum")
	netFree        = netapi32.NewProc("NetApiBufferFree")
	logicalDrives  = kernel32.NewProc("GetLogicalDrives")
	driveType      = kernel32.NewProc("GetDriveTypeW")
	shellItem      = shell32.NewProc("SHCreateItemFromParsingName")
	keyFromName    = sysdll.Load("propsys.dll").NewProc("PSGetPropertyKeyFromName")
)

// at reads an address Windows returned as the pointer it is.
func at(address uintptr) unsafe.Pointer { return *(*unsafe.Pointer)(unsafe.Pointer(&address)) }

// wide reads text that Windows points to.
func wide(text *uint16) string {
	if text == nil {
		return ""
	}
	units := (*[1 << 16]uint16)(unsafe.Pointer(text))
	n := 0
	for n < len(units) && units[n] != 0 {
		n++
	}
	return syscall.UTF16ToString(units[:n])
}

type collector struct {
	guard model.Guard
	gaps  []model.Gap
}

func (c *collector) gap(area model.Area, what string) {
	c.gaps = append(c.gaps, model.Gap{Area: area, What: what})
}

// Collect gathers how the PC is protected. It only reads.
func Collect() (model.Guard, []model.Gap) {
	c := &collector{}
	leave, err := com.Enter()
	defer leave()
	c.securityCentre(err == nil)
	c.defender()
	c.history()
	c.firewall()
	c.accountControl()
	c.updates()
	c.volumes(err == nil)
	c.remoteDesktop()
	c.accounts()
	c.hosts()
	c.programs()
	return c.guard, c.gaps
}

// The parts of protection that Windows Security keeps watch over.
const (
	watchFirewall  = 0x1
	watchAntivirus = 0x4
)

// securityCentre asks Windows Security for its own verdict and for the
// antivirus and firewall products that have registered with it.
func (c *collector) securityCentre(objects bool) {
	health := func(provider uintptr) model.Answer {
		if providerHealth.Find() != nil {
			return model.NotKnown
		}
		const good, notWatched = 0, 1
		verdict := int32(-1)
		if r, _, _ := providerHealth.Call(provider, uintptr(unsafe.Pointer(&verdict))); r != 0 || verdict < 0 || verdict == notWatched {
			return model.NotKnown
		}
		return model.Say(verdict == good)
	}
	c.guard.AntivirusHealth = health(watchAntivirus)
	c.guard.FirewallHealth = health(watchFirewall)
	if !objects {
		return
	}
	c.guard.Antivirus = products(watchAntivirus)
	c.guard.FirewallProducts = products(watchFirewall)
}

var (
	productListClass = com.ID("17072F7B-9ABE-4A74-A261-1EB76B55107A")
	productList      = com.ID("722A338C-6E8E-4E72-AC27-1417FB0C81C2") // IWSCProductList
)

// products lists the security products of one kind that Windows Security
// knows of. Every function used only reads.
func products(provider uintptr) []model.SecurityProduct {
	list, err := com.Create(productListClass, productList)
	if err != nil {
		return nil
	}
	defer list.Release()
	const initialise, getCount, getItem = 7, 8, 9
	const getName, getState, getSignatures = 7, 8, 9
	if r := list.Call(initialise, provider); com.Failed(r) {
		return nil
	}
	var count int32
	if r := list.Call(getCount, uintptr(unsafe.Pointer(&count))); com.Failed(r) {
		return nil
	}
	var found []model.SecurityProduct
	for i := int32(0); i < count; i++ {
		var pointer unsafe.Pointer
		if r := list.Call(getItem, uintptr(i), uintptr(unsafe.Pointer(&pointer))); com.Failed(r) || pointer == nil {
			continue
		}
		product := com.Wrap(pointer)
		var name uintptr
		state, signatures := int32(-1), int32(-1)
		product.Call(getName, uintptr(unsafe.Pointer(&name)))
		product.Call(getState, uintptr(unsafe.Pointer(&state)))
		product.Call(getSignatures, uintptr(unsafe.Pointer(&signatures)))
		product.Release()
		const on, upToDate = 0, 1
		entry := model.SecurityProduct{Name: com.Text(name)}
		if state >= 0 {
			entry.On = model.Say(state == on)
		}
		if signatures >= 0 {
			entry.UpToDate = model.Say(signatures == upToDate)
		}
		found = append(found, entry)
	}
	return found
}

// defender reads Microsoft Defender's own settings.
func (c *collector) defender() {
	const defender = `SOFTWARE\Microsoft\Windows Defender`
	const policy = `SOFTWARE\Policies\Microsoft\Windows Defender`
	// Real-time protection is on unless a setting says otherwise.
	if key, err := reg.Open(reg.Machine, defender+`\Real-Time Protection`, reg.Native); err == nil {
		off, _ := key.Number("DisableRealtimeMonitoring")
		key.Close()
		c.guard.RealTime = model.Say(off != 1)
	}
	for _, place := range []struct{ path, name string }{{policy + `\Real-Time Protection`, "DisableRealtimeMonitoring"}, {policy, "DisableAntiSpyware"}, {defender, "DisableAntiSpyware"}} {
		if off, ok := reg.Number(reg.Machine, place.path, reg.Native, place.name); ok && off == 1 {
			c.guard.RealTime = model.No
		}
	}
	// Tamper protection stops other programs from changing these settings.
	// Windows stores it as a number that is odd when the protection is on.
	if tamper, ok := reg.Number(reg.Machine, defender+`\Features`, reg.Native, "TamperProtection"); ok {
		c.guard.Tamper = model.Say(tamper&1 == 1)
	}
	// What Defender has been told not to scan.
	refused := false
	for _, base := range []string{defender, policy} {
		for _, kind := range []struct{ key, name string }{{"Paths", "Folder or file"}, {"Extensions", "File type"}, {"Processes", "Program"}, {"TemporaryPaths", "Folder or file"}} {
			key, err := reg.Open(reg.Machine, base+`\Exclusions\`+kind.key, reg.Native)
			if err != nil {
				refused = refused || reg.Refused(err)
				continue
			}
			c.guard.ExclusionsVisible = true
			for _, value := range key.Values() {
				if value.Name != "" {
					c.guard.Exclusions = append(c.guard.Exclusions, model.Exclusion{Kind: kind.name, Value: value.Name})
				}
			}
			key.Close()
		}
	}
	if refused && !c.guard.ExclusionsVisible {
		c.gap(model.Protection, "The list of folders and programs that Microsoft Defender skips can only be read with administrator rights.")
	} else if !refused && !c.guard.ExclusionsVisible {
		c.guard.ExclusionsVisible = true // nothing to refuse: there is no list on this PC
	}
}

// history reads Microsoft Defender's own log: what it found lately, and
// which exclusions the log shows being added.
func (c *collector) history() {
	c.guard.HistoryDays = HistoryDays
	finds, err := eventlog.Read(HistoryLog, eventlog.Where(eventlog.Numbered(foundByScan, foundBehaviour, found, acted), eventlog.Since(HistoryDays)), 400)
	switch {
	case errors.Is(err, eventlog.ErrMissing):
		return // no Microsoft Defender on this PC, so no log of it
	case errors.Is(err, eventlog.ErrDenied):
		c.gap(model.Protection, "Windows does not let this account read Microsoft Defender's log of what it found.")
		return
	case err != nil:
		c.gap(model.Protection, "Microsoft Defender's log of what it found could not be read: "+err.Error()+".")
		return
	}
	c.guard.HistoryRead = true
	c.guard.Detections = Detections(finds)
	// Every change of a setting, as far back as the log goes. Most are of no
	// interest here: the exclusions are picked out of them.
	if changes, err := eventlog.ReadPlain(HistoryLog, eventlog.Where(eventlog.Numbered(realTimeOff, settingChanged)), 6000); err == nil || len(changes) > 0 {
		c.guard.LoggedExclusions = LoggedExclusions(changes)
		limit := time.Now().AddDate(0, 0, -HistoryDays)
		for _, when := range SwitchedOff(changes) {
			if when.After(limit) {
				c.guard.SwitchedOff = append(c.guard.SwitchedOff, when)
			}
		}
	}
}

// firewall reads whether Windows Firewall is on for each kind of network.
func (c *collector) firewall() {
	const settings = `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\`
	const policy = `SOFTWARE\Policies\Microsoft\WindowsFirewall\`
	for _, profile := range []struct{ key, name string }{{"StandardProfile", "Private networks"}, {"PublicProfile", "Public networks"}, {"DomainProfile", "Work networks"}} {
		entry := model.FirewallProfile{Name: profile.name}
		if on, ok := reg.Number(reg.Machine, settings+profile.key, reg.Native, "EnableFirewall"); ok {
			entry.On = model.Say(on == 1)
		}
		// A setting pushed by an organisation wins over the PC's own.
		if on, ok := reg.Number(reg.Machine, policy+profile.key, reg.Native, "EnableFirewall"); ok {
			entry.On = model.Say(on == 1)
		}
		c.guard.Firewall = append(c.guard.Firewall, entry)
	}
}

// accountControl reads User Account Control, the prompt that asks before a
// program is given administrator rights.
func (c *collector) accountControl() {
	const system = `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
	if on, ok := reg.Number(reg.Machine, system, reg.Native, "EnableLUA"); ok {
		c.guard.UAC = model.Say(on == 1)
	}
	// Zero means administrators are let through without being asked, which
	// is what the lowest position of the slider in Control Panel sets.
	if prompt, ok := reg.Number(reg.Machine, system, reg.Native, "ConsentPromptBehaviorAdmin"); ok {
		c.guard.UACSilent = model.Say(prompt == 0)
	}
	if secure, ok := reg.Number(reg.Machine, `SYSTEM\CurrentControlSet\Control\SecureBoot\State`, reg.Native, "UEFISecureBootEnabled"); ok {
		c.guard.SecureBoot = model.Say(secure == 1)
	}
	const logon = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
	if auto, ok := reg.Text(reg.Machine, logon, reg.Native, "AutoAdminLogon"); ok {
		c.guard.AutoSignIn = model.Say(strings.TrimSpace(auto) == "1")
		if c.guard.AutoSignIn == model.Yes {
			c.guard.AutoUser, _ = reg.Text(reg.Machine, logon, reg.Native, "DefaultUserName")
		}
	} else {
		c.guard.AutoSignIn = model.No
	}
}

// updates works out when Windows last installed an update. Windows keeps a
// record of every update package with the moment it went in; the newest of
// those moments is the answer.
func (c *collector) updates() {
	c.guard.Build = pcinfo.Build()
	packages, err := reg.Open(reg.Machine, `SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages`, reg.Native)
	if err != nil {
		c.gap(model.Protection, "When Windows last installed an update could not be read.")
		return
	}
	defer packages.Close()
	var newest int64
	for _, name := range packages.Subkeys() {
		// Monthly updates are recorded as Package_for_RollupFix or
		// Package_for_KB and a number.
		if !strings.HasPrefix(strings.ToLower(name), "package_for_") {
			continue
		}
		key, err := packages.Sub(name)
		if err != nil {
			continue
		}
		high, hasHigh := key.Number("InstallTimeHigh")
		low, hasLow := key.Number("InstallTimeLow")
		key.Close()
		if moment := int64(high)<<32 | int64(low); hasHigh && hasLow && moment > newest {
			newest = moment
		}
	}
	const windowsEpoch = 116444736000000000 // Windows counts from the year 1601
	if newest > windowsEpoch {
		c.guard.LastUpdate, c.guard.UpdateKnown = time.Unix(0, (newest-windowsEpoch)*100), true
	} else {
		c.gap(model.Protection, "When Windows last installed an update could not be worked out.")
	}
}

var shellItem2 = com.ID("7E9FB0D3-919F-4307-AB2E-9B1860310C93") // IShellItem2

// propertyKey mirrors PROPERTYKEY, the number Windows knows a property of a
// file or drive by.
type propertyKey struct {
	Set    com.GUID
	Number uint32
}

// encryptionKey asks Windows for the number of the property Explorer reads
// to draw a padlock on a drive. Asking by name is safer than writing the
// number down, which differs from what is published in places.
func encryptionKey() (key propertyKey, ok bool) {
	if keyFromName.Find() != nil {
		return key, false
	}
	name, _ := syscall.UTF16PtrFromString("System.Volume.BitLockerProtection")
	r, _, _ := keyFromName.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&key)))
	return key, r == 0
}

// volumes asks, for each fixed disk, whether it is encrypted. The usual
// tools for this need administrator rights. Explorer's own property for
// the padlock it draws on a drive does not, so that is what is read.
func (c *collector) volumes(objects bool) {
	encryptionProperty, known := encryptionKey()
	if !objects || !known || shellItem.Find() != nil {
		c.gap(model.Protection, "Whether the disks are encrypted could not be read.")
		return
	}
	mask, _, _ := logicalDrives.Call()
	for letter := 0; letter < 26; letter++ {
		if mask&(1<<letter) == 0 {
			continue
		}
		drive := string(rune('A'+letter)) + ":"
		root, _ := syscall.UTF16PtrFromString(drive + `\`)
		const fixedDisk = 3
		if kind, _, _ := driveType.Call(uintptr(unsafe.Pointer(root))); kind != fixedDisk {
			continue
		}
		volume := model.Volume{Drive: drive}
		var pointer unsafe.Pointer
		name, _ := syscall.UTF16PtrFromString(drive)
		if r, _, _ := shellItem.Call(uintptr(unsafe.Pointer(name)), 0, uintptr(unsafe.Pointer(&shellItem2)), uintptr(unsafe.Pointer(&pointer))); r == 0 && pointer != nil {
			item := com.Wrap(pointer)
			var value com.Variant
			const getProperty, wholeNumber = 13, 3
			if r := item.Call(getProperty, uintptr(unsafe.Pointer(&encryptionProperty)), uintptr(unsafe.Pointer(&value))); r == 0 && value.Kind == wholeNumber {
				volume.Encrypted, volume.State = encryption(int32(value.Value))
			}
			item.Release()
		}
		if volume.Encrypted == model.NotKnown && volume.State == "" {
			volume.State = "Windows did not say"
		}
		c.guard.Volumes = append(c.guard.Volumes, volume)
	}
}

// encryption puts Windows' number for a drive's encryption into words.
func encryption(state int32) (model.Answer, string) {
	switch state {
	case 1:
		return model.Yes, "On"
	case 2:
		return model.No, "Off"
	case 3:
		return model.Yes, "Being encrypted now"
	case 4:
		return model.No, "Being decrypted now"
	case 5:
		return model.No, "Encrypted, but the protection is paused"
	case 6:
		return model.Yes, "On (locked)"
	}
	return model.NotKnown, ""
}

// remoteDesktop reads whether this PC accepts Remote Desktop connections.
func (c *collector) remoteDesktop() {
	const server = `SYSTEM\CurrentControlSet\Control\Terminal Server`
	if refuse, ok := reg.Number(reg.Machine, server, reg.Native, "fDenyTSConnections"); ok {
		c.guard.RemoteDesktop = model.Say(refuse == 0)
	}
	if refuse, ok := reg.Number(reg.Machine, `SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`, reg.Native, "fDenyTSConnections"); ok {
		c.guard.RemoteDesktop = model.Say(refuse == 0)
	}
	if early, ok := reg.Number(reg.Machine, server+`\WinStations\RDP-Tcp`, reg.Native, "UserAuthentication"); ok {
		c.guard.RemoteNLA = model.Say(early == 1)
	}
}

// accounts lists who is in the Administrators group and whether the Guest
// account is switched on.
func (c *collector) accounts() {
	// Every local account, to see which are switched off and which are the
	// two that every PC has: Administrator (ending -500) and Guest (-501).
	type user struct {
		Name, Password     *uint16
		PasswordAge, Level uint32
		Home, Comment      *uint16
		Flags              uint32
		Script             *uint16
	}
	const normalAccounts, everything, switchedOff = 2, ^uint32(0), 0x2
	disabled, builtIn := map[string]bool{}, map[string]string{}
	var buffer uintptr
	var read, total, resume uint32
	if r, _, _ := userList.Call(0, 1, normalAccounts, uintptr(unsafe.Pointer(&buffer)), uintptr(everything), uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&resume))); r == 0 && buffer != 0 {
		for _, u := range unsafe.Slice((*user)(at(buffer)), read) {
			name := wide(u.Name)
			disabled[strings.ToLower(name)] = u.Flags&switchedOff != 0
			if sid, _, _, err := syscall.LookupSID("", name); err == nil {
				if text, err := sid.String(); err == nil {
					switch {
					case strings.HasSuffix(text, "-500"):
						builtIn[strings.ToLower(name)] = "Administrator"
					case strings.HasSuffix(text, "-501"):
						builtIn[strings.ToLower(name)] = "Guest"
						c.guard.Guest = model.Say(u.Flags&switchedOff == 0)
					}
				}
			}
		}
		netFree.Call(buffer)
	}

	// The Administrators group has another name in other languages, so it
	// is found by its number, which is the same everywhere.
	administrators, err := syscall.StringToSid("S-1-5-32-544")
	if err != nil {
		return
	}
	group, _, _, err := administrators.LookupAccount("")
	if err != nil {
		c.gap(model.Accounts, "The Administrators group could not be found.")
		return
	}
	groupName, _ := syscall.UTF16PtrFromString(group)
	type member struct {
		SID  *syscall.SID
		Use  uint32
		Name *uint16
	}
	buffer, read, total = 0, 0, 0
	var next uintptr
	if r, _, _ := groupMembers.Call(0, uintptr(unsafe.Pointer(groupName)), 2, uintptr(unsafe.Pointer(&buffer)), uintptr(everything), uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&next))); r != 0 || buffer == 0 {
		c.gap(model.Accounts, fmt.Sprintf("The members of the Administrators group could not be read (Windows error %d).", r))
		return
	}
	defer netFree.Call(buffer)
	c.guard.AdminsVisible = true
	computer, _ := os.Hostname()
	for _, m := range unsafe.Slice((*member)(at(buffer)), read) {
		const oneUser = 1
		name := wide(m.Name)
		account := model.Account{Name: name, Group: m.Use != oneUser}
		// A local account is written PC\name. Show the name alone.
		if domain, short, found := strings.Cut(name, `\`); found && strings.EqualFold(domain, computer) {
			account.Name = short
			if off, known := disabled[strings.ToLower(short)]; known {
				account.Disabled = model.Say(off)
			}
			account.BuiltIn = builtIn[strings.ToLower(short)]
		}
		c.guard.Admins = append(c.guard.Admins, account)
	}
}

// hosts reads the hosts file from wherever this PC is set to keep it.
func (c *collector) hosts() {
	folder := winpath.Join(sysdll.Folder(), `drivers\etc`)
	if set, ok := reg.Text(reg.Machine, `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`, reg.Native, "DataBasePath"); ok && strings.TrimSpace(set) != "" {
		folder = winpath.Tidy(pcinfo.Expand(set))
	}
	c.guard.HostsPath = winpath.Join(folder, "hosts")
	text, err := os.ReadFile(c.guard.HostsPath)
	switch {
	case err == nil:
		c.guard.HostsVisible = true
		c.guard.Hosts = ParseHosts(string(text))
	case os.IsNotExist(err):
		c.guard.HostsVisible = true // no file means no entries
	default:
		c.gap(model.Protection, "The hosts file could not be opened.")
	}
}

// programs lists what is installed, as Settings shows it under Apps.
func (c *collector) programs() {
	const uninstall = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
	seen := map[string]bool{}
	for _, place := range []struct {
		root syscall.Handle
		view reg.View
	}{{reg.Machine, reg.Native}, {reg.Machine, reg.Compat}, {reg.User, reg.Native}} {
		list, err := reg.Open(place.root, uninstall, place.view)
		if err != nil {
			continue
		}
		for _, name := range list.Subkeys() {
			key, err := list.Sub(name)
			if err != nil {
				continue
			}
			title, _ := key.Text("DisplayName")
			publisher, _ := key.Text("Publisher")
			location, _ := key.Text("InstallLocation")
			key.Close()
			if title = strings.TrimSpace(title); title == "" || seen[strings.ToLower(title)] {
				continue
			}
			seen[strings.ToLower(title)] = true
			c.guard.Programs = append(c.guard.Programs, model.Installed{Name: title, Publisher: strings.TrimSpace(publisher), Location: strings.Trim(strings.TrimSpace(location), `"`)})
		}
		list.Close()
	}
	sort.Slice(c.guard.Programs, func(i, j int) bool {
		return strings.ToLower(c.guard.Programs[i].Name) < strings.ToLower(c.guard.Programs[j].Name)
	})
}
