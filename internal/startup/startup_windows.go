//go:build windows

package startup

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"lazascope/internal/browsers"
	"lazascope/internal/cmdline"
	"lazascope/internal/com"
	"lazascope/internal/model"
	"lazascope/internal/pcinfo"
	"lazascope/internal/reg"
	"lazascope/internal/services"
	"lazascope/internal/winpath"
)

type collector struct {
	world   cmdline.World
	entries []model.Startup
	gaps    []model.Gap
}

// Collect gathers everything set to start by itself. It only reads. What
// could not be read is returned as gaps, to be shown instead of left out.
func Collect(world cmdline.World) ([]model.Startup, []model.Gap) {
	c := &collector{world: world}
	// Shortcuts and Task Scheduler are reached through COM.
	leave, err := com.Enter()
	defer leave()
	c.runLists()
	c.otherAccounts()
	c.folders(err == nil)
	c.storeApps()
	if err == nil {
		c.tasks()
	} else {
		c.gap("Scheduled tasks could not be read: " + err.Error() + ".")
	}
	c.services()
	c.settings()
	c.extensions()
	return c.entries, c.gaps
}

func (c *collector) gap(what string) {
	c.gaps = append(c.gaps, model.Gap{Area: model.StartsWithWindows, What: what})
}

// add records an entry whose command has been taken apart.
func (c *collector) add(entry model.Startup, read cmdline.Command) {
	entry.Program.Path, entry.Arguments = read.Program, read.Arguments
	entry.Target.Path = read.Works()
	entry.Untraced = !read.Found
	c.entries = append(c.entries, entry)
}

const currentVersion = `Software\Microsoft\Windows\CurrentVersion\`

// runList is one of the registry's lists of programs to start at sign-in.
type runList struct {
	root     syscall.Handle
	path     string
	view     reg.View
	kind     model.StartupKind
	shown    string // the key as a person would write it
	approved string // the list in which Task Manager keeps this one's on and off switches
}

// values returns the text values of a key as name and command.
func values(root syscall.Handle, path string, view reg.View) (found [][2]string, exists bool) {
	key, err := reg.Open(root, path, view)
	if err != nil {
		return nil, false
	}
	defer key.Close()
	for _, value := range key.Values() {
		if value.Kind == reg.KindText || value.Kind == reg.KindExpandable {
			if strings.TrimSpace(value.Text) != "" {
				found = append(found, [2]string{value.Name, value.Text})
			}
		}
	}
	return found, true
}

func same(a, b [][2]string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// runLists reads the Run and RunOnce lists, for the whole PC and for this
// account, as 64-bit and as 32-bit programs see them.
func (c *collector) runLists() {
	const wow = `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\`
	lists := []runList{
		{reg.Machine, currentVersion + "Run", reg.Native, model.RunKey, `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "Run"},
		{reg.Machine, currentVersion + "Run", reg.Compat, model.RunKey, `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, "Run32"},
		{reg.Machine, currentVersion + "RunOnce", reg.Native, model.RunOnceKey, `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, ""},
		{reg.Machine, currentVersion + "RunOnce", reg.Compat, model.RunOnceKey, `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`, ""},
		{reg.Machine, currentVersion + `Policies\Explorer\Run`, reg.Native, model.RunKey, `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`, ""},
		{reg.Machine, currentVersion + `Policies\Explorer\Run`, reg.Compat, model.RunKey, `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`, ""},
		{reg.User, currentVersion + "Run", reg.Native, model.RunKey, `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, "Run"},
		{reg.User, currentVersion + "RunOnce", reg.Native, model.RunOnceKey, `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`, ""},
		{reg.User, currentVersion + `Policies\Explorer\Run`, reg.Native, model.RunKey, `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`, ""},
		{reg.User, wow + "Run", reg.Native, model.RunKey, `HKCU\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, "Run32"},
		{reg.User, wow + "RunOnce", reg.Native, model.RunOnceKey, `HKCU\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`, ""},
	}
	for _, list := range lists {
		found, _ := values(list.root, list.path, list.view)
		if list.view == reg.Compat {
			// Some keys are one and the same for 32-bit and 64-bit programs.
			// Reading such a key both ways would list its entries twice.
			if native, _ := values(list.root, list.path, reg.Native); same(found, native) {
				continue
			}
		}
		for _, value := range found {
			name, command := value[0], value[1]
			if name == "" {
				name = "(Default)"
			}
			entry := model.Startup{Kind: list.kind, Name: name, Where: list.shown, AllUsers: list.root == reg.Machine, Command: command, Enabled: true}
			if list.approved != "" && switchedOff(list.approved, name) {
				entry.Enabled = false
			}
			c.add(entry, c.world.Read(command))
		}
	}
}

// otherAccounts reads the Run and RunOnce lists of the other accounts whose
// settings Windows has loaded: the accounts services run as, and anyone
// else who is signed in. Windows' own list of start-up commands includes
// them, and so must this one. An account that is not signed in keeps its
// list in a file that is not opened here.
func (c *collector) otherAccounts() {
	all, err := reg.Open(reg.Users, "", reg.Native)
	if err != nil {
		return
	}
	defer all.Close()
	mine := ""
	if token, err := syscall.OpenCurrentProcessToken(); err == nil {
		if user, err := token.GetTokenUser(); err == nil {
			mine, _ = user.User.Sid.String()
		}
		token.Close()
	}
	refused := 0
	for _, account := range all.Subkeys() {
		// The account in use has been read already. "_Classes" keys hold file
		// types, and S-1-5-18 is a second name for .DEFAULT, the SYSTEM account.
		if strings.EqualFold(account, mine) || strings.HasSuffix(strings.ToLower(account), "_classes") || account == "S-1-5-18" {
			continue
		}
		whose := pcinfo.AccountName(account)
		if account == ".DEFAULT" {
			whose = "SYSTEM"
		}
		opened := false
		for _, list := range []struct {
			name string
			kind model.StartupKind
		}{{"Run", model.RunKey}, {"RunOnce", model.RunOnceKey}} {
			key, err := reg.Open(reg.Users, account+`\`+currentVersion+list.name, reg.Native)
			if err != nil {
				if reg.Refused(err) && !opened {
					refused++
					opened = true // counted once for the account
				}
				continue
			}
			opened = true
			for _, value := range key.Values() {
				if (value.Kind != reg.KindText && value.Kind != reg.KindExpandable) || strings.TrimSpace(value.Text) == "" {
					continue
				}
				name := value.Name
				if name == "" {
					name = "(Default)"
				}
				entry := model.Startup{Kind: list.kind, Name: name, Where: `HKU\` + account + `\` + currentVersion + list.name, Command: value.Text, Enabled: true, Account: whose,
					Trigger: "When the account " + whose + " is signed in"}
				c.add(entry, c.world.Read(value.Text))
			}
			key.Close()
		}
	}
	if refused > 0 {
		what := fmt.Sprintf("The start-up lists of %d other accounts", refused)
		if refused == 1 {
			what = "The start-up list of 1 other account"
		}
		c.gap(what + " " + model.Withheld(pcinfo.Elevated(), refused != 1) + ".")
	}
}

// switchedOff reports whether a start-up entry has been turned off on Task
// Manager's Start-up tab. Task Manager does not remove such an entry. It
// notes the switch in a list of its own, where an odd first byte means off.
func switchedOff(list, name string) bool {
	for _, root := range []syscall.Handle{reg.Machine, reg.User} {
		key, err := reg.Open(root, currentVersion+`Explorer\StartupApproved\`+list, reg.Native)
		if err != nil {
			continue
		}
		state, ok := key.Bytes(name)
		key.Close()
		if ok && len(state) > 0 && state[0]&1 == 1 {
			return true
		}
	}
	return false
}

// folders reads the two Startup folders: this account's and the one for
// every account.
func (c *collector) folders(shortcuts bool) {
	for _, place := range []struct {
		folder   string
		allUsers bool
	}{{pcinfo.KnownFolder(pcinfo.UserStartup), false}, {pcinfo.KnownFolder(pcinfo.CommonStartup), true}} {
		if place.folder == "" {
			continue
		}
		items, err := os.ReadDir(place.folder)
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				c.gap("The Startup folder " + place.folder + " could not be opened.")
			}
			continue
		}
		for _, item := range items {
			name := item.Name()
			if item.IsDir() || strings.EqualFold(name, "desktop.ini") {
				continue
			}
			path := filepath.Join(place.folder, name)
			entry := model.Startup{Kind: model.StartupFolder, Name: name, Where: place.folder, AllUsers: place.allUsers, Command: path, Enabled: !switchedOff("StartupFolder", name)}
			if shortcuts && strings.EqualFold(filepath.Ext(name), ".lnk") {
				if target, arguments := shortcut(path); target != "" {
					entry.Command = strings.TrimSpace(`"` + target + `" ` + arguments)
					c.add(entry, c.world.Launch(target, arguments))
					continue
				}
			}
			c.add(entry, c.world.Launch(path, ""))
		}
	}
}

var (
	shellLinkClass = com.ID("00021401-0000-0000-C000-000000000046")
	shellLink      = com.ID("000214F9-0000-0000-C000-000000000046") // IShellLinkW
	persistFile    = com.ID("0000010B-0000-0000-C000-000000000046") // IPersistFile
)

// shortcut reads where a shortcut (.lnk file) points and what it passes
// along. The shortcut is opened for reading and is not followed or fixed.
func shortcut(path string) (target, arguments string) {
	link, err := com.Create(shellLinkClass, shellLink)
	if err != nil {
		return "", ""
	}
	defer link.Release()
	file, err := link.Ask(persistFile)
	if err != nil {
		return "", ""
	}
	defer file.Release()
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "", ""
	}
	const load, readOnly = 5, 0
	if r := file.Call(load, uintptr(unsafe.Pointer(name)), readOnly); com.Failed(r) {
		return "", ""
	}
	const getPath, getArguments = 3, 10
	buffer := make([]uint16, 32768)
	if r := link.Call(getPath, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 0, 0); r == 0 {
		target = syscall.UTF16ToString(buffer)
	}
	clear(buffer)
	if r := link.Call(getArguments, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer))); r == 0 {
		arguments = syscall.UTF16ToString(buffer)
	}
	return target, arguments
}

// storeApps reads the start-up tasks of apps from the Microsoft Store.
// These show on Task Manager's Start-up tab but are in none of the Run
// lists: each app's switch is kept with the app's own settings.
func (c *collector) storeApps() {
	const appModel = `Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\`
	apps, err := reg.Open(reg.User, appModel+"SystemAppData", reg.Native)
	if err != nil {
		return
	}
	defer apps.Close()
	for _, family := range apps.Subkeys() {
		app, err := apps.Sub(family)
		if err != nil {
			continue
		}
		for _, id := range app.Subkeys() {
			task, err := app.Sub(id)
			if err != nil {
				continue
			}
			state, ok := task.Number("State")
			task.Close()
			if !ok {
				continue
			}
			const on, onByPolicy = 2, 4
			entry := model.Startup{Kind: model.StoreApp, Name: id, Where: "Store app " + family, Enabled: state == on || state == onByPolicy}
			folder, title := packageFolder(appModel, family)
			entry.Title = title
			if folder != "" {
				if manifest, err := os.ReadFile(filepath.Join(folder, "AppxManifest.xml")); err == nil {
					executable, declared := StartupExecutable(manifest, id)
					if !declared {
						continue // a key that happens to hold a State, not a start-up task
					}
					if executable != "" {
						path := filepath.Join(folder, executable)
						entry.Command = path
						c.add(entry, c.world.Launch(path, ""))
						continue
					}
				}
			}
			entry.Untraced = true
			c.entries = append(c.entries, entry)
		}
		app.Close()
	}
}

// packageFolder finds where the app of a package family is installed, and
// the app's name. A family is written Name_PublisherCode; the installed
// package adds the version and more between the two.
func packageFolder(appModel, family string) (folder, title string) {
	cut := strings.LastIndexByte(family, '_')
	if cut <= 0 {
		return "", ""
	}
	name, publisher := strings.ToLower(family[:cut])+"_", "_"+strings.ToLower(family[cut+1:])
	packages, err := reg.Open(reg.User, appModel+`Repository\Packages`, reg.Native)
	if err != nil {
		return "", ""
	}
	defer packages.Close()
	for _, full := range packages.Subkeys() {
		lower := strings.ToLower(full)
		if !strings.HasPrefix(lower, name) || !strings.HasSuffix(lower, publisher) {
			continue
		}
		key, err := packages.Sub(full)
		if err != nil {
			continue
		}
		root, _ := key.Text("PackageRootFolder")
		shown, _ := key.Text("DisplayName")
		key.Close()
		if root == "" {
			continue
		}
		if _, err := os.Stat(filepath.Join(root, "AppxManifest.xml")); err != nil {
			continue
		}
		// Language and scale packs share the family and have a manifest too,
		// but only the main package says what the app runs.
		if manifest, err := os.ReadFile(filepath.Join(root, "AppxManifest.xml")); err == nil && strings.Contains(string(manifest), "<Application") {
			return root, pcinfo.Indirect(shown)
		}
	}
	return "", ""
}

var (
	schedulerClass = com.ID("0F87369F-A4E5-4CFC-BD3E-73E6154572DD")
	taskService    = com.ID("2FABA4C7-4DA9-4013-9697-20CC3FD40F85") // ITaskService
)

// Places in the tables of the Task Scheduler objects. Only functions that
// read are used. The ones that would run, change or delete a task are left
// alone, and each place used here has only other reading functions next to
// it in its table.
const (
	serviceGetFolder = 7
	serviceConnect   = 10
	folderGetFolders = 10
	folderGetTasks   = 14
	listCount        = 7
	listItem         = 8
	taskGetPath      = 8
	taskGetState     = 9
	taskGetXML       = 20
)

// tasks reads every scheduled task this account is allowed to see.
func (c *collector) tasks() {
	service, err := com.Create(schedulerClass, taskService)
	if err != nil {
		c.gap("Scheduled tasks could not be read: Task Scheduler did not answer.")
		return
	}
	defer service.Release()
	// Connect to this PC as the account in use: four empty values.
	var server, user, domain, password com.Variant
	if r := service.Call(serviceConnect, uintptr(unsafe.Pointer(&server)), uintptr(unsafe.Pointer(&user)), uintptr(unsafe.Pointer(&domain)), uintptr(unsafe.Pointer(&password))); com.Failed(r) {
		c.gap(fmt.Sprintf("Scheduled tasks could not be read: Task Scheduler refused the connection (0x%08X).", uint32(r)))
		return
	}
	top := com.String(`\`)
	defer com.Free(top)
	var folder unsafe.Pointer
	if r := service.Call(serviceGetFolder, top, uintptr(unsafe.Pointer(&folder))); com.Failed(r) || folder == nil {
		c.gap("Scheduled tasks could not be read: the list of tasks would not open.")
		return
	}
	unreadable := 0
	c.taskFolder(com.Wrap(folder), 0, &unreadable)
	if unreadable > 0 {
		what := fmt.Sprintf("%d scheduled tasks are listed, but their details", unreadable)
		if unreadable == 1 {
			what = "1 scheduled task is listed, but its details"
		}
		c.gap(what + " " + model.Withheld(pcinfo.Elevated(), true) + ".")
	}
	if !pcinfo.Elevated() {
		// Task Scheduler leaves these out without a word, so nothing here
		// can count them. Saying nothing would pass a short list off as the
		// whole one.
		c.gap("Windows shows some scheduled tasks to administrators only, so they are missing from this list. There are usually a few dozen. Most are parts of Windows and of software updaters, but not always all. Look again as administrator to see them.")
	}
}

// each calls visit with every item of a Task Scheduler list.
func each(list *com.Object, visit func(item *com.Object)) {
	defer list.Release()
	var count int32
	if r := list.Call(listCount, uintptr(unsafe.Pointer(&count))); com.Failed(r) {
		return
	}
	for i := int32(1); i <= count; i++ {
		index := com.Number(i)
		var item unsafe.Pointer
		if r := list.Call(listItem, uintptr(unsafe.Pointer(&index)), uintptr(unsafe.Pointer(&item))); com.Failed(r) || item == nil {
			continue
		}
		visit(com.Wrap(item))
	}
}

func (c *collector) taskFolder(folder *com.Object, depth int, unreadable *int) {
	defer folder.Release()
	const hiddenToo = 1
	var list unsafe.Pointer
	if r := folder.Call(folderGetTasks, hiddenToo, uintptr(unsafe.Pointer(&list))); !com.Failed(r) && list != nil {
		each(com.Wrap(list), func(task *com.Object) { c.task(task, unreadable) })
	}
	if depth >= 16 {
		return
	}
	list = nil
	if r := folder.Call(folderGetFolders, 0, uintptr(unsafe.Pointer(&list))); !com.Failed(r) && list != nil {
		each(com.Wrap(list), func(inner *com.Object) { c.taskFolder(inner, depth+1, unreadable) })
	}
}

func (c *collector) task(task *com.Object, unreadable *int) {
	defer task.Release()
	var path, document uintptr
	var state int32
	task.Call(taskGetPath, uintptr(unsafe.Pointer(&path)))
	task.Call(taskGetState, uintptr(unsafe.Pointer(&state)))
	name := com.Text(path)
	if r := task.Call(taskGetXML, uintptr(unsafe.Pointer(&document))); com.Failed(r) || document == 0 {
		*unreadable++
		c.entries = append(c.entries, model.Startup{Kind: model.ScheduledTask, Name: name, Where: "Task Scheduler", AllUsers: true, Enabled: true, Untraced: true})
		return
	}
	parsed, err := ParseTask(com.Text(document))
	if err != nil {
		*unreadable++
		c.entries = append(c.entries, model.Startup{Kind: model.ScheduledTask, Name: name, Where: "Task Scheduler", AllUsers: true, Enabled: true, Untraced: true})
		return
	}
	const disabled, running = 1, 4
	entry := model.Startup{
		Kind: model.ScheduledTask, Name: name, Where: "Task Scheduler", AllUsers: true,
		Enabled: parsed.Enabled && state != disabled, Running: state == running,
		Account: pcinfo.AccountName(parsed.Account), Trigger: strings.Join(parsed.Triggers, "; "),
		Description: pcinfo.Indirect(parsed.Description),
	}
	if entry.Trigger == "" {
		entry.Trigger = "Only when something asks for it"
	}
	if len(parsed.Actions) == 0 {
		entry.Untraced = true
		c.entries = append(c.entries, entry)
		return
	}
	for _, action := range parsed.Actions {
		if action.Class != "" {
			// The task calls a Windows component by its number instead of
			// starting a program. The registry says which file that is.
			entry := entry
			entry.Command = "Windows component " + action.Class
			library := c.component(action.Class)
			entry.Program.Path, entry.Target.Path, entry.Untraced = library, library, library == ""
			c.entries = append(c.entries, entry)
			continue
		}
		entry := entry
		entry.Command = strings.TrimSpace(action.Command + " " + action.Arguments)
		read := c.world.Launch(action.Command, action.Arguments)
		if !read.Found {
			// Some tasks put the whole line in the place meant for the program.
			if whole := c.world.Read(entry.Command); whole.Found {
				read = whole
			}
		}
		c.add(entry, read)
	}
}

// component returns the file behind a Windows component's number, or "".
func (c *collector) component(class string) string {
	for _, view := range []reg.View{reg.Native, reg.Compat} {
		library, _ := reg.Text(reg.Classes, `CLSID\`+class+`\InprocServer32`, view, "")
		server, _ := reg.Text(reg.Classes, `CLSID\`+class+`\LocalServer32`, view, "")
		if library != "" {
			if path, _ := c.world.Locate(library); path != "" {
				return path
			}
		}
		if server != "" {
			return c.world.Read(server).Works()
		}
	}
	return ""
}

// services reads the services and drivers that Windows starts by itself.
func (c *collector) services() {
	running, titles := map[string]bool{}, map[string]string{}
	if states, err := services.List(); err == nil || len(states) > 0 {
		for _, state := range states {
			running[strings.ToLower(state.Name)] = state.Running
			titles[strings.ToLower(state.Name)] = state.Title
		}
	} else {
		c.gap("Which services are running now could not be read.")
	}
	const where = `SYSTEM\CurrentControlSet\Services`
	all, err := reg.Open(reg.Machine, where, reg.Native)
	if err != nil {
		c.gap("The list of services and drivers could not be read.")
		return
	}
	defer all.Close()
	refused := 0
	for _, name := range all.Subkeys() {
		key, err := all.Sub(name)
		if err != nil {
			if reg.Refused(err) {
				refused++
			}
			continue
		}
		kind, _ := key.Number("Type")
		start, hasStart := key.Number("Start")
		image, _ := key.Text("ImagePath")
		account, _ := key.Text("ObjectName")
		description, _ := key.Text("Description")
		title, _ := key.Text("DisplayName")
		delayed, _ := key.Number("DelayedAutostart")
		library, _ := reg.Text(reg.Machine, where+`\`+name+`\Parameters`, reg.Native, "ServiceDll")
		if library == "" {
			library, _ = key.Text("ServiceDll")
		}
		key.Close()
		// Windows comes with drivers for disk controllers this PC may not
		// have. They are recorded as loading at boot, and beside that record
		// Windows keeps an override that says "not on this hardware". The
		// override is what counts, and it is what Windows itself reports.
		if override, ok := reg.Number(reg.Machine, where+`\`+name+`\StartOverride`, reg.Native, "0"); ok {
			start = override
		}

		const (
			kernelDriver, fileDriver = 0x01, 0x02
			ownProgram, sharedHost   = 0x10, 0x20
			perUserModel, perUser    = 0x40, 0x80
			boot, system, automatic  = 0, 1, 2
		)
		driver := kind&(kernelDriver|fileDriver) != 0
		service := kind&(ownProgram|sharedHost) != 0
		if !hasStart || (!driver && !service) {
			continue
		}
		// Only what starts by itself: automatic services, and drivers
		// loaded while or just after Windows starts. Windows also keeps a
		// pattern for each service that runs once per signed-in user; the
		// pattern itself never runs, so only the copies made from it count.
		if start > automatic || (service && start != automatic) || (kind&perUserModel != 0 && kind&perUser == 0) {
			continue
		}
		entry := model.Startup{
			Kind: model.Service, Name: name, Where: `HKLM\` + where + `\` + name, AllUsers: true, Command: image,
			Enabled: true, Running: running[strings.ToLower(name)], Description: pcinfo.Indirect(description),
			Trigger: "When Windows starts",
		}
		shown := titles[strings.ToLower(name)]
		if shown == "" {
			shown = pcinfo.Indirect(title)
		}
		if shown != "" && !strings.EqualFold(shown, name) {
			entry.Title = shown
		}
		if driver {
			entry.Kind = model.Driver
			switch start {
			case boot:
				entry.Trigger = "While Windows is loading"
			case system:
				entry.Trigger = "As Windows starts"
			}
			if image == "" {
				image = `System32\drivers\` + name + `.sys` // where Windows looks when no file is named
				entry.Command = image
			}
			path, found := c.world.Locate(image)
			entry.Program.Path, entry.Target.Path, entry.Untraced = path, path, !found
			c.entries = append(c.entries, entry)
			continue
		}
		entry.Account = services.Plain(account)
		if delayed == 1 {
			entry.Trigger = "A little after Windows starts"
		}
		read := c.world.Read(image)
		// Many services share one host program, svchost. The service
		// itself is a library, named in the registry.
		if winpath.Stem(read.Program) == "svchost" && library != "" {
			read.Target = c.world.Tidy(library)
		}
		c.add(entry, read)
	}
	if refused > 0 {
		what := fmt.Sprintf("%d services or drivers", refused)
		if refused == 1 {
			what = "1 service or driver"
		}
		if elevated := pcinfo.Elevated(); elevated {
			c.gap(what + " " + model.Withheld(true, refused != 1) + ".")
		} else if refused == 1 {
			c.gap(what + " is protected and can only be read with administrator rights.")
		} else {
			c.gap(what + " are protected and can only be read with administrator rights.")
		}
	}
}

// extensions reads the extensions added to this account's web browsers.
// The browsers keep them in plain files, which are opened for reading.
func (c *collector) extensions() {
	found, unread := browsers.List(browsers.Folders{Local: os.Getenv("LOCALAPPDATA"), Roaming: os.Getenv("APPDATA")})
	for _, note := range unread {
		c.gap(note)
	}
	for i := range found {
		extension := found[i]
		c.entries = append(c.entries, model.Startup{Kind: model.BrowserExtension, Name: extension.Name, Where: extension.Browser + ", profile " + extension.Profile,
			Enabled: extension.Enabled, Trigger: "Whenever " + extension.Browser + " is open", Description: extension.About, Extension: &extension})
	}
}

// settings reads three settings that are meant for something else and get
// misused to start programs: the sign-in programs, debugger settings and
// the libraries loaded into every program.
func (c *collector) settings() {
	const windowsNT = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\`

	// What Windows runs as a user signs in. Normally the desktop
	// (explorer.exe) and a helper that prepares it (userinit.exe).
	for _, place := range []struct {
		root  syscall.Handle
		shown string
	}{{reg.Machine, `HKLM\` + windowsNT + "Winlogon"}, {reg.User, `HKCU\` + windowsNT + "Winlogon"}} {
		for _, value := range []string{"Shell", "Userinit"} {
			line, ok := reg.Text(place.root, windowsNT+"Winlogon", reg.Native, value)
			if !ok {
				continue
			}
			for _, command := range strings.Split(line, ",") {
				if command = strings.TrimSpace(command); command == "" {
					continue
				}
				entry := model.Startup{Kind: model.LogonSetting, Name: value, Where: place.shown, AllUsers: place.root == reg.Machine, Command: command, Enabled: true, Trigger: "When someone signs in"}
				c.add(entry, c.world.Read(command))
			}
		}
	}

	// A "debugger" set for a program makes Windows start the debugger in
	// its place.
	seen := map[string]bool{}
	for _, view := range []reg.View{reg.Native, reg.Compat} {
		options, err := reg.Open(reg.Machine, windowsNT+"Image File Execution Options", view)
		if err != nil {
			continue
		}
		for _, program := range options.Subkeys() {
			key, err := options.Sub(program)
			if err != nil {
				continue
			}
			debugger, ok := key.Text("Debugger")
			key.Close()
			if !ok || strings.TrimSpace(debugger) == "" || seen[strings.ToLower(program+"|"+debugger)] {
				continue
			}
			seen[strings.ToLower(program+"|"+debugger)] = true
			entry := model.Startup{Kind: model.DebuggerSetting, Name: program, Subject: program, Where: `HKLM\` + windowsNT + `Image File Execution Options\` + program, AllUsers: true,
				Command: debugger, Enabled: true, Trigger: "Whenever " + program + " is opened"}
			c.add(entry, c.world.Read(debugger))
		}
		options.Close()
	}

	// Libraries Windows loads into every program that shows a window.
	seen = map[string]bool{}
	for _, view := range []reg.View{reg.Native, reg.Compat} {
		key, err := reg.Open(reg.Machine, windowsNT+"Windows", view)
		if err != nil {
			continue
		}
		libraries, _ := key.Text("AppInit_DLLs")
		load, _ := key.Number("LoadAppInit_DLLs")
		key.Close()
		for _, library := range strings.FieldsFunc(libraries, func(r rune) bool { return r == ',' || r == ' ' }) {
			if seen[strings.ToLower(library)] {
				continue
			}
			seen[strings.ToLower(library)] = true
			path, found := c.world.Locate(library)
			entry := model.Startup{Kind: model.LoadedLibrary, Name: winpath.Base(library), Where: `HKLM\` + windowsNT + `Windows\AppInit_DLLs`, AllUsers: true, Command: library,
				Enabled: load == 1, Trigger: "Whenever a program with a window starts", Untraced: !found}
			entry.Program.Path, entry.Target.Path = path, path
			c.entries = append(c.entries, entry)
		}
	}
}
