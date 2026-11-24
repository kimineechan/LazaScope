//go:build windows

package wallets

import (
	"encoding/json"
	"os"
	"path/filepath"

	"lazascope/internal/model"
	"lazascope/internal/reg"
)

// Collect reads what the cryptocurrency checks need, and lists every wallet
// in the look: the folders of wallet files that exist, the folders a cloud
// service copies off the PC, and what Windows keeps of the clipboard. It
// only checks that folders exist: no wallet file is opened.
func Collect(s *model.Snapshot) {
	s.Clouds = clouds()
	s.Clipboard = clipboardSettings()
	under := map[string]string{"appdata": os.Getenv("APPDATA"), "localappdata": os.Getenv("LOCALAPPDATA"), "documents": shellFolder("Personal")}
	var found []model.Wallet
	seen := map[string]bool{}
	for _, f := range folders {
		base := under[f.under]
		if base == "" || seen[f.wallet] {
			continue
		}
		path := filepath.Join(base, f.path)
		if _, err := os.Stat(path); err == nil {
			seen[f.wallet] = true
			found = append(found, model.Wallet{Name: f.wallet, Kind: "Wallet files", Where: path, Keys: f.keys})
		}
	}
	s.Wallets = Inventory(s, found)
}

// shellFolder returns where one of the account's own folders is, such as
// Documents, which can have been moved into OneDrive.
func shellFolder(name string) string {
	path, _ := reg.Text(reg.User, `Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`, reg.Native, name)
	return path
}

// clouds returns the folders that OneDrive, Dropbox and iCloud Drive copy
// off the PC, as they record them for the account.
func clouds() []model.CloudFolder {
	var out []model.CloudFolder
	seen := map[string]bool{}
	add := func(service, path string) {
		if path == "" || seen[path] {
			return
		}
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			seen[path] = true
			out = append(out, model.CloudFolder{Service: service, Path: path})
		}
	}
	for _, name := range []string{"OneDrive", "OneDriveConsumer", "OneDriveCommercial"} {
		add("OneDrive", os.Getenv(name))
	}
	// Dropbox writes where its folders are into a small file of its own.
	for _, base := range []string{os.Getenv("LOCALAPPDATA"), os.Getenv("APPDATA")} {
		content, err := os.ReadFile(filepath.Join(base, "Dropbox", "info.json"))
		if err != nil || len(content) > 1<<16 {
			continue
		}
		var info map[string]struct {
			Path string `json:"path"`
		}
		if json.Unmarshal(content, &info) == nil {
			for _, account := range info {
				add("Dropbox", account.Path)
			}
		}
	}
	if profile, err := os.UserHomeDir(); err == nil {
		add("iCloud Drive", filepath.Join(profile, "iCloudDrive"))
	}
	return out
}

// clipboardSettings reads whether Windows keeps a history of what is
// copied, and whether it sends it to the account's other devices. Both are
// off until someone switches them on.
func clipboardSettings() model.ClipboardSettings {
	const key = `Software\Microsoft\Clipboard`
	c := model.ClipboardSettings{Read: true, History: model.No, Cloud: model.No}
	if n, ok := reg.Number(reg.User, key, reg.Native, "EnableClipboardHistory"); ok {
		c.History = model.Say(n == 1)
	}
	if n, ok := reg.Number(reg.User, key, reg.Native, "EnableCloudClipboard"); ok {
		c.Cloud = model.Say(n == 1)
	}
	if c.History == model.No {
		c.Cloud = model.No // without a history there is nothing to send
	}
	return c
}
