//go:build windows

package phrase

import (
	"os"
	"strings"

	"lazascope/internal/reg"
	"lazascope/internal/winpath"
)

// Places returns the folders where people keep notes: the account's
// Desktop, Documents and Downloads, wherever Windows has them, and the
// OneDrive folders. A folder inside another one in the list is left out,
// as searching the outer one covers it.
func Places() []string {
	var places []string
	for _, name := range []string{"Desktop", "Personal", "{374DE290-123F-4565-9164-39C4925E467B}"} {
		if path, ok := reg.Text(reg.User, `Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`, reg.Native, name); ok {
			places = append(places, path)
		}
	}
	for _, name := range []string{"OneDrive", "OneDriveConsumer", "OneDriveCommercial"} {
		places = append(places, os.Getenv(name))
	}
	var out []string
	for _, p := range places {
		if strings.TrimSpace(p) == "" {
			continue
		}
		if info, err := os.Stat(p); err != nil || !info.IsDir() {
			continue
		}
		inside := false
		for _, q := range places {
			if q != "" && !winpath.Same(p, q) && winpath.Under(p, q) {
				inside = true
			}
		}
		duplicate := false
		for _, o := range out {
			duplicate = duplicate || winpath.Same(o, p)
		}
		if !inside && !duplicate {
			out = append(out, p)
		}
	}
	return out
}
