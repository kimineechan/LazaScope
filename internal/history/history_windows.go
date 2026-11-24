//go:build windows

package history

import (
	"errors"
	"os"
	"os/user"
	"sort"
	"strings"

	"lazascope/internal/model"
	"lazascope/internal/procs"
	"lazascope/internal/reg"
)

// The two UserAssist lists that name programs: one for programs and one
// for shortcuts. The others hold older or internal counters.
var userAssist = []string{"{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}", "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}"}

// Collect reads the records of what ran: this account's UserAssist lists,
// and with administrator rights, BAM's record for this account. Only this
// account's records are read, even with administrator rights: what other
// people on the PC ran is theirs.
func Collect(f model.Folders, elevated bool) ([]model.Run, []model.Gap) {
	var runs []model.Run
	var gaps []model.Gap
	for _, list := range userAssist {
		key, err := reg.Open(reg.User, `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\`+list+`\Count`, reg.Native)
		if err != nil {
			continue // a list that was never written to
		}
		for _, v := range key.Values() {
			if r, ok := UserAssist(v.Name, v.Data, f); ok {
				runs = append(runs, r)
			}
		}
		key.Close()
	}
	me, err := user.Current()
	if err != nil {
		return sorted(runs), gaps
	}
	key, err := reg.Open(reg.Machine, `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\`+me.Uid, reg.Native)
	switch {
	case errors.Is(err, os.ErrPermission) || reg.Refused(err):
		gaps = append(gaps, model.Gap{Area: model.RunningNow, What: "Windows' record of when each program last ran (BAM) " + model.Withheld(elevated, false) + "."})
	case err == nil:
		drives := procs.DriveNames()
		for _, v := range key.Values() {
			if r, ok := BAM(v.Name, v.Data, func(p string) string { return procs.DrivePath(p, drives) }); ok {
				runs = append(runs, r)
			}
		}
		key.Close()
	}
	return sorted(runs), gaps
}

func sorted(runs []model.Run) []model.Run {
	sort.SliceStable(runs, func(i, j int) bool { return runs[i].Last.After(runs[j].Last) })
	return runs
}

// Origin reads the mark Windows put on a file it downloaded, if it has one.
func Origin(path string) *model.Origin {
	content, err := os.ReadFile(path + ":Zone.Identifier")
	if err != nil || len(content) > 1<<16 {
		return nil
	}
	if o, ok := Zone(strings.TrimPrefix(string(content), string(rune(0xFEFF)))); ok {
		return o
	}
	return nil
}
