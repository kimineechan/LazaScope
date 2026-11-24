//go:build windows

// Package sensor watches programs start, live, and hands each one to the
// detections. It asks Windows Management Instrumentation to report every
// new process, which needs no administrator rights. WMI looks once a
// second, so a program that starts and ends within the same second can be
// missed, and the command lines of other accounts' programs are only given
// to administrators. It only reads.
package sensor

import (
	"strings"
	"time"

	"lazascope/internal/detect"
	"lazascope/internal/winpath"
	"lazascope/internal/wmi"
)

var fields = []string{"Name", "ProcessId", "ParentProcessId", "CommandLine", "ExecutablePath", "CreationDate"}

// Watch reports every program that starts, until stop is closed.
func Watch(stop <-chan struct{}, each func(detect.Event)) error {
	// The programs already running, so that a new one's parent has a name.
	names := map[uint32]string{}
	if rows, err := wmi.Query(`root\cimv2`, "SELECT Name, ProcessId FROM Win32_Process", []string{"Name", "ProcessId"}, 10*time.Second); err == nil {
		for _, row := range rows {
			names[number(row["ProcessId"])] = text(row["Name"])
		}
	}
	return wmi.Watch(`root\cimv2`, "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'", fields, stop, func(row map[string]any) {
		e := detect.Event{PID: number(row["ProcessId"]), Parent: number(row["ParentProcessId"]), Name: text(row["Name"]),
			Path: text(row["ExecutablePath"]), Command: text(row["CommandLine"]), When: When(text(row["CreationDate"]))}
		if e.Name == "" && e.Path != "" {
			e.Name = winpath.Base(e.Path)
		}
		if e.When.IsZero() {
			e.When = time.Now()
		}
		e.By = names[e.Parent]
		names[e.PID] = e.Name
		each(e)
	})
}

func number(v any) uint32 {
	n, _ := v.(int64)
	return uint32(n)
}

func text(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

// When reads a time as WMI writes it: yyyymmddHHMMSS.mmmmmm and the
// difference from UTC in minutes, such as 20261124221503.123456+000.
func When(cim string) time.Time {
	if len(cim) < 25 {
		return time.Time{}
	}
	t, err := time.Parse("20060102150405.000000", cim[:21])
	if err != nil {
		return time.Time{}
	}
	sign, minutes := cim[21], 0
	for _, r := range cim[22:25] {
		if r < '0' || r > '9' {
			return time.Time{}
		}
		minutes = minutes*10 + int(r-'0')
	}
	offset := time.Duration(minutes) * time.Minute
	if sign == '-' {
		offset = -offset
	}
	return t.Add(-offset).UTC()
}
