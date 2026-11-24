package view

import (
	"strconv"
	"strings"

	"lazascope/internal/detect"
)

// LiveColumns are the columns of the live watch's list.
var LiveColumns = []Column{{"When", 96}, {"Check", 124}, {"Program", 210}, {"Started by", 180}, {"Command", 0}}

// LiveRow lays out one program starting, with the detections it set off.
func LiveRow(e detect.Event, alerts []detect.Alert) Row {
	row := Row{Level: Plain, Path: e.Path, When: e.When, Ref: "live:" + strconv.Itoa(int(e.PID))}
	for _, a := range alerts {
		row.Level = max(row.Level, level(a.Severity))
	}
	check := ""
	if row.Level != Plain {
		check = row.Level.String()
	}
	by := e.By
	if by == "" {
		by = "number " + strconv.Itoa(int(e.Parent))
	}
	command := e.Command
	if command == "" {
		command = "(not given to this account)"
	}
	row.Cells = []string{e.When.Local().Format("15:04:05"), check, e.Name + " (" + strconv.Itoa(int(e.PID)) + ")", by, command}
	lines := []Line{{Heading, e.Name}, {Text, "Started at " + e.When.Local().Format("15:04:05 on 2 January 2006") + ", as process " + strconv.Itoa(int(e.PID)) + ", by " + by + "."}}
	for _, a := range alerts {
		var techniques []string
		for _, id := range a.Attack {
			techniques = append(techniques, id+" "+detect.Techniques[id])
		}
		lines = append(lines, Line{Heading, a.Severity.String() + ": " + a.Title}, Line{Text, a.Why},
			Line{Aside, "Detection: " + a.ID + ". MITRE ATT&CK: " + strings.Join(techniques, "; ")})
	}
	if e.Path != "" {
		lines = append(lines, Line{Text, "File:"}, Line{Command, e.Path})
	}
	if e.Command != "" {
		lines = append(lines, Line{Text, "Command:"}, Line{Command, e.Command})
	} else {
		lines = append(lines, Line{Aside, "Windows gives the command lines of other accounts' programs to administrators only."})
	}
	row.Detail = lines
	row.Fields = map[string][]string{"page": {"live"}, "name": {e.Name}, "path": {e.Path}, "command": {e.Command}, "pid": {strconv.Itoa(int(e.PID))},
		"parent": {strconv.Itoa(int(e.Parent))}, "level": {levelWord(row.Level)}}
	for _, a := range alerts {
		row.Fields["rule"] = append(row.Fields["rule"], a.ID)
		row.Fields["attack"] = append(row.Fields["attack"], a.Attack...)
	}
	row.Text = strings.Join(row.Cells, "\n") + "\n" + e.Path
	return row
}
