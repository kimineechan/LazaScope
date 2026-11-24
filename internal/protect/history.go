package protect

import (
	"sort"
	"strings"
	"time"

	"lazascope/internal/eventlog"
	"lazascope/internal/model"
)

// Microsoft Defender keeps a log of its own: what it found, what it did
// about it, and every change to its settings. Unlike the list of
// exclusions, the log can be read without administrator rights.

// HistoryLog is the name of that log.
const HistoryLog = "Microsoft-Windows-Windows Defender/Operational"

// HistoryDays is how far back the look goes for what Defender found.
const HistoryDays = 90

// The numbers Defender gives its records.
const (
	foundByScan      = 1006 // older versions: found during a scan
	foundBehaviour   = 1015
	found            = 1116
	acted            = 1117
	realTimeOff      = 5001
	settingChanged   = 5007
	exclusionsMarker = `\windows defender\exclusions\`
)

// The lists of exclusions, by the name of the registry key that holds each.
var exclusionKinds = map[string]string{
	"paths": "Folder or file", "temporarypaths": "Folder or file", "extensions": "File type", "processes": "Program", "ipaddresses": "Network address",
}

// exclusionOf picks the exclusion out of one side of a "setting changed"
// record, which reads like
//
//	HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Games = 0x0
func exclusionOf(value string) (model.Exclusion, bool) {
	at := strings.Index(strings.ToLower(value), exclusionsMarker)
	if at < 0 {
		return model.Exclusion{}, false
	}
	rest := value[at+len(exclusionsMarker):]
	cut := strings.IndexByte(rest, '\\')
	if cut <= 0 {
		return model.Exclusion{}, false
	}
	kind, known := exclusionKinds[strings.ToLower(rest[:cut])]
	what := rest[cut+1:]
	if end := strings.LastIndex(what, " = "); end >= 0 {
		what = what[:end]
	}
	what = strings.TrimSpace(what)
	if !known || what == "" {
		return model.Exclusion{}, false
	}
	return model.Exclusion{Kind: kind, Value: what}, true
}

// LoggedExclusions replays Defender's record of setting changes and returns
// the exclusions that were added and have not been removed since, the
// oldest first. The log only reaches back so far: an exclusion older than
// its first record is not in it, and one that is in it may since have been
// removed in a way the log did not note.
func LoggedExclusions(records []eventlog.Event) []model.LoggedExclusion {
	ordered := append([]eventlog.Event(nil), records...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Time.Before(ordered[j].Time) })
	standing := map[string]model.LoggedExclusion{}
	for _, record := range ordered {
		if record.ID != settingChanged {
			continue
		}
		added, isNew := exclusionOf(record.Value("New Value"))
		removed, wasOld := exclusionOf(record.Value("Old Value"))
		if wasOld && !isNew {
			delete(standing, strings.ToLower(removed.Kind+"|"+removed.Value))
		}
		if isNew {
			key := strings.ToLower(added.Kind + "|" + added.Value)
			if _, already := standing[key]; !already {
				standing[key] = model.LoggedExclusion{When: record.Time, Exclusion: added}
			}
		}
	}
	out := make([]model.LoggedExclusion, 0, len(standing))
	for _, exclusion := range standing {
		out = append(out, exclusion)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].When.Equal(out[j].When) {
			return out[i].When.Before(out[j].When)
		}
		return out[i].Value < out[j].Value
	})
	return out
}

// foundIn tidies the place Defender says it found something. Defender
// writes it as "file:_C:\thing.exe", and joins several places with "; ".
func foundIn(path string) string {
	var places []string
	for _, place := range strings.Split(path, "; ") {
		place = strings.TrimSpace(place)
		for _, lead := range []string{"file:_", "containerfile:_"} {
			if len(place) > len(lead) && strings.EqualFold(place[:len(lead)], lead) {
				place = place[len(lead):]
			}
		}
		if place != "" {
			places = append(places, place)
		}
	}
	return strings.Join(places, "; ")
}

// Detections turns Defender's records of finding something, and of acting
// on it, into one detection each, the newest first. A find and the action
// that follows share a number, which is how the two are matched.
func Detections(records []eventlog.Event) []model.Detection {
	ordered := append([]eventlog.Event(nil), records...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Time.Before(ordered[j].Time) })
	byNumber := map[string]int{}
	var out []model.Detection
	for _, record := range ordered {
		switch record.ID {
		case foundByScan, foundBehaviour, found, acted:
		default:
			continue
		}
		threat := record.Value("Threat Name")
		if threat == "" {
			continue
		}
		number := record.Value("Detection ID")
		if number == "" {
			number = threat + "|" + record.Value("Path")
		}
		at, seen := byNumber[number]
		if !seen {
			out = append(out, model.Detection{When: record.Time})
			at = len(out) - 1
			byNumber[number] = at
		}
		d := &out[at]
		fill := func(into *string, value string) {
			if *into == "" && value != "" {
				*into = value
			}
		}
		fill(&d.Threat, threat)
		fill(&d.Severity, record.Value("Severity Name"))
		fill(&d.Category, record.Value("Category Name"))
		fill(&d.Path, foundIn(record.Value("Path")))
		fill(&d.Process, record.Value("Process Name"))
		fill(&d.Source, record.Value("Source Name"))
		if record.ID == acted {
			if action := record.Value("Action Name"); action != "" && !strings.EqualFold(action, "Not Applicable") {
				d.Action = action
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].When.After(out[j].When) })
	// Defender often writes the same find twice within moments, each under
	// a number of its own. Said once is enough.
	var once []model.Detection
	for _, d := range out {
		repeat := false
		for i := range once {
			if strings.EqualFold(once[i].Threat, d.Threat) && strings.EqualFold(once[i].Path, d.Path) && once[i].When.Sub(d.When) < 10*time.Minute {
				if once[i].Action == "" {
					once[i].Action = d.Action
				}
				repeat = true
				break
			}
		}
		if !repeat {
			once = append(once, d)
		}
	}
	return once
}

// SwitchedOff returns when real-time protection was switched off, the
// newest first.
func SwitchedOff(records []eventlog.Event) []time.Time {
	var when []time.Time
	for _, record := range records {
		if record.ID == realTimeOff {
			when = append(when, record.Time)
		}
	}
	sort.Slice(when, func(i, j int) bool { return when[i].After(when[j]) })
	return when
}
