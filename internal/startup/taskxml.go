// Package startup gathers everything on a PC that is set to start by
// itself: the registry's Run lists, the Startup folders, scheduled tasks,
// services, drivers and a few settings that are misused for the same end.
package startup

import (
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Task is what LazaScope takes from a scheduled task. Task Scheduler
// describes each task as a small XML document, and this is read from it.
type Task struct {
	Author      string
	Description string
	Enabled     bool
	Hidden      bool
	Account     string   // the account or group the task runs as, as written in the task
	Highest     bool     // it asks for administrator rights when it runs
	Triggers    []string // when it starts, in plain words
	Actions     []TaskAction
}

// TaskAction is one thing a task does.
type TaskAction struct {
	Command   string // the program to start
	Arguments string
	Class     string // or the number of a Windows component to call instead of a program
}

type taskDocument struct {
	Registration struct {
		Author      string `xml:"Author"`
		Description string `xml:"Description"`
	} `xml:"RegistrationInfo"`
	Triggers struct {
		All []taskTrigger `xml:",any"`
	} `xml:"Triggers"`
	Principals struct {
		Principal []struct {
			UserID   string `xml:"UserId"`
			GroupID  string `xml:"GroupId"`
			RunLevel string `xml:"RunLevel"`
		} `xml:"Principal"`
	} `xml:"Principals"`
	Settings struct {
		Enabled string `xml:"Enabled"`
		Hidden  string `xml:"Hidden"`
	} `xml:"Settings"`
	Actions struct {
		Exec []struct {
			Command   string `xml:"Command"`
			Arguments string `xml:"Arguments"`
		} `xml:"Exec"`
		Handler []struct {
			Class string `xml:"ClassId"`
		} `xml:"ComHandler"`
	} `xml:"Actions"`
}

type taskTrigger struct {
	XMLName    xml.Name
	Enabled    string `xml:"Enabled"`
	Repetition struct {
		Interval string `xml:"Interval"`
	} `xml:"Repetition"`
	ByDay   *struct{} `xml:"ScheduleByDay"`
	ByWeek  *struct{} `xml:"ScheduleByWeek"`
	ByMonth *struct{} `xml:"ScheduleByMonth"`
	ByDOW   *struct{} `xml:"ScheduleByMonthDayOfWeek"`
}

// ParseTask reads the XML description of a scheduled task.
func ParseTask(document string) (Task, error) {
	decoder := xml.NewDecoder(strings.NewReader(document))
	// The document says it is UTF-16, which it was before it became a Go
	// string. It is already readable, so the label is passed over.
	decoder.CharsetReader = func(label string, input io.Reader) (io.Reader, error) { return input, nil }
	var parsed taskDocument
	if err := decoder.Decode(&parsed); err != nil {
		return Task{}, fmt.Errorf("the task's description could not be read: %w", err)
	}
	task := Task{
		Author:      strings.TrimSpace(parsed.Registration.Author),
		Description: strings.TrimSpace(parsed.Registration.Description),
		Enabled:     !strings.EqualFold(strings.TrimSpace(parsed.Settings.Enabled), "false"),
		Hidden:      strings.EqualFold(strings.TrimSpace(parsed.Settings.Hidden), "true"),
	}
	for _, principal := range parsed.Principals.Principal {
		if task.Account == "" {
			task.Account = strings.TrimSpace(principal.UserID)
		}
		if task.Account == "" {
			task.Account = strings.TrimSpace(principal.GroupID)
		}
		if strings.EqualFold(strings.TrimSpace(principal.RunLevel), "HighestAvailable") {
			task.Highest = true
		}
	}
	for _, trigger := range parsed.Triggers.All {
		if strings.EqualFold(strings.TrimSpace(trigger.Enabled), "false") {
			continue // a trigger that is switched off starts nothing
		}
		if words := trigger.words(); words != "" && !contains(task.Triggers, words) {
			task.Triggers = append(task.Triggers, words)
		}
	}
	for _, exec := range parsed.Actions.Exec {
		task.Actions = append(task.Actions, TaskAction{Command: strings.TrimSpace(exec.Command), Arguments: strings.TrimSpace(exec.Arguments)})
	}
	for _, handler := range parsed.Actions.Handler {
		task.Actions = append(task.Actions, TaskAction{Class: strings.TrimSpace(handler.Class)})
	}
	return task, nil
}

func contains(list []string, text string) bool {
	for _, have := range list {
		if have == text {
			return true
		}
	}
	return false
}

// words says when a trigger starts its task.
func (t taskTrigger) words() string {
	words := ""
	switch t.XMLName.Local {
	case "LogonTrigger":
		words = "When someone signs in"
	case "BootTrigger":
		words = "When Windows starts"
	case "IdleTrigger":
		words = "When the PC is left idle"
	case "EventTrigger":
		words = "When Windows logs a certain event"
	case "RegistrationTrigger":
		words = "When the task is created or changed"
	case "SessionStateChangeTrigger":
		words = "When the screen is locked, unlocked or connected to"
	case "WnfStateChangeTrigger":
		words = "When something changes in Windows"
	case "TimeTrigger":
		words = "At a set time"
	case "CalendarTrigger":
		switch {
		case t.ByDay != nil:
			words = "Daily"
		case t.ByWeek != nil:
			words = "Weekly"
		case t.ByMonth != nil, t.ByDOW != nil:
			words = "Monthly"
		default:
			words = "On set days"
		}
	default:
		return ""
	}
	if every := Span(t.Repetition.Interval); every != "" {
		words += ", then every " + every
	}
	return words
}

// Span puts a length of time written the way Task Scheduler writes it,
// such as PT5M or P1D, into words: "5 minutes", "1 day". Anything it does
// not recognise gives "".
func Span(written string) string {
	written = strings.ToUpper(strings.TrimSpace(written))
	if !strings.HasPrefix(written, "P") {
		return ""
	}
	var parts []string
	clock, digits := false, ""
	for _, r := range written[1:] {
		switch {
		case r == 'T':
			clock = true
		case r >= '0' && r <= '9':
			digits += string(r)
		default:
			n, err := strconv.Atoi(digits)
			digits = ""
			if err != nil || n == 0 {
				continue
			}
			unit := ""
			switch {
			case r == 'D':
				unit = "day"
			case r == 'H' && clock:
				unit = "hour"
			case r == 'M' && clock:
				unit = "minute"
			case r == 'M':
				unit = "month"
			case r == 'S' && clock:
				unit = "second"
			default:
				return ""
			}
			if n != 1 {
				unit += "s"
			}
			parts = append(parts, strconv.Itoa(n)+" "+unit)
		}
	}
	return strings.Join(parts, " ")
}
