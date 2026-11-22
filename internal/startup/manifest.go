package startup

import (
	"bytes"
	"encoding/xml"
	"strings"
)

// StartupExecutable looks in the manifest of a Store app, the file in which
// the app declares what it is made of, for the start-up task with the given
// name. declared is false when the app has no such task. executable is the
// program the task starts, as a path inside the app's folder; it is empty
// when the manifest does not say.
func StartupExecutable(manifest []byte, task string) (executable string, declared bool) {
	decoder := xml.NewDecoder(bytes.NewReader(manifest))
	decoder.Strict = false
	attribute := func(element xml.StartElement, name string) string {
		for _, a := range element.Attr {
			if strings.EqualFold(a.Name.Local, name) {
				return a.Value
			}
		}
		return ""
	}
	// A start-up task sits inside an extension, which sits inside an
	// application. The program is named on the extension, or failing that on
	// the application.
	application, extension := "", ""
	for {
		token, err := decoder.Token()
		if err != nil {
			return "", false
		}
		switch element := token.(type) {
		case xml.StartElement:
			switch element.Name.Local {
			case "Application":
				application, extension = attribute(element, "Executable"), ""
			case "Extension":
				extension = attribute(element, "Executable")
			case "StartupTask":
				if strings.EqualFold(attribute(element, "TaskId"), task) {
					if extension != "" {
						return strings.ReplaceAll(extension, "/", `\`), true
					}
					return strings.ReplaceAll(application, "/", `\`), true
				}
			}
		case xml.EndElement:
			if element.Name.Local == "Extension" {
				extension = ""
			}
		}
	}
}
