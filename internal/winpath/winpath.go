// Package winpath handles Windows file paths as text. Go's own path tools
// follow the rules of the system they run on, and the rules and their tests
// have to give the same answers everywhere, so the few operations they need
// are written out here.
package winpath

import "strings"

func separator(c byte) bool { return c == '\\' || c == '/' }

// Tidy trims a path, uses backslashes throughout and drops a backslash at
// the end, except after a drive letter.
func Tidy(path string) string {
	path = strings.ReplaceAll(strings.TrimSpace(path), "/", `\`)
	for len(path) > 3 && strings.HasSuffix(path, `\`) {
		path = path[:len(path)-1]
	}
	return path
}

// Base returns the last part of a path: the file's name.
func Base(path string) string {
	path = Tidy(path)
	for i := len(path) - 1; i >= 0; i-- {
		if separator(path[i]) || path[i] == ':' {
			return path[i+1:]
		}
	}
	return path
}

// Dir returns a path without its last part: the folder a file is in.
func Dir(path string) string {
	path = Tidy(path)
	for i := len(path) - 1; i >= 0; i-- {
		if separator(path[i]) {
			if i == 2 && path[1] == ':' {
				return path[:3] // the top of a drive keeps its backslash
			}
			return path[:i]
		}
	}
	return ""
}

// Ext returns the ending of a file's name in small letters, with its dot,
// such as ".exe". It is empty when the name has none.
func Ext(path string) string {
	name := Base(path)
	if dot := strings.LastIndexByte(name, '.'); dot > 0 {
		return strings.ToLower(name[dot:])
	}
	return ""
}

// Stem returns a file's name in small letters without its ending, so that
// "C:\Windows\System32\CMD.EXE" gives "cmd".
func Stem(path string) string {
	name := strings.ToLower(Base(path))
	if dot := strings.LastIndexByte(name, '.'); dot > 0 {
		return name[:dot]
	}
	return name
}

// Join puts a folder and a name together.
func Join(folder, name string) string {
	folder = Tidy(folder)
	if folder == "" {
		return name
	}
	if strings.HasSuffix(folder, `\`) {
		return folder + name
	}
	return folder + `\` + name
}

// Absolute reports whether a path says where it is in full: it starts at a
// drive or at a network share.
func Absolute(path string) bool {
	path = Tidy(path)
	if len(path) >= 3 && path[1] == ':' && path[2] == '\\' {
		return true
	}
	return strings.HasPrefix(path, `\\`)
}

// Under reports whether a path is inside a folder, at any depth. Capital
// and small letters count as the same, as they do to Windows.
func Under(path, folder string) bool {
	path, folder = strings.ToLower(Tidy(path)), strings.ToLower(Tidy(folder))
	if folder == "" || len(path) <= len(folder) || !strings.HasPrefix(path, folder) {
		return false
	}
	return strings.HasSuffix(folder, `\`) || path[len(folder)] == '\\'
}

// In reports whether a file sits directly in a folder, not deeper.
func In(path, folder string) bool {
	return folder != "" && strings.EqualFold(Dir(path), Tidy(folder))
}

// Same reports whether two paths name the same place.
func Same(a, b string) bool { return strings.EqualFold(Tidy(a), Tidy(b)) }

// Has reports whether a path passes through a folder of the given name,
// such as "Downloads", wherever that folder is.
func Has(path, name string) bool {
	return strings.Contains(strings.ToLower(Dir(path))+`\`, `\`+strings.ToLower(name)+`\`)
}
