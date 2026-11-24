//go:build !windows

package phrase

import "io/fs"

// onlyInCloud reports whether a file is kept only in the cloud. Only
// Windows marks such files.
func onlyInCloud(fs.FileInfo) bool { return false }
