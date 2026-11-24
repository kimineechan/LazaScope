//go:build windows

package phrase

import (
	"io/fs"
	"syscall"
)

// The marks Windows gives a file that is kept in the cloud and not on the
// PC, such as a OneDrive file shown with a cloud. Reading one would make
// OneDrive download it.
const (
	attributeOffline        = 0x00001000
	attributeRecallOnOpen   = 0x00040000
	attributeRecallOnAccess = 0x00400000
)

// onlyInCloud reports whether a file is kept only in the cloud.
func onlyInCloud(info fs.FileInfo) bool {
	data, ok := info.Sys().(*syscall.Win32FileAttributeData)
	return ok && data.FileAttributes&(attributeOffline|attributeRecallOnOpen|attributeRecallOnAccess) != 0
}
