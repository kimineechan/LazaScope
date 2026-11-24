//go:build windows

package phrase

import (
	"path/filepath"
	"syscall"
	"testing"
)

// A file kept only in the cloud is counted and left unread, as reading it
// would make OneDrive download it. Windows marks such a file; the mark that
// anyone may set on their own file stands in for OneDrive's here.
func TestCloudFilesAreNotRead(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "phrase.txt")
	write(t, path, []byte(vectors[1].phrase))
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.SetFileAttributes(name, attributeOffline); err != nil {
		t.Skipf("the mark could not be set here: %v", err)
	}
	t.Cleanup(func() { syscall.SetFileAttributes(name, syscall.FILE_ATTRIBUTE_NORMAL) })
	result := Search([]string{root}, nil, nil)
	if result.Cloud != 1 || result.Read != 0 || len(result.Found) != 0 {
		t.Errorf("cloud %d, read %d, found %d: want 1, 0, 0", result.Cloud, result.Read, len(result.Found))
	}
}
