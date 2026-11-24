//go:build windows

package virustotal

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"lazascope/internal/sysdll"
)

// The key is kept in LazaScope's own folder, sealed with Windows' data
// protection (DPAPI): Windows locks it with a secret of the account that
// saved it, so that only that account, on this PC, can open it again. A
// copy of the file taken to another PC, or read by another account, is no
// use to anyone. A program running as the same account could still ask
// Windows to open it, as it could with a browser's saved passwords.

var (
	crypt32   = sysdll.Load("crypt32.dll")
	protect   = crypt32.NewProc("CryptProtectData")
	unprotect = crypt32.NewProc("CryptUnprotectData")
	localFree = sysdll.Load("kernel32.dll").NewProc("LocalFree")
)

const (
	keyFile    = "virustotal-key.bin"
	memoryFile = "virustotal.json"
	noPrompt   = 0x1 // CRYPTPROTECT_UI_FORBIDDEN: never put a window up
)

// entropy is mixed into the seal, so that the sealed key opens only for a
// program that asks for exactly this.
var entropy = []byte("LazaScope VirusTotal key")

// ErrNoKey is returned when no key has been saved.
var ErrNoKey = errors.New("no VirusTotal key has been saved")

type blob struct {
	Size uint32
	Data *byte
}

func blobOf(data []byte) *blob {
	if len(data) == 0 {
		return &blob{}
	}
	return &blob{uint32(len(data)), &data[0]}
}

// bytes copies what Windows handed back, and gives Windows its memory back.
func (b *blob) bytes() []byte {
	if b.Data == nil {
		return nil
	}
	out := make([]byte, b.Size)
	copy(out, unsafe.Slice(b.Data, b.Size))
	localFree.Call(uintptr(unsafe.Pointer(b.Data)))
	return out
}

func seal(plain []byte) ([]byte, error) {
	var out blob
	description, _ := syscall.UTF16PtrFromString("LazaScope VirusTotal key")
	ok, _, err := protect.Call(uintptr(unsafe.Pointer(blobOf(plain))), uintptr(unsafe.Pointer(description)),
		uintptr(unsafe.Pointer(blobOf(entropy))), 0, 0, noPrompt, uintptr(unsafe.Pointer(&out)))
	if ok == 0 {
		return nil, err
	}
	return out.bytes(), nil
}

func unseal(sealed []byte) ([]byte, error) {
	var out blob
	ok, _, err := unprotect.Call(uintptr(unsafe.Pointer(blobOf(sealed))), 0,
		uintptr(unsafe.Pointer(blobOf(entropy))), 0, 0, noPrompt, uintptr(unsafe.Pointer(&out)))
	if ok == 0 {
		return nil, err
	}
	return out.bytes(), nil
}

// Folder returns LazaScope's own folder for what it keeps between runs:
// LazaScope inside the account's local application data, which does not
// travel with the account to other PCs.
func Folder() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "LazaScope"), nil
}

// MemoryPath returns where the memory of VirusTotal's answers is kept.
func MemoryPath() (string, error) {
	folder, err := Folder()
	if err != nil {
		return "", err
	}
	return filepath.Join(folder, memoryFile), nil
}

// SaveKey seals a key for this account and keeps it in LazaScope's folder.
func SaveKey(key string) error {
	key, ok := CleanKey(key)
	if !ok {
		return ErrForm
	}
	folder, err := Folder()
	if err != nil {
		return err
	}
	sealed, err := seal([]byte(key))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(folder, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(folder, keyFile), sealed, 0o600)
}

// LoadKey opens the key saved earlier. It returns ErrNoKey when there is
// none.
func LoadKey() (string, error) {
	folder, err := Folder()
	if err != nil {
		return "", err
	}
	sealed, err := os.ReadFile(filepath.Join(folder, keyFile))
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrNoKey
	}
	if err != nil {
		return "", err
	}
	plain, err := unseal(sealed)
	if err != nil {
		return "", errors.New("the saved VirusTotal key could not be opened. It can only be opened by the Windows account that saved it, on the PC it was saved on")
	}
	key, ok := CleanKey(string(plain))
	if !ok {
		return "", ErrForm
	}
	return key, nil
}

// ForgetKey removes the saved key, if there is one.
func ForgetKey() error {
	folder, err := Folder()
	if err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(folder, keyFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Key returns the key to use: the one in the environment variable
// LAZASCOPE_VIRUSTOTAL_KEY when it is set, for scripts, or else the one
// saved in the window. It returns ErrNoKey when there is neither.
func Key() (string, error) {
	if key := os.Getenv("LAZASCOPE_VIRUSTOTAL_KEY"); key != "" {
		if key, ok := CleanKey(key); ok {
			return key, nil
		}
		return "", ErrForm
	}
	return LoadKey()
}
