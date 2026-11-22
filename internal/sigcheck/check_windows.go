//go:build windows

package sigcheck

import (
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"lazascope/internal/sysdll"
)

var (
	wintrust = sysdll.Load("wintrust.dll")
	crypt32  = sysdll.Load("crypt32.dll")

	winVerifyTrust    = wintrust.NewProc("WinVerifyTrust")
	stateToProvider   = wintrust.NewProc("WTHelperProvDataFromStateData")
	providerSigner    = wintrust.NewProc("WTHelperGetProvSignerFromChain")
	signerCertificate = wintrust.NewProc("WTHelperGetProvCertFromChain")
	acquireSHA256     = wintrust.NewProc("CryptCATAdminAcquireContext2")
	acquireSHA1       = wintrust.NewProc("CryptCATAdminAcquireContext")
	releaseAdmin      = wintrust.NewProc("CryptCATAdminReleaseContext")
	fingerprint       = wintrust.NewProc("CryptCATAdminCalcHashFromFileHandle2")
	findCatalogue     = wintrust.NewProc("CryptCATAdminEnumCatalogFromHash")
	catalogueDetails  = wintrust.NewProc("CryptCATCatalogInfoFromContext")
	releaseCatalogue  = wintrust.NewProc("CryptCATAdminReleaseCatalogContext")
	certificateName   = crypt32.NewProc("CertGetNameStringW")
)

type guid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

var (
	// The ordinary check of a signed file: WINTRUST_ACTION_GENERIC_VERIFY_V2.
	genericVerify = guid{0x00AAC56B, 0xCD44, 0x11D0, [8]byte{0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE}}
	// The set of catalogues that covers Windows' own files and drivers:
	// DRIVER_ACTION_VERIFY.
	systemCatalogues = guid{0xF750E6C3, 0x38EE, 0x11D1, [8]byte{0x85, 0xE5, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE}}
)

// trustFile mirrors WINTRUST_FILE_INFO.
type trustFile struct {
	Size    uint32
	Path    *uint16
	File    syscall.Handle
	Subject *guid
}

// trustCatalogue mirrors WINTRUST_CATALOG_INFO.
type trustCatalogue struct {
	Size       uint32
	Version    uint32
	Catalogue  *uint16
	MemberTag  *uint16
	MemberPath *uint16
	MemberFile syscall.Handle
	Hash       *byte
	HashLength uint32
	Context    uintptr
	Admin      uintptr
}

// trustData mirrors WINTRUST_DATA.
type trustData struct {
	Size             uint32
	PolicyData       uintptr
	ClientData       uintptr
	UIChoice         uint32
	RevocationChecks uint32
	UnionChoice      uint32
	Info             unsafe.Pointer
	StateAction      uint32
	StateData        uintptr
	URLReference     *uint16
	ProviderFlags    uint32
	UIContext        uint32
	Settings         uintptr
}

const (
	noWindows       = 2 // WTD_UI_NONE: never show a dialog
	choiceFile      = 1 // WTD_CHOICE_FILE
	choiceCatalogue = 2 // WTD_CHOICE_CATALOG
	stateVerify     = 1 // WTD_STATEACTION_VERIFY
	stateClose      = 2 // WTD_STATEACTION_CLOSE

	// Windows may go online during a check, to ask whether a certificate has
	// been withdrawn or to fetch a missing link of its chain. This program
	// promises that nothing leaves the PC, so both are turned off: no
	// withdrawal check, and only what Windows already holds on disk is used.
	noRevocation  = 0x00000010 // WTD_REVOCATION_CHECK_NONE
	cacheOnly     = 0x00001000 // WTD_CACHE_ONLY_URL_RETRIEVAL
	offlineChecks = noRevocation | cacheOnly
)

// Checker checks files and remembers the answers, so that a file named by
// several start-up entries and running programs is only read once.
type Checker struct {
	lock sync.Mutex
	seen map[string]*answer

	catalogues   sync.Mutex // one catalogue lookup at a time
	sha256, sha1 uintptr    // handles to Windows' catalogue index, opened when first needed
	opened       bool

	asked, read atomic.Int64
}

type answer struct {
	once   sync.Once
	result Result
}

// New returns a Checker with nothing remembered. Close it when done.
func New() *Checker { return &Checker{seen: map[string]*answer{}} }

// Close gives back what the Checker holds of Windows.
func (c *Checker) Close() {
	c.catalogues.Lock()
	defer c.catalogues.Unlock()
	for _, admin := range []*uintptr{&c.sha256, &c.sha1} {
		if *admin != 0 {
			releaseAdmin.Call(*admin, 0)
			*admin = 0
		}
	}
	c.opened = false
}

// Counts returns how many checks were asked for and how many of them
// needed the file to be read, the rest having been remembered.
func (c *Checker) Counts() (asked, read int64) { return c.asked.Load(), c.read.Load() }

// Check says who signed a file and whether the signature holds. It is safe
// to call from several goroutines at once.
func (c *Checker) Check(path string) Result {
	c.asked.Add(1)
	if path == "" {
		return Result{Problem: "No file is named."}
	}
	path = filepath.Clean(path)
	info, err := os.Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Result{Problem: "The file does not exist."}
	case err != nil:
		return Result{Problem: "The file could not be opened: " + reason(err)}
	case info.IsDir():
		return Result{Problem: "That is a folder, not a file."}
	}
	// A file is known by its place, its size and when it was last written.
	// Change any of them and it is checked afresh.
	key := strings.ToLower(path) + "|" + strconv.FormatInt(info.Size(), 10) + "|" + strconv.FormatInt(info.ModTime().UnixNano(), 10)
	c.lock.Lock()
	known := c.seen[key]
	if known == nil {
		known = &answer{}
		c.seen[key] = known
	}
	c.lock.Unlock()
	known.once.Do(func() {
		c.read.Add(1)
		known.result = c.check(path)
	})
	return known.result
}

// check does the work of Check for a file that exists.
func (c *Checker) check(path string) Result {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return Result{Problem: "The file's name cannot be given to Windows."}
	}
	// First the seal inside the file.
	file := trustFile{Path: name}
	file.Size = uint32(unsafe.Sizeof(file))
	code, signer := verify(choiceFile, unsafe.Pointer(&file))
	if code == 0 {
		return Result{Status: Signed, Source: Embedded, Signer: signer}
	}
	inside := Result{Status: Invalid, Source: Embedded, Signer: signer, Problem: problem(code), Code: code}
	if unsigned(code) {
		inside = Result{Status: Unsigned}
	} else if code == codeFileError {
		inside = Result{Problem: problem(code), Code: code}
	}
	// Then the catalogues. A file with no seal of its own, or one that does
	// not hold, may still be listed in one.
	if listed, found := c.catalogue(path, name); found {
		if listed.Status == Signed || inside.Status == Unsigned {
			return listed
		}
	}
	return inside
}

// verify asks Windows to check a file, or a file against a catalogue, and
// returns Windows' answer (zero for a signature that holds) with the name
// on the signing certificate.
func verify(choice uint32, info unsafe.Pointer) (code uint32, signer string) {
	data := trustData{UIChoice: noWindows, UnionChoice: choice, Info: info, StateAction: stateVerify, ProviderFlags: offlineChecks}
	data.Size = uint32(unsafe.Sizeof(data))
	const nobody = ^uintptr(0) // no window to put questions to
	r, _, _ := winVerifyTrust.Call(nobody, uintptr(unsafe.Pointer(&genericVerify)), uintptr(unsafe.Pointer(&data)))
	code = uint32(r)
	if data.StateData != 0 {
		signer = signerName(data.StateData)
	}
	data.StateAction = stateClose
	winVerifyTrust.Call(nobody, uintptr(unsafe.Pointer(&genericVerify)), uintptr(unsafe.Pointer(&data)))
	return code, signer
}

// at reads an address Windows returned as the pointer it is.
func at(address uintptr) unsafe.Pointer { return *(*unsafe.Pointer)(unsafe.Pointer(&address)) }

// signerName digs the signing certificate out of what a check left behind
// and returns the name on it.
func signerName(state uintptr) string {
	provider, _, _ := stateToProvider.Call(state)
	if provider == 0 {
		return ""
	}
	signer, _, _ := providerSigner.Call(provider, 0, 0, 0)
	if signer == 0 {
		return ""
	}
	link, _, _ := signerCertificate.Call(signer, 0)
	if link == 0 {
		return ""
	}
	// CRYPT_PROVIDER_CERT starts with its own size, then the certificate.
	certificate := *(*uintptr)(at(link + unsafe.Sizeof(uintptr(0))))
	if certificate == 0 {
		return ""
	}
	const simpleName = 4 // CERT_NAME_SIMPLE_DISPLAY_TYPE
	buffer := make([]uint16, 512)
	n, _, _ := certificateName.Call(certificate, simpleName, 0, 0, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	if n <= 1 {
		return ""
	}
	return syscall.UTF16ToString(buffer)
}

// open prepares the two handles to Windows' index of catalogues: one that
// fingerprints files the current way (SHA-256) and one the older way
// (SHA-1), since catalogues of both kinds are in use.
func (c *Checker) open() {
	if c.opened {
		return
	}
	c.opened = true
	if acquireSHA256.Find() == nil {
		algorithm, _ := syscall.UTF16PtrFromString("SHA256")
		acquireSHA256.Call(uintptr(unsafe.Pointer(&c.sha256)), uintptr(unsafe.Pointer(&systemCatalogues)), uintptr(unsafe.Pointer(algorithm)), 0, 0)
	}
	acquireSHA1.Call(uintptr(unsafe.Pointer(&c.sha1)), uintptr(unsafe.Pointer(&systemCatalogues)), 0)
}

// catalogue looks for a file in Windows' catalogues, and in the catalogue
// of the app package the file belongs to, if it belongs to one. found is
// false when no catalogue lists the file.
func (c *Checker) catalogue(path string, name *uint16) (result Result, found bool) {
	const readOnly, shareAll = 0x80000000, 0x1 | 0x2 | 0x4
	file, err := syscall.CreateFile(name, readOnly, shareAll, nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return Result{}, false
	}
	defer syscall.CloseHandle(file)

	c.catalogues.Lock()
	defer c.catalogues.Unlock()
	c.open()
	var current []byte // the SHA-256 fingerprint, kept for the package catalogue
	for _, admin := range []uintptr{c.sha256, c.sha1} {
		if admin == 0 {
			continue
		}
		hash := make([]byte, 64)
		size := uint32(len(hash))
		if ok, _, _ := fingerprint.Call(admin, uintptr(file), uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&hash[0])), 0); ok == 0 || size == 0 {
			continue
		}
		hash = hash[:size]
		if admin == c.sha256 {
			current = hash
		}
		listing, _, _ := findCatalogue.Call(admin, uintptr(unsafe.Pointer(&hash[0])), uintptr(len(hash)), 0, 0)
		if listing == 0 {
			continue
		}
		// CATALOG_INFO: its own size, then the path of the catalogue file.
		var details struct {
			Size uint32
			Path [syscall.MAX_PATH]uint16
		}
		details.Size = uint32(unsafe.Sizeof(details))
		ok, _, _ := catalogueDetails.Call(listing, uintptr(unsafe.Pointer(&details)), 0)
		releaseCatalogue.Call(admin, listing, 0)
		if ok == 0 {
			continue
		}
		return against(syscall.UTF16ToString(details.Path[:]), name, file, hash, admin), true
	}
	// An app from the Microsoft Store brings its own catalogue, which is not
	// in Windows' index.
	if own := packageCatalogue(path); own != "" && current != nil {
		if listed := against(own, name, file, current, c.sha256); listed.Status == Signed {
			return listed, true
		}
	}
	return Result{}, false
}

// against checks a file against one catalogue: that the catalogue lists
// the file's fingerprint, and that the catalogue's own signature holds.
func against(catalogue string, name *uint16, file syscall.Handle, hash []byte, admin uintptr) Result {
	cataloguePath, err := syscall.UTF16PtrFromString(catalogue)
	if err != nil {
		return Result{}
	}
	tag, _ := syscall.UTF16PtrFromString(strings.ToUpper(hex.EncodeToString(hash)))
	info := trustCatalogue{Catalogue: cataloguePath, MemberTag: tag, MemberPath: name, MemberFile: file, Hash: &hash[0], HashLength: uint32(len(hash)), Admin: admin}
	info.Size = uint32(unsafe.Sizeof(info))
	code, signer := verify(choiceCatalogue, unsafe.Pointer(&info))
	result := Result{Status: Signed, Source: Catalogue, Signer: signer, Catalogue: filepath.Base(catalogue)}
	if code != 0 {
		result.Status, result.Problem, result.Code = Invalid, problem(code), code
		if unsigned(code) {
			result = Result{Status: Unsigned}
		}
	}
	return result
}

// packageCatalogue returns the catalogue of the app package a file is
// part of, or "". A package keeps it in a folder named AppxMetadata at its
// top.
func packageCatalogue(path string) string {
	folder := filepath.Dir(path)
	for range 8 {
		catalogue := filepath.Join(folder, "AppxMetadata", "CodeIntegrity.cat")
		if info, err := os.Stat(catalogue); err == nil && !info.IsDir() {
			return catalogue
		}
		parent := filepath.Dir(folder)
		if parent == folder {
			break
		}
		folder = parent
	}
	return ""
}

// reason puts an error from opening a file into a few plain words.
func reason(err error) string {
	switch {
	case errors.Is(err, fs.ErrPermission):
		return "access was refused."
	case errors.Is(err, fs.ErrNotExist):
		return "it does not exist."
	}
	var number syscall.Errno
	if errors.As(err, &number) {
		return "Windows error " + strconv.Itoa(int(number)) + "."
	}
	return "it could not be read."
}
