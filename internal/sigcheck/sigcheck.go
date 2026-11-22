// Package sigcheck asks Windows whether a program file carries a valid
// digital signature, and from whom.
//
// A digital signature is a maker's seal on a file: it names the maker and
// breaks if a single byte of the file is changed afterwards. Windows keeps
// seals in two places. Most software carries its seal inside the file. Many
// of Windows' own files do not; their fingerprints are listed in separate
// signed lists called catalogues. A check that only looks inside the file
// therefore calls most of Windows unsigned, so this package looks in both
// places.
//
// The package has no window and no knowledge of what a result means for a
// PC. It only answers "who signed this file, and does the seal hold?".
package sigcheck

import "strings"

// Status is the outcome of a check.
type Status int

const (
	Unknown  Status = iota // the file could not be checked, for instance because it is missing
	Signed                 // a seal that holds, from a maker Windows trusts
	Unsigned               // no seal, neither in the file nor in a catalogue
	Invalid                // a seal that does not hold
)

func (s Status) String() string {
	switch s {
	case Signed:
		return "signed"
	case Unsigned:
		return "not signed"
	case Invalid:
		return "signature not valid"
	}
	return "not checked"
}

// Source is where a signature was found.
type Source int

const (
	NoSource  Source = iota
	Embedded         // inside the file
	Catalogue        // in a catalogue, a signed list of file fingerprints
)

func (s Source) String() string {
	switch s {
	case Embedded:
		return "in the file"
	case Catalogue:
		return "in a Windows catalogue"
	}
	return ""
}

// Result is what a check found out about one file.
type Result struct {
	Status    Status
	Source    Source
	Signer    string // the name on the certificate the file was signed with
	Catalogue string // the catalogue that lists the file, for a catalogue signature
	Problem   string // why the file could not be checked, or why its signature does not hold
	Code      uint32 // the number Windows gave for the problem, or zero
}

// Trusted reports whether the file has a signature that holds.
func (r Result) Trusted() bool { return r.Status == Signed }

// Maker describes the signature in a few words, for a column of a table.
func (r Result) Maker() string {
	switch r.Status {
	case Signed:
		if r.Signer == "" {
			return "Signed"
		}
		return r.Signer
	case Unsigned:
		return "Not signed"
	case Invalid:
		if r.Signer != "" {
			return "Signature not valid (" + r.Signer + ")"
		}
		return "Signature not valid"
	}
	return "Not checked"
}

// FromMicrosoft reports whether the file has a valid signature from
// Microsoft. A name alone proves nothing, so an unsigned file that merely
// claims to be Microsoft's is not counted.
func (r Result) FromMicrosoft() bool {
	if r.Status != Signed {
		return false
	}
	signer := strings.ToLower(r.Signer)
	return strings.HasPrefix(signer, "microsoft ") || signer == "microsoft"
}

// The numbers Windows gives for the outcomes this package tells apart.
const (
	codeProviderUnknown = 0x800B0001 // no part of Windows knows how to check this kind of file
	codeFormUnknown     = 0x800B0003 // not a kind of file that can carry a signature
	codeNotTrusted      = 0x800B0004
	codeNoSignature     = 0x800B0100
	codeExpired         = 0x800B0101
	codeUntrustedRoot   = 0x800B0109
	codeChaining        = 0x800B010A
	codeRevoked         = 0x800B010C
	codeWrongUsage      = 0x800B0110
	codeDistrusted      = 0x800B0111
	codeBadDigest       = 0x80096010
	codeFileError       = 0x80092003
)

// unsigned reports whether a number from Windows means "there is no
// signature here" as opposed to "there is one, and it is wrong".
func unsigned(code uint32) bool {
	return code == codeNoSignature || code == codeFormUnknown || code == codeProviderUnknown
}

// problem puts a number from Windows into words.
func problem(code uint32) string {
	switch code {
	case codeBadDigest:
		return "The file was changed after it was signed."
	case codeExpired:
		return "The certificate it was signed with had run out, and the signature carries no trusted date."
	case codeUntrustedRoot:
		return "It was signed with a certificate that Windows does not trust, such as one its maker made for themselves."
	case codeChaining:
		return "Windows could not trace its certificate back to an issuer it trusts."
	case codeRevoked:
		return "The certificate it was signed with has been withdrawn by its issuer."
	case codeDistrusted:
		return "The certificate it was signed with is blocked on this PC."
	case codeWrongUsage:
		return "The certificate it was signed with is not meant for signing programs."
	case codeNotTrusted:
		return "Windows does not trust its signature."
	case codeFileError:
		return "Windows could not read the file to check it."
	}
	return "Windows could not confirm its signature."
}

// Changed reports whether the signature failed because the file itself was
// altered after signing, the most telling way for a signature to fail.
func (r Result) Changed() bool { return r.Status == Invalid && r.Code == codeBadDigest }
