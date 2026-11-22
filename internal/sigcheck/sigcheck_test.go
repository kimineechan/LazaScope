package sigcheck

import "testing"

func TestMaker(t *testing.T) {
	for _, test := range []struct {
		result Result
		want   string
	}{
		{Result{Status: Signed, Signer: "Example Ltd"}, "Example Ltd"},
		{Result{Status: Signed}, "Signed"},
		{Result{Status: Signed, Signer: "EB51A5DA-0E72-4863-82E4-EA21C1F8DFE3"}, "Microsoft Store app"},
		{Result{Status: Signed, Signer: "EB51A5DA-0E72-4863-82E4-EA21C1F8DFEZ"}, "EB51A5DA-0E72-4863-82E4-EA21C1F8DFEZ"},
		{Result{Status: Unsigned}, "Not signed"},
		{Result{Status: Invalid, Signer: "Example Ltd"}, "Signature not valid (Example Ltd)"},
		{Result{Status: Invalid}, "Signature not valid"},
		{Result{}, "Not checked"},
	} {
		if got := test.result.Maker(); got != test.want {
			t.Errorf("%+v: got %q, want %q", test.result, got, test.want)
		}
	}
}

// Only a signature that holds counts as Microsoft's. The name on a broken
// or missing signature proves nothing.
func TestFromMicrosoft(t *testing.T) {
	for _, test := range []struct {
		result Result
		want   bool
	}{
		{Result{Status: Signed, Signer: "Microsoft Windows"}, true},
		{Result{Status: Signed, Signer: "Microsoft Corporation"}, true},
		{Result{Status: Signed, Signer: "Microsoft Windows Hardware Compatibility Publisher"}, true},
		{Result{Status: Signed, Signer: "Microsofty Ltd"}, false},
		{Result{Status: Signed, Signer: "Not Microsoft Corporation"}, false},
		{Result{Status: Invalid, Signer: "Microsoft Corporation"}, false},
		{Result{Status: Unsigned}, false},
	} {
		if got := test.result.FromMicrosoft(); got != test.want {
			t.Errorf("%+v: got %v, want %v", test.result, got, test.want)
		}
	}
}

func TestProblemsAreWorded(t *testing.T) {
	for _, code := range []uint32{codeBadDigest, codeExpired, codeUntrustedRoot, codeChaining, codeRevoked, codeDistrusted, codeWrongUsage, codeNotTrusted, codeFileError, 0x12345678} {
		if problem(code) == "" {
			t.Errorf("0x%08X has no wording", code)
		}
	}
	if !unsigned(codeNoSignature) || !unsigned(codeFormUnknown) || unsigned(codeBadDigest) {
		t.Error("a missing signature and a broken one are told apart wrongly")
	}
	if !(Result{Status: Invalid, Code: codeBadDigest}).Changed() || (Result{Status: Invalid, Code: codeExpired}).Changed() {
		t.Error("Changed is true only for a file altered after signing")
	}
}
