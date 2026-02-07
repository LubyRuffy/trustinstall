//go:build integration

package integration

import "testing"

func TestShellQuote(t *testing.T) {
	got := shellQuote("abc")
	if got != "'abc'" {
		t.Fatalf("unexpected: %q", got)
	}
	got = shellQuote("a'b")
	if got != `'a'"'"'b'` {
		t.Fatalf("unexpected: %q", got)
	}
}

func TestIsUTMCtlAutomationDenied(t *testing.T) {
	if !isUTMCtlAutomationDenied("OSStatus error -1743") {
		t.Fatalf("expected true")
	}
	if !isUTMCtlAutomationDenied("NOTE: utmctl does not work from SSH sessions or before logging in.") {
		t.Fatalf("expected true")
	}
	if isUTMCtlAutomationDenied("UUID Status Name") {
		t.Fatalf("expected false")
	}
}
