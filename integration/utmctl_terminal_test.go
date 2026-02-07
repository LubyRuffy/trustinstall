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

func TestIsUTMCtlEventError(t *testing.T) {
	if !isUTMCtlEventError("Error from event: The operation couldn’t be completed. (OSStatus error -10004.)") {
		t.Fatalf("expected true")
	}
	if !isUTMCtlEventError("OSStatus error -10004") {
		t.Fatalf("expected true")
	}
	if isUTMCtlEventError("ok\n") {
		t.Fatalf("expected false")
	}
}
