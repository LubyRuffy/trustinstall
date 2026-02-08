package main

import "testing"

func TestNormalizeALPN(t *testing.T) {
	if got := normalizeALPN(""); got != "http/1.1" {
		t.Fatalf("normalizeALPN(\"\")=%q", got)
	}
	if got := normalizeALPN("  "); got != "http/1.1" {
		t.Fatalf("normalizeALPN(\"  \")=%q", got)
	}
	if got := normalizeALPN("h2"); got != "h2" {
		t.Fatalf("normalizeALPN(\"h2\")=%q", got)
	}
}

func TestFilterHTTPALPNs(t *testing.T) {
	{
		got := filterHTTPALPNs(nil)
		if len(got) != 1 || got[0] != "http/1.1" {
			t.Fatalf("filterHTTPALPNs(nil)=%v", got)
		}
	}
	{
		got := filterHTTPALPNs([]string{"h2", "http/1.1"})
		if len(got) != 2 || got[0] != "h2" || got[1] != "http/1.1" {
			t.Fatalf("filterHTTPALPNs(h2,http/1.1)=%v", got)
		}
	}
	{
		got := filterHTTPALPNs([]string{"spdy/3", "h2", "h2", "http/1.1", "foo"})
		if len(got) != 2 || got[0] != "h2" || got[1] != "http/1.1" {
			t.Fatalf("filterHTTPALPNs(mixed)=%v", got)
		}
	}
	{
		got := filterHTTPALPNs([]string{"http/1.1", "h2"})
		if len(got) != 2 || got[0] != "http/1.1" || got[1] != "h2" {
			t.Fatalf("filterHTTPALPNs(order)=%v", got)
		}
	}
}

func TestContainsString(t *testing.T) {
	if containsString(nil, "a") {
		t.Fatalf("containsString(nil, a)=true")
	}
	if !containsString([]string{"a", "b"}, "b") {
		t.Fatalf("containsString([a b], b)=false")
	}
	if containsString([]string{"a", "b"}, "c") {
		t.Fatalf("containsString([a b], c)=true")
	}
}
