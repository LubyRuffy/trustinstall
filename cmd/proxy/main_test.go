package main

import (
	"net/http"
	"testing"
)

func TestPrepareOutgoingRequest_ClearsRequestURIAndFillsURL(t *testing.T) {
	r, err := http.NewRequest("GET", "http://example.com/path", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	// Mimic a server-side request where RequestURI is set.
	r.RequestURI = "/path"
	r.URL.Scheme = ""
	r.URL.Host = ""
	r.Host = "example.com"

	prepareOutgoingRequest(r, "http")

	if r.RequestURI != "" {
		t.Fatalf("RequestURI not cleared: %q", r.RequestURI)
	}
	if r.URL.Scheme != "http" {
		t.Fatalf("scheme not set: %q", r.URL.Scheme)
	}
	if r.URL.Host != "example.com" {
		t.Fatalf("host not set: %q", r.URL.Host)
	}
	if r.URL.Path != "/path" {
		t.Fatalf("path changed unexpectedly: %q", r.URL.Path)
	}
}

func TestSanitizeRequestForDump_RemovesSensitiveHeaders(t *testing.T) {
	r, err := http.NewRequest("GET", "http://example.com/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	r.Header.Set("Authorization", "Bearer secret")
	r.Header.Set("Proxy-Authorization", "Basic secret")
	r.Header.Set("Cookie", "a=b")
	r.Header.Set("X-Api-Key", "secret")
	r.Header.Set("X-Auth-Token", "secret")
	r.Header.Set("User-Agent", "ua")

	s := sanitizeRequestForDump(r)

	for _, k := range []string{"Authorization", "Proxy-Authorization", "Cookie", "X-Api-Key", "X-Auth-Token"} {
		if got := s.Header.Get(k); got != "" {
			t.Fatalf("expected %s removed, got %q", k, got)
		}
	}
	if got := s.Header.Get("User-Agent"); got == "" {
		t.Fatalf("expected User-Agent preserved")
	}
	// Ensure original request is untouched.
	if got := r.Header.Get("Authorization"); got == "" {
		t.Fatalf("original request was modified")
	}
}

func TestSanitizeResponseForDump_RemovesSetCookie(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
	}
	resp.Header.Add("Set-Cookie", "a=b")
	resp.Header.Set("Content-Type", "text/plain")

	s := sanitizeResponseForDump(resp)
	if got := s.Header.Get("Set-Cookie"); got != "" {
		t.Fatalf("expected Set-Cookie removed, got %q", got)
	}
	if got := s.Header.Get("Content-Type"); got == "" {
		t.Fatalf("expected Content-Type preserved")
	}
	// Ensure original response is untouched.
	if got := resp.Header.Get("Set-Cookie"); got == "" {
		t.Fatalf("original response was modified")
	}
}

func TestSplitHostPortDefault(t *testing.T) {
	t.Run("no port", func(t *testing.T) {
		h, p := splitHostPortDefault("example.com", "443")
		if h != "example.com" || p != "443" {
			t.Fatalf("got %q %q", h, p)
		}
	})
	t.Run("with port", func(t *testing.T) {
		h, p := splitHostPortDefault("example.com:8443", "443")
		if h != "example.com" || p != "8443" {
			t.Fatalf("got %q %q", h, p)
		}
	})
}
