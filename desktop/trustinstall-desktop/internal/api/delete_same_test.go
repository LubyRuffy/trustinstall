package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInstallCA_DeleteSamePassthroughFalse(t *testing.T) {
	t.Parallel()

	inst := &stubInstaller{}
	h := newRouter(inst)

	body, _ := json.Marshal(map[string]any{
		"dir":          "/tmp/x",
		"fileBaseName": "a",
		"commonName":   "b",
		"deleteSame":   false,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/installca", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if len(inst.calls) != 1 {
		t.Fatalf("calls=%d, want 1", len(inst.calls))
	}
	if inst.calls[0].deleteSame {
		t.Fatalf("deleteSame=true, want false")
	}
}
