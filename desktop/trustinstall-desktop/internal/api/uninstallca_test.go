package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUninstallCA_DefaultCommonName(t *testing.T) {
	t.Parallel()

	inst := &stubInstaller{}
	h := newRouter(inst)

	body, _ := json.Marshal(map[string]any{
		"commonName": "",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/uninstallca", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if len(inst.uninstallArgs) != 1 {
		t.Fatalf("uninstallArgs=%d, want 1", len(inst.uninstallArgs))
	}
	if inst.uninstallArgs[0].commonName != "trustinstall-ca" {
		t.Fatalf("commonName=%q", inst.uninstallArgs[0].commonName)
	}
}

func TestUninstallCA_DeleteLocalFiles(t *testing.T) {
	t.Parallel()

	inst := &stubInstaller{}
	h := newRouter(inst)

	body, _ := json.Marshal(map[string]any{
		"commonName":   "cn",
		"deleteLocal":  true,
		"dir":          "/tmp/x",
		"fileBaseName": "a",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/uninstallca", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	// Local deletion is now handled inside trustinstall package; stubInstaller does not remove files.
	if len(inst.uninstallArgs) != 1 {
		t.Fatalf("uninstallArgs=%d, want 1", len(inst.uninstallArgs))
	}
	if !inst.uninstallArgs[0].deleteLocal {
		t.Fatalf("deleteLocal=false, want true")
	}
}

func TestUninstallCA_Error(t *testing.T) {
	t.Parallel()

	inst := &stubInstaller{uninstallErr: errTest}
	h := newRouter(inst)

	body, _ := json.Marshal(map[string]any{
		"commonName": "cn",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/uninstallca", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}
