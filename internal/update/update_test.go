package update

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLooksLikeBinary(t *testing.T) {
	cases := []struct {
		name string
		head []byte
		want bool
	}{
		{"elf", []byte{0x7f, 'E', 'L', 'F'}, true},
		{"macho-64-le", []byte{0xcf, 0xfa, 0xed, 0xfe}, true},
		{"macho-64-be", []byte{0xfe, 0xed, 0xfa, 0xcf}, true},
		{"macho-32-le", []byte{0xce, 0xfa, 0xed, 0xfe}, true},
		{"macho-32-be", []byte{0xfe, 0xed, 0xfa, 0xce}, true},
		{"macho-fat", []byte{0xca, 0xfe, 0xba, 0xbe}, true},
		{"mz", []byte{'M', 'Z', 0x00, 0x00}, true},
		{"mz-real", append([]byte{'M', 'Z'}, make([]byte, 60)...), true},
		{"html", []byte("<!DO"), false},
		{"json", []byte("{\"e"), false},
		{"text", []byte("404 Not Found"), false},
		{"empty", nil, false},
		{"too-short", []byte{0x7f, 'E'}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := looksLikeBinary(c.head); got != c.want {
				t.Errorf("looksLikeBinary(%v) = %v, want %v", c.head, got, c.want)
			}
		})
	}
}

func TestReplace(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "pgate")
	if err := os.WriteFile(target, []byte("old"), 0755); err != nil {
		t.Fatalf("seed: %v", err)
	}

	newContent := []byte("new binary bytes, not actually executable")
	if err := Replace(target, newContent); err != nil {
		t.Fatalf("Replace: %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != string(newContent) {
		t.Errorf("content mismatch: got %q, want %q", got, newContent)
	}

	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0755 {
		t.Errorf("mode = %o, want 0755", got)
	}
}

func TestReplaceLeavesOriginalOnFailure(t *testing.T) {
	// Empty payload must not touch the target.
	dir := t.TempDir()
	target := filepath.Join(dir, "pgate")
	original := []byte("keep me")
	if err := os.WriteFile(target, original, 0755); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := Replace(target, nil); err == nil {
		t.Fatal("expected error for empty payload, got nil")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != string(original) {
		t.Errorf("target was modified: got %q, want %q", got, original)
	}

	// Temp cleanup
	entries, _ := os.ReadDir(dir)
	if n := len(entries); n != 1 {
		t.Errorf("unexpected leftover files in dir: %d (want 1)", n)
		for _, e := range entries {
			t.Logf("  - %s", e.Name())
		}
	}
}

// TestFetchLatest covers the parsing path against an httptest server. The
// real /releases/latest endpoint is mocked so this test doesn't require
// network access.
func TestFetchLatest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/releases/latest") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Accept"); got != "application/vnd.github+json" {
			t.Errorf("Accept header = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tag_name": "v1.2.3",
			"name":     "v1.2.3",
			"draft":    false,
		})
	}))
	defer srv.Close()

	// Redirect the package's hardcoded URL at the test server.
	orig := latestURL
	latestURL = srv.URL + "/repos/test/test/releases/latest"
	defer func() { latestURL = orig }()

	got, err := FetchLatest()
	if err != nil {
		t.Fatalf("FetchLatest: %v", err)
	}
	if got != "v1.2.3" {
		t.Errorf("FetchLatest = %q, want v1.2.3", got)
	}
}

func TestFetchLatest_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	orig := latestURL
	latestURL = srv.URL + "/releases/latest"
	defer func() { latestURL = orig }()

	_, err := FetchLatest()
	if err == nil {
		t.Fatal("expected error for 404, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error %q should mention 'not found'", err.Error())
	}
}

func TestFetchTag_Empty(t *testing.T) {
	if _, err := FetchTag(""); err == nil {
		t.Fatal("expected error for empty tag, got nil")
	}
}

func TestFetchTag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/releases/tags/v1.2.3") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"tag_name": "v1.2.3"})
	}))
	defer srv.Close()

	orig := tagURLBase
	tagURLBase = srv.URL + "/repos/test/test"
	defer func() { tagURLBase = orig }()

	got, err := FetchTag("v1.2.3")
	if err != nil {
		t.Fatalf("FetchTag: %v", err)
	}
	if got != "v1.2.3" {
		t.Errorf("FetchTag = %q, want v1.2.3", got)
	}
}

func TestDownload_RejectsHTML(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, "<!DOCTYPE html><html>404 Not Found</html>")
	}))
	defer srv.Close()

	origDownload := downloadURLBase
	downloadURLBase = srv.URL + "/repos/test/test/releases/download"
	defer func() { downloadURLBase = origDownload }()

	_, err := Download("v1.2.3")
	if err == nil {
		t.Fatal("expected error for HTML response, got nil")
	}
	if !strings.Contains(err.Error(), "not a recognizable binary") {
		t.Errorf("error %q should mention binary validation", err.Error())
	}
}

func TestDownload_AcceptsBinary(t *testing.T) {
	// Synthesize a tiny ELF-like payload: the magic bytes plus a couple of
	// zero bytes for the sanity check. We don't actually exec it.
	payload := append([]byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00}, make([]byte, 16)...)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	origDownload := downloadURLBase
	downloadURLBase = srv.URL + "/repos/test/test/releases/download"
	defer func() { downloadURLBase = origDownload }()

	got, err := Download("v9.9.9")
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("Download returned different payload")
	}
}
