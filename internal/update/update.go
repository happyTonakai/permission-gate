// Package update implements self-update for the pgate binary.
//
// It fetches release metadata from the GitHub Releases API, downloads the
// release artifact for the current OS/arch, and atomically replaces the
// running executable. The package does not perform auto-checks; callers
// invoke FetchLatest / FetchTag explicitly.
package update

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const (
	repo        = "happyTonakai/permission-gate"
	httpTimeout = 30 * time.Second
	userAgent   = "permission-gate-cli"
)

// URL builders. Exposed as package vars so tests can redirect at the
// httptest server without touching http.DefaultTransport. Production code
// relies on their zero values.
var (
	latestURL       = "https://api.github.com/repos/" + repo + "/releases/latest"
	tagURLBase      = "https://api.github.com/repos/" + repo
	downloadURLBase = "https://github.com/" + repo + "/releases/download"
)

// Release is the minimal subset of the GitHub release JSON we consume.
// Field tags match GitHub's wire format; everything else is ignored.
type Release struct {
	TagName    string `json:"tag_name"`
	Name       string `json:"name"`
	Prerelease bool   `json:"prerelease"`
	Draft      bool   `json:"draft"`
}

// FetchLatest returns the tag of the latest stable release, as reported by
// GitHub's /releases/latest endpoint. Pre-releases are not included unless
// the user explicitly opts in via the upstream "latest" flag.
func FetchLatest() (string, error) {
	rel, err := fetchRelease(latestURL)
	if err != nil {
		return "", err
	}
	return rel.TagName, nil
}

// FetchTag resolves a tag the user typed (e.g. "v1.2.3" or "1.2.3") against
// the GitHub API. The returned string is whatever the upstream uses — the
// caller can compare it directly to version values produced by -ldflags.
func FetchTag(tag string) (string, error) {
	if tag == "" {
		return "", fmt.Errorf("empty tag")
	}
	url := tagURLBase + "/releases/tags/" + tag
	rel, err := fetchRelease(url)
	if err != nil {
		return "", err
	}
	return rel.TagName, nil
}

// fetchRelease performs a single authenticated-by-being-on-GitHub GET.
// It is exported only via FetchLatest / FetchTag above — both keep their
// own error wrapping consistent.
func fetchRelease(url string) (*Release, error) {
	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GitHub API: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// fall through
	case http.StatusNotFound:
		return nil, fmt.Errorf("GitHub API: release not found at %s", url)
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("GitHub API: HTTP %d: %s", resp.StatusCode, body)
	}

	var rel Release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("decode GitHub response: %w", err)
	}
	return &rel, nil
}

// BinaryName returns the canonical release asset name for the current
// OS/arch, matching what the release workflow in .github/workflows/release.yml
// uploads (e.g. "pgate_darwin_arm64").
func BinaryName() string {
	return fmt.Sprintf("pgate_%s_%s", runtime.GOOS, runtime.GOARCH)
}

// BinaryURL returns the GitHub download URL for a given release tag.
func BinaryURL(tag string) string {
	return downloadURLBase + "/" + tag + "/" + BinaryName()
}

// Download fetches the binary asset for the given tag and returns its
// bytes. The asset is sanity-checked for an executable magic number so we
// don't write HTML error pages over a working binary.
func Download(tag string) ([]byte, error) {
	if tag == "" {
		return nil, fmt.Errorf("empty tag")
	}
	url := BinaryURL(tag)

	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Drain a small prefix of error bodies so the message is useful
		// without buffering arbitrarily large HTML pages.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("download %s: HTTP %d: %s", url, resp.StatusCode, body)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", url, err)
	}
	if len(body) < 4 {
		return nil, fmt.Errorf("download %s: response too small (%d bytes)", url, len(body))
	}
	if !looksLikeBinary(body) {
		return nil, fmt.Errorf("download %s: response is not a recognizable binary", url)
	}
	return body, nil
}

// looksLikeBinary checks for executable magic numbers. Anything else —
// HTML, JSON error, plain text — is rejected so a 5xx that returns a JSON
// error body doesn't silently overwrite the working binary.
//
// Coverage:
//   - ELF (\x7fELF)         — Linux
//   - Mach-O 32 LE / 64 LE / 64 BE / 32 BE / universal (FAT) — macOS
//   - PE / MZ                — Windows (not currently shipped, but harmless)
func looksLikeBinary(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	if b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F' {
		return true
	}
	if b[0] == 'M' && b[1] == 'Z' {
		return true
	}
	switch [4]byte{b[0], b[1], b[2], b[3]} {
	case [4]byte{0xcf, 0xfa, 0xed, 0xfe}, // Mach-O 64 LE
		[4]byte{0xfe, 0xed, 0xfa, 0xce}, // Mach-O 32 BE
		[4]byte{0xfe, 0xed, 0xfa, 0xcf}, // Mach-O 64 BE
		[4]byte{0xce, 0xfa, 0xed, 0xfe}, // Mach-O 32 LE
		[4]byte{0xca, 0xfe, 0xba, 0xbe}: // Mach-O universal / FAT
		return true
	}
	return false
}

// Replace overwrites currentPath with newBinary atomically: the temp file
// is created in the same directory (so os.Rename is atomic), fsynced,
// renamed into place, and only then visible. On failure the temp file is
// removed and currentPath is left untouched.
func Replace(currentPath string, newBinary []byte) error {
	if currentPath == "" {
		return fmt.Errorf("empty target path")
	}
	if len(newBinary) == 0 {
		return fmt.Errorf("empty binary payload")
	}

	dir, base := filepath.Dir(currentPath), filepath.Base(currentPath)
	tmp, err := os.CreateTemp(dir, base+".update.*")
	if err != nil {
		return fmt.Errorf("create temp in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }
	success := false
	defer func() {
		if !success {
			cleanup()
		}
	}()

	if _, err := tmp.Write(newBinary); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	// Release artifacts are executables on disk; preserve the install.sh
	// contract of 0755. CreateTemp defaults to 0600 which would break the
	// next "pgate check" call.
	if err := tmp.Chmod(0755); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpPath, currentPath); err != nil {
		return fmt.Errorf("rename %s -> %s: %w", tmpPath, currentPath, err)
	}
	success = true
	return nil
}
