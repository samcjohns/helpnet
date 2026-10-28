package probe

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func tarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(body))
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

// fakeRelease serves a GitHub "latest release" API with one linux/amd64
// archive. sum overrides the archive's checksum when non-empty.
func fakeRelease(t *testing.T, archive []byte, sum string) {
	t.Helper()
	if sum == "" {
		h := sha256.Sum256(archive)
		sum = hex.EncodeToString(h[:])
	}
	const name = "librespeed-cli_1.0.14_linux_amd64.tar.gz"
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest":
			fmt.Fprintf(w, `{"assets":[{"name":"checksums.txt","browser_download_url":"%[1]s/sums"},
				{"name":"librespeed-cli_1.0.14_darwin_arm64.tar.gz","browser_download_url":"%[1]s/wrong"},
				{"name":%[2]q,"browser_download_url":"%[1]s/archive"}]}`, srv.URL, name)
		case "/sums":
			fmt.Fprintf(w, "%s  other.tar.gz\n%s  %s\n", strings.Repeat("0", 64), sum, name)
		case "/archive":
			w.Write(archive)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	old := speedReleaseAPI
	speedReleaseAPI = srv.URL + "/latest"
	t.Cleanup(func() { speedReleaseAPI = old })
}

func TestDownloadSpeedTool(t *testing.T) {
	fakeRelease(t, tarGz(t, map[string]string{"LICENSE": "MIT", "librespeed-cli": "#!/bin/sh\necho hi\n"}), "")
	dir := filepath.Join(t.TempDir(), "bin")
	p, err := downloadSpeedTool(context.Background(), "linux", "amd64", dir)
	if err != nil {
		t.Fatal(err)
	}
	if p != filepath.Join(dir, "librespeed-cli") {
		t.Errorf("path = %q", p)
	}
	b, err := os.ReadFile(p)
	if err != nil || !strings.Contains(string(b), "echo hi") {
		t.Fatalf("installed file: %q, %v", b, err)
	}
	// Windows has no executable bit; the .exe name is what makes it runnable.
	if fi, _ := os.Stat(p); runtime.GOOS != "windows" && fi.Mode().Perm()&0o100 == 0 {
		t.Errorf("not executable: %v", fi.Mode())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("temp files left behind: %v", entries)
	}
}

func TestDownloadSpeedToolRejectsBadChecksum(t *testing.T) {
	fakeRelease(t, tarGz(t, map[string]string{"librespeed-cli": "x"}), strings.Repeat("a", 64))
	dir := t.TempDir()
	if _, err := downloadSpeedTool(context.Background(), "linux", "amd64", dir); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("err = %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("files written despite bad checksum: %v", entries)
	}
}

func TestDownloadSpeedToolNoAsset(t *testing.T) {
	fakeRelease(t, tarGz(t, map[string]string{"librespeed-cli": "x"}), "")
	if _, err := downloadSpeedTool(context.Background(), "plan9", "amd64", t.TempDir()); err == nil || !strings.Contains(err.Error(), "plan9/amd64") {
		t.Fatalf("err = %v", err)
	}
}

func TestChecksumFor(t *testing.T) {
	sums := "ABC123  a.tar.gz\ndef456 *b.zip\n"
	if got := checksumFor(sums, "a.tar.gz"); got != "abc123" {
		t.Errorf("a = %q", got)
	}
	if got := checksumFor(sums, "b.zip"); got != "def456" {
		t.Errorf("b = %q", got)
	}
	if got := checksumFor(sums, "c.zip"); got != "" {
		t.Errorf("c = %q", got)
	}
}
