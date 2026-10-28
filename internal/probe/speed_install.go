package probe

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// speedReleaseAPI is the GitHub endpoint for the latest librespeed-cli
// release. Tests point it at an httptest server.
var speedReleaseAPI = "https://api.github.com/repos/librespeed/speedtest-cli/releases/latest"

const maxSpeedDownload = 64 << 20 // release archives are ~4 MB

// SpeedInstallDir is where InstallSpeedTool puts librespeed-cli when no
// package manager is used: ~/.local/bin, or %LOCALAPPDATA%\nethelp\bin on
// Windows. No privileges are needed to write there.
func SpeedInstallDir() string {
	if runtime.GOOS == "windows" {
		if d := os.Getenv("LOCALAPPDATA"); d != "" {
			return filepath.Join(d, "nethelp", "bin")
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".local", "bin")
}

func speedBinaryName() string {
	if runtime.GOOS == "windows" {
		return "librespeed-cli.exe"
	}
	return "librespeed-cli"
}

// speedToolPath finds librespeed-cli on PATH or in SpeedInstallDir, which
// may not be on PATH.
func speedToolPath() string {
	if p := LookPath("librespeed-cli"); p != "" {
		return p
	}
	if d := SpeedInstallDir(); d != "" {
		p := filepath.Join(d, speedBinaryName())
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p
		}
	}
	return ""
}

// InstallSpeedTool installs librespeed-cli without privileges and returns
// its path. On macOS it uses Homebrew when available; otherwise it downloads
// the latest release from GitHub, verifies its SHA-256 checksum and unpacks
// the binary into SpeedInstallDir.
func InstallSpeedTool(ctx context.Context) (string, error) {
	if p := speedToolPath(); p != "" {
		return p, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	if runtime.GOOS == "darwin" && LookPath("brew") != "" {
		if out, err := RunCommand(ctx, "brew", "install", "librespeed-cli"); err != nil {
			return "", fmt.Errorf("brew install librespeed-cli: %v", firstLine(out, err))
		}
		if p := speedToolPath(); p != "" {
			return p, nil
		}
		return "", errors.New("brew finished but librespeed-cli is not on PATH")
	}
	return downloadSpeedTool(ctx, runtime.GOOS, runtime.GOARCH, SpeedInstallDir())
}

func downloadSpeedTool(ctx context.Context, goos, goarch, dir string) (string, error) {
	if dir == "" {
		return "", errors.New("no install directory (home directory unknown)")
	}
	var rel struct {
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	body, err := httpGet(ctx, speedReleaseAPI)
	if err != nil {
		return "", fmt.Errorf("looking up the latest release: %w", err)
	}
	if err := json.Unmarshal(body, &rel); err != nil {
		return "", fmt.Errorf("parsing release info: %w", err)
	}
	var archive, archiveURL, sumsURL string
	suffix := "_" + goos + "_" + goarch
	for _, a := range rel.Assets {
		switch {
		case a.Name == "checksums.txt":
			sumsURL = a.URL
		case strings.HasSuffix(a.Name, suffix+".tar.gz"), strings.HasSuffix(a.Name, suffix+".zip"):
			archive, archiveURL = a.Name, a.URL
		}
	}
	if archiveURL == "" {
		return "", fmt.Errorf("no librespeed-cli release for %s/%s", goos, goarch)
	}
	if sumsURL == "" {
		return "", errors.New("release has no checksums.txt")
	}
	sums, err := httpGet(ctx, sumsURL)
	if err != nil {
		return "", fmt.Errorf("downloading checksums: %w", err)
	}
	want := checksumFor(string(sums), archive)
	if want == "" {
		return "", fmt.Errorf("no checksum listed for %s", archive)
	}
	data, err := httpGet(ctx, archiveURL)
	if err != nil {
		return "", fmt.Errorf("downloading %s: %w", archive, err)
	}
	if got := sha256.Sum256(data); hex.EncodeToString(got[:]) != want {
		return "", fmt.Errorf("checksum mismatch for %s", archive)
	}
	name := "librespeed-cli"
	if goos == "windows" {
		name += ".exe"
	}
	bin, err := extractFile(archive, data, name)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, name)
	tmp, err := os.CreateTemp(dir, ".librespeed-cli-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(bin); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Chmod(tmp.Name(), 0o755); err != nil {
		return "", err
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return "", err
	}
	return dst, nil
}

func httpGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxSpeedDownload+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxSpeedDownload {
		return nil, errors.New("download too large")
	}
	return b, nil
}

// checksumFor finds the hex SHA-256 for file in a `sha256sum`-style list.
func checksumFor(sums, file string) string {
	for _, line := range strings.Split(sums, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == file {
			return strings.ToLower(f[0])
		}
	}
	return ""
}

// extractFile returns the contents of the file called name (in any
// directory) from a .tar.gz or .zip archive.
func extractFile(archive string, data []byte, name string) ([]byte, error) {
	if strings.HasSuffix(archive, ".zip") {
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return nil, err
		}
		for _, f := range zr.File {
			if path.Base(f.Name) == name && !f.FileInfo().IsDir() {
				rc, err := f.Open()
				if err != nil {
					return nil, err
				}
				defer rc.Close()
				return io.ReadAll(io.LimitReader(rc, maxSpeedDownload))
			}
		}
		return nil, fmt.Errorf("%s not found in %s", name, archive)
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("%s not found in %s", name, archive)
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag == tar.TypeReg && path.Base(h.Name) == name {
			return io.ReadAll(io.LimitReader(tr, maxSpeedDownload))
		}
	}
}
