package probe

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"
)

// CaptiveResult describes the plain-HTTP connectivity check.
type CaptiveResult struct {
	URL        string `json:"url"`
	Status     int    `json:"status,omitempty"`
	Location   string `json:"location,omitempty"`
	BodySample string `json:"body_sample,omitempty"`
	Detected   bool   `json:"detected"`
	Error      string `json:"error,omitempty"`
}

// CheckCaptivePortal requests a known endpoint that should answer 204 with an
// empty body. A redirect or unexpected body means something is intercepting
// plain HTTP — almost always a hotel/airport login page.
func CheckCaptivePortal(ctx context.Context, url string, timeout time.Duration) CaptiveResult {
	r := CaptiveResult{URL: url}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client := &http.Client{
		Transport: &http.Transport{DisableKeepAlives: true, Proxy: http.ProxyFromEnvironment},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	resp, err := client.Do(req)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	r.Status = resp.StatusCode
	r.Location = resp.Header.Get("Location")
	r.BodySample = strings.TrimSpace(string(body))
	if len(r.BodySample) > 120 {
		r.BodySample = r.BodySample[:120] + "…"
	}
	r.Detected = resp.StatusCode != http.StatusNoContent || len(body) > 0
	return r
}
