package fingerprint

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// DefaultUA is shared with the scanner so every request identifies itself
// consistently (the old code used two different default UAs).
const DefaultUA = "Mozilla/5.0 (compatible; woxeshell/1.0)"

var phpVersionRe = regexp.MustCompile(`PHP/(\d+\.\d+\.\d+)`)

type Info struct {
	IsPHP   bool
	Version string
	Source  string
	// FinalURL is the URL after following same-host redirects; the active
	// checks must target it instead of the original URL or every probe
	// would only collect the redirect response.
	FinalURL string
	// Error is set only when every passive probe failed at the network
	// level (unreachable target). A reachable non-PHP target has no error.
	Error string
}

// Detect passively probes the target for PHP indicators. It follows
// same-host redirects (up to 3 hops) which the old code silently ignored,
// causing redirects-to-PHP sites to be reported as non-PHP.
func Detect(ctx context.Context, c *http.Client, target, ua string) Info {
	paths := []string{target, joinPath(target, "/index.php")}
	sawResp := false
	finalURL := ""
	var lastErr string
	for _, p := range paths {
		info, err := probe(ctx, c, p, ua)
		if err != nil {
			lastErr = err.Error()
			continue
		}
		sawResp = true
		if info.IsPHP {
			return info
		}
		if info.FinalURL != "" {
			finalURL = info.FinalURL
		}
	}
	if !sawResp {
		return Info{Error: lastErr}
	}
	return Info{FinalURL: finalURL}
}

func probe(ctx context.Context, c *http.Client, u, ua string) (Info, error) {
	var info Info
	current := u
	for hops := 0; hops < 4; hops++ {
		req, err := http.NewRequestWithContext(ctx, "GET", current, nil)
		if err != nil {
			return info, err
		}
		if ua == "" {
			ua = DefaultUA
		}
		req.Header.Set("User-Agent", ua)

		resp, err := c.Do(req)
		if err != nil {
			return info, err
		}
		powered := resp.Header.Get("X-Powered-By")
		server := resp.Header.Get("Server")
		cookie := resp.Header.Get("Set-Cookie")
		// Drain a little of the body so the keep-alive connection can be
		// reused (the old code left bodies unread, forcing a new TCP
		// connection for every request).
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8192))
		_ = resp.Body.Close()

		full := powered + " " + server
		info.FinalURL = current
		if m := phpVersionRe.FindStringSubmatch(full); m != nil {
			info.Version = m[1]
			info.IsPHP = true
			info.Source = "version-header"
			return info, nil
		}
		hay := strings.ToLower(powered + " " + server + " " + cookie)
		if strings.Contains(hay, "php") {
			info.IsPHP = true
			info.Source = "header"
			return info, nil
		}

		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			loc := resp.Header.Get("Location")
			if next, ok := sameHostRedirect(current, loc); ok {
				current = next
				continue
			}
		}
		return info, nil
	}
	return info, nil
}

func sameHostRedirect(base, loc string) (string, bool) {
	if loc == "" {
		return "", false
	}
	bu, err := url.Parse(base)
	if err != nil {
		return "", false
	}
	lu, err := bu.Parse(loc)
	if err != nil || lu.Host == "" || lu.Host != bu.Host {
		return "", false
	}
	if lu.Scheme != "http" && lu.Scheme != "https" {
		return "", false
	}
	return lu.String(), true
}

func joinPath(base, p string) string {
	base = strings.TrimRight(base, "/")
	if strings.HasPrefix(p, "/") {
		return base + p
	}
	return base + "/" + p
}

// VerStatus is the tri-state result of comparing a version against the
// known-fixed map. The old boolean logic treated every branch that was not
// in the map (e.g. PHP 7.4) as "patched" and skipped scanning entirely.
type VerStatus int

const (
	VerUnknown VerStatus = iota
	VerVulnerable
	VerPatched
)

func VersionStatus(v string, fixed map[string]string) VerStatus {
	if v == "" {
		return VerUnknown
	}
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return VerUnknown
	}
	branch := parts[0] + "." + parts[1]
	fixedForBranch, ok := fixed[branch]
	if !ok {
		return VerUnknown
	}
	if compareSemver(v, fixedForBranch) < 0 {
		return VerVulnerable
	}
	return VerPatched
}

// IsVersionVulnerable is kept for compatibility with the old API.
func IsVersionVulnerable(v string, fixed map[string]string) bool {
	return VersionStatus(v, fixed) == VerVulnerable
}

func compareSemver(a, b string) int {
	pa := strings.Split(a, ".")
	pb := strings.Split(b, ".")
	for i := 0; i < 3; i++ {
		var na, nb int
		if i < len(pa) {
			na = atoi(pa[i])
		}
		if i < len(pb) {
			nb = atoi(pb[i])
		}
		if na < nb {
			return -1
		}
		if na > nb {
			return 1
		}
	}
	return 0
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func DefaultFixed() map[string]string {
	return map[string]string{
		"8.5": "8.5.12",
		"8.4": "8.4.27",
		"8.3": "8.3.36",
		"8.2": "8.2.35",
	}
}

func SetDeadline(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, d)
}
