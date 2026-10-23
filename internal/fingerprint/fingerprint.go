package fingerprint

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var phpVersionRe = regexp.MustCompile(`PHP/(\d+\.\d+\.\d+)`)

type Info struct {
	IsPHP   bool
	Version string
	Source  string
}

func Detect(ctx context.Context, c *http.Client, target, ua string) Info {
	paths := []string{target, joinPath(target, "/index.php"), joinPath(target, "/?php=1")}
	for _, p := range paths {
		info := probe(ctx, c, p, ua)
		if info.IsPHP {
			return info
		}
	}
	return Info{}
}

func probe(ctx context.Context, c *http.Client, u, ua string) Info {
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return Info{}
	}
	if ua == "" {
		ua = "Mozilla/5.0 (compatible; php2shell-scanner/1.0)"
	}
	req.Header.Set("User-Agent", ua)

	resp, err := c.Do(req)
	if err != nil {
		return Info{}
	}
	defer resp.Body.Close()

	var info Info
	powered := resp.Header.Get("X-Powered-By")
	server := resp.Header.Get("Server")
	cookie := resp.Header.Get("Set-Cookie")

	hay := strings.ToLower(powered + " " + server + " " + cookie)
	if strings.Contains(hay, "php") {
		info.IsPHP = true
		info.Source = "header"
	}

	full := powered + " " + server
	if m := phpVersionRe.FindStringSubmatch(full); m != nil {
		info.Version = m[1]
		info.IsPHP = true
		info.Source = "version-header"
	}
	return info
}

func joinPath(base, p string) string {
	base = strings.TrimRight(base, "/")
	if strings.HasPrefix(p, "/") {
		return base + p
	}
	return base + "/" + p
}

func IsVersionVulnerable(v string, fixed map[string]string) bool {
	if v == "" {
		return true
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return true
	}
	branch := parts[0] + "." + parts[1]
	fixedForBranch, ok := fixed[branch]
	if !ok {
		return false
	}
	return compareSemver(v, fixedForBranch) < 0
}

func compareSemver(a, b string) int {
	pa := strings.Split(a, ".")
	pb := strings.Split(b, ".")
	for i := 0; i < 3; i++ {
		na, nb := atoi(pa[i]), atoi(pb[i])
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