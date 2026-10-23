package target

import (
	"bufio"
	"errors"
	"os"
	"strings"
)

func Load(single, listFile string) ([]string, error) {
	seen := map[string]struct{}{}
	var out []string

	add := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" || strings.HasPrefix(u, "#") {
			return
		}
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			u = "https://" + u
		}
		if _, ok := seen[u]; ok {
			return
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}

	if single != "" {
		add(single)
	}
	if listFile != "" {
		f, err := os.Open(listFile)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			add(sc.Text())
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no valid targets (use -u or -l)")
	}
	return out, nil
}

func HostOf(u string) string {
	s := u
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	return s
}