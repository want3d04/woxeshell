package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"woxeshell/internal/model"
)

type Reporter interface {
	Report(r model.Result)
	Flush()
	CountVulnerable() int
	CountScanned() int
	CountErrors() int
}

type impl struct {
	mu      sync.Mutex
	color   bool
	verbose bool
	outPath string
	outFile *os.File
	enc     *json.Encoder
	vulnCnt int
	errCnt  int
	scanned int
}

func New(outPath string, color, verbose bool) Reporter {
	r := &impl{color: color, verbose: verbose, outPath: outPath}
	if outPath != "" {
		f, err := os.Create(outPath)
		if err == nil {
			r.outFile = f
			r.enc = json.NewEncoder(f)
		} else {
			fmt.Fprintln(os.Stderr, "json output error:", err)
		}
	}
	return r
}

func (r *impl) Report(res model.Result) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scanned++

	if r.enc != nil {
		_ = r.enc.Encode(res)
	}

	switch {
	case res.Vulnerable:
		r.vulnCnt++
		r.printVuln(res)
	case res.Error != "":
		r.errCnt++
		r.printErr(res)
	case !res.PHP:
		r.printSkip(res)
	default:
		r.printSafe(res)
	}
}

func (r *impl) c(code, s string) string {
	if !r.color {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (r *impl) printVuln(res model.Result) {
	ver := ""
	if res.Version != "" {
		ver = " (PHP " + res.Version + ")"
	}
	exec := ""
	if res.Exec {
		exec = r.c("1;35", " [php-exec observed]")
	}
	fmt.Printf("%s %s%s%s\n", r.c("1;31", "[VULN]"), res.Target, ver, exec)
	for _, v := range res.CVEs {
		fmt.Printf("       %s\n", r.c("33", v))
	}
	for _, e := range res.Evidence {
		fmt.Printf("       - %s\n", e)
	}
}

func (r *impl) printSafe(res model.Result) {
	ver := ""
	if res.Version != "" {
		ver = " (PHP " + res.Version + ")"
	}
	fmt.Printf("%s %s%s\n", r.c("1;32", "[SAFE]"), res.Target, ver)

	if r.verbose {
		for _, e := range res.Evidence {
			fmt.Printf("       - %s\n", e)
		}
		if len(res.Evidence) == 0 {
			fmt.Printf("       - %s\n", r.c("2", "no indicators matched"))
		}
	} else {
		fmt.Printf("       %s\n", r.c("2", "no indicators found (run with -v for details)"))
	}
}

func (r *impl) printSkip(res model.Result) {
	fmt.Printf("%s %s\n", r.c("1;90", "[SKIP]"), res.Target)
	if r.verbose {
		fmt.Printf("       - %s\n", r.c("2", "not identified as PHP (headers) and PHP execution not observed (active probe)"))
	}
}

func (r *impl) printErr(res model.Result) {
	fmt.Printf("%s %s (%s)\n", r.c("1;33", "[ERR ]"), res.Target, res.Error)
}

func (r *impl) Flush() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.outFile != nil {
		_ = r.outFile.Sync()
		_ = r.outFile.Close()
	}
}

func (r *impl) CountVulnerable() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.vulnCnt
}

func (r *impl) CountScanned() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.scanned
}

func (r *impl) CountErrors() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.errCnt
}
