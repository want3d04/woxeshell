package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"woxeshell/internal/reporter"
	"woxeshell/internal/scanner"
	"woxeshell/internal/target"
)

const version = "1.1.0"

type headerFlags []string

func (h *headerFlags) String() string { return strings.Join(*h, ", ") }
func (h *headerFlags) Set(v string) error {
	*h = append(*h, v)
	return nil
}

const banner = `
                             _           _ _
                            | |         | | |
 _ _ _  ___ _   _ _____  ___| |__  _____| | |
| | | |/ _ ( \ / ) ___ |/___)  _ \| ___ | | |
| | | | |_| ) X (| ____|___ | | | | ____| | |
 \___/ \___(_/ \_)_____|___/|_| |_|_____)\_)_)

            woxeshell - php2shell detection scanner v` + version + `
    CVE-2026-109618 / CVE-2026-109619  |  author : w4nt3d
`

func printBanner(noColor bool) {
	if noColor {
		fmt.Fprint(os.Stderr, banner)
		return
	}
	fmt.Fprint(os.Stderr, "\x1b[1;36m"+banner+"\x1b[0m")
}

func main() {
	var (
		urlFlag    = flag.String("u", "", "single target URL")
		listFlag   = flag.String("l", "", "file with target URLs")
		outFlag    = flag.String("o", "", "write JSONL report to this file")
		conc       = flag.Int("c", 10, "concurrency")
		timeout    = flag.Duration("t", 20*time.Second, "per-request timeout")
		maxTotal   = flag.Duration("max-time", 0, "global timeout (0 = unlimited)")
		rate       = flag.Int("r", 0, "global rate limit (req/sec), 0 = unlimited")
		ua         = flag.String("ua", "", "custom User-Agent")
		insecure   = flag.Bool("k", false, "skip TLS verification")
		proxy      = flag.String("x", "", "proxy URL (http://, socks5://)")
		verbose    = flag.Bool("v", false, "verbose")
		noColor    = flag.Bool("no-color", false, "disable ANSI colors")
		noBanner   = flag.Bool("no-banner", false, "suppress banner")
		skipFinger = flag.Bool("skip-fingerprint", false, "assume PHP, skip passive fingerprinting")
		retries    = flag.Int("retries", 1, "retries per request on transient errors")
		probeMB    = flag.Int("probe-size", 32, "oversized-body probe size in MB (CVE-2026-109618)")
		pairs      = flag.Int("pairs", 3, "A/B request pairs per target (CVE-2026-109619)")
		settle     = flag.Duration("settle", time.Second, "wait after oversized request before health check")
		showVer    = flag.Bool("version", false, "print version and exit")
	)
	var extraHeaders headerFlags
	flag.Var(&extraHeaders, "H", "extra header 'Name: Value' (repeatable)")
	flag.Usage = usage
	flag.Parse()

	if *showVer {
		fmt.Println("woxeshell " + version)
		return
	}

	if !*noBanner {
		printBanner(*noColor)
	}

	if *probeMB < 1 {
		*probeMB = 1
	}
	if *probeMB > 1024 {
		fmt.Fprintln(os.Stderr, "warning: capping -probe-size to 1024 MB")
		*probeMB = 1024
	}

	targets, err := target.Load(*urlFlag, *listFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		flag.Usage()
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if *maxTotal > 0 {
		var c2 context.CancelFunc
		ctx, c2 = context.WithTimeout(ctx, *maxTotal)
		defer c2()
	}

	hdrs := http.Header{}
	for _, h := range extraHeaders {
		if i := strings.Index(h, ":"); i > 0 {
			hdrs.Add(strings.TrimSpace(h[:i]), strings.TrimSpace(h[i+1:]))
		}
	}

	rep := reporter.New(*outFlag, !*noColor, *verbose)
	sc := scanner.New(scanner.Options{
		Concurrency:    *conc,
		Timeout:        *timeout,
		RatePerSec:     *rate,
		UserAgent:      *ua,
		Verbose:        *verbose,
		Reporter:       rep,
		InsecureTLS:    *insecure,
		ProxyURL:       *proxy,
		ExtraHeaders:   hdrs,
		SkipFinger:     *skipFinger,
		Retries:        *retries,
		ProbeSizeBytes: int64(*probeMB) << 20,
		Pairs:          *pairs,
		Settle:         *settle,
	})

	start := time.Now()
	sc.Run(ctx, targets)
	rep.Flush()

	vuln := rep.CountVulnerable()
	scanned := rep.CountScanned()
	errs := rep.CountErrors()

	summaryColor := func(code, s string) string {
		if *noColor {
			return s
		}
		return "\x1b[" + code + "m" + s + "\x1b[0m"
	}

	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "summary: %d target(s) scanned in %s\n",
		scanned, time.Since(start).Round(time.Millisecond))
	if errs > 0 {
		fmt.Fprintf(os.Stderr, "         %d target(s) unreachable or errored\n", errs)
	}
	if vuln > 0 {
		fmt.Fprintf(os.Stderr, "result : %s\n", summaryColor("1;31", fmt.Sprintf("%d vulnerable", vuln)))
	} else {
		fmt.Fprintf(os.Stderr, "result : %s\n", summaryColor("1;32", "0 vulnerable"))
	}

	if vuln > 0 {
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, banner)
	fmt.Fprintf(os.Stderr, `
woxeshell - detection-only scanner for:
  CVE-2026-109618  PHP OOM corruption during request cleanup
  CVE-2026-109619  PHP stale request-owned global state on same worker

Usage:
  woxeshell -u https://host
  woxeshell -l targets.txt -c 20 -o report.jsonl -v

Flags:
`)
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, `
Exit codes:
  0  no indicators
  1  at least one indicator
  2  usage error

Authorized testing only. Positive result is an indicator, not proof of RCE.
`)
}
