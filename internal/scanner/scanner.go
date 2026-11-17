package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"woxeshell/internal/fingerprint"
	"woxeshell/internal/model"
	"woxeshell/internal/reporter"
)

type Options struct {
	Concurrency  int
	Timeout      time.Duration
	RatePerSec   int
	UserAgent    string
	Verbose      bool
	Reporter     reporter.Reporter
	InsecureTLS  bool
	ProxyURL     string
	ExtraHeaders http.Header
	SkipFinger   bool
	Retries      int
	ProbeSizeBytes int64

	Pairs int

	Settle time.Duration
}

type Scanner struct {
	opts   Options
	client *http.Client
	sem    chan struct{}
}

func New(o Options) *Scanner {
	if o.Concurrency <= 0 {
		o.Concurrency = 10
	}
	if o.Timeout <= 0 {
		o.Timeout = 20 * time.Second
	}
	if o.Retries < 0 {
		o.Retries = 0
	}
	if o.ProbeSizeBytes <= 0 {
		o.ProbeSizeBytes = 32 << 20
	}
	if o.Pairs <= 0 {
		o.Pairs = 3
	}
	if o.Settle <= 0 {
		o.Settle = time.Second
	}

	return &Scanner{
		opts:   o,
		client: buildClient(o),
		sem:    make(chan struct{}, o.Concurrency),
	}
}

func (s *Scanner) Run(ctx context.Context, targets []string) {
	var wg sync.WaitGroup
	results := make(chan model.Result, s.opts.Concurrency*2)

	consumerDone := make(chan struct{})
	go func() {
		defer close(consumerDone)
		for r := range results {
			s.opts.Reporter.Report(r)
		}
	}()


	var tickC <-chan time.Time
	if s.opts.RatePerSec > 0 {
		interval := time.Second / time.Duration(s.opts.RatePerSec)
		if interval <= 0 {
			interval = time.Millisecond
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		tickC = ticker.C
	}

loop:
	for _, t := range targets {
		if tickC != nil {
			select {
			case <-tickC:
			case <-ctx.Done():
				break loop
			}
		}
		select {
		case <-ctx.Done():
			break loop
		case s.sem <- struct{}{}:
		}
		wg.Add(1)
		go func(t string) {
			defer wg.Done()
			defer func() { <-s.sem }()
			var res model.Result
			defer func() {
				if r := recover(); r != nil {
					res = model.Result{Target: t, Error: fmt.Sprintf("internal error: %v", r)}
				}
				select {
				case results <- res:
				case <-ctx.Done():
				}
			}()
			res = s.probe(ctx, t)
		}(t)
	}

	wg.Wait()
	close(results)
	<-consumerDone
}

func (s *Scanner) probe(ctx context.Context, target string) (res model.Result) {
	start := time.Now()
	res = model.Result{Target: target, At: start.UTC().Format(time.RFC3339)}
	defer func() { res.DurationMS = time.Since(start).Milliseconds() }()


	tctx, cancel := fingerprint.SetDeadline(ctx, s.opts.Timeout*4)
	defer cancel()

	var fp fingerprint.Info
	checkTarget := target
	if s.opts.SkipFinger {
		res.PHP = true
		res.PHPSource = "assumed (skip-fingerprint)"
	} else {
		fp = fingerprint.Detect(tctx, s.client, target, s.opts.UserAgent)
		res.PHP = fp.IsPHP
		res.Version = fp.Version
		res.PHPSource = fp.Source
		if fp.FinalURL != "" && fp.FinalURL != target {

			checkTarget = fp.FinalURL
			res.Evidence = append(res.Evidence, "active checks redirected to "+fp.FinalURL)
		}
	}


	if fp.Version != "" {
		switch fingerprint.VersionStatus(fp.Version, fingerprint.DefaultFixed()) {
		case fingerprint.VerPatched:
			res.Evidence = append(res.Evidence,
				"version "+fp.Version+" >= fixed release for its branch; skipping active probes")
			return res
		case fingerprint.VerVulnerable:
			res.Evidence = append(res.Evidence,
				"version "+fp.Version+" is below the fixed release for its branch")
		default:

			res.Evidence = append(res.Evidence,
				"version "+fp.Version+" has no official fix release for its branch; running active probes anyway")
		}
	}


	vuln619, executed, ev := s.check109619(tctx, checkTarget)
	res.Evidence = append(res.Evidence, ev...)
	if executed {
		res.PHP = true
		res.Exec = true
		res.PHPSource = "active-probe"
	}
	if vuln619 {
		res.CVEs = append(res.CVEs, "CVE-2026-109619")
	}

	if !res.PHP {
		if fp.Error != "" {

			res.Error = "unreachable: " + fp.Error
		} else {
			res.Evidence = append(res.Evidence,
				"target does not appear to be PHP (no PHP headers; PHP execution not observed)")
		}
		return res
	}


	vuln618, ev618 := s.check109618(tctx, checkTarget)
	res.Evidence = append(res.Evidence, ev618...)
	if vuln618 {
		res.CVEs = append(res.CVEs, "CVE-2026-109618")
	}

	res.Vulnerable = len(res.CVEs) > 0
	return res
}

func (s *Scanner) applyHeaders(req *http.Request) {
	if s.opts.UserAgent == "" {
		req.Header.Set("User-Agent", fingerprint.DefaultUA)
	} else {
		req.Header.Set("User-Agent", s.opts.UserAgent)
	}
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Cache-Control", "no-cache")
	for k, vals := range s.opts.ExtraHeaders {
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}
}


func (s *Scanner) doWithRetry(ctx context.Context, req *http.Request) (*http.Response, error) {
	attempts := s.opts.Retries + 1
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			if err := rewind(req); err != nil {
				return nil, err
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(200*i) * time.Millisecond):
			}
		}
		resp, err := s.client.Do(req)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if isPermanentErr(err) {
			return nil, err
		}
	}
	return nil, lastErr
}

func rewind(req *http.Request) error {
	if req.Body == nil || req.GetBody == nil {
		return nil
	}
	b, err := req.GetBody()
	if err != nil {
		return err
	}
	req.Body = b
	return nil
}

func isPermanentErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	return strings.Contains(err.Error(), "Client.Timeout")
}

func isCtxErr(err error) bool {
	return isPermanentErr(err)
}


func readAndClose(resp *http.Response, readLimit, drainLimit int64) string {
	if resp == nil || resp.Body == nil {
		return ""
	}
	var b []byte
	if readLimit > 0 {
		b, _ = io.ReadAll(io.LimitReader(resp.Body, readLimit))
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, drainLimit))
	_ = resp.Body.Close()
	return string(b)
}

func addQueryParam(rawurl, k, v string) string {
	u, err := url.Parse(rawurl)
	if err != nil {
		return rawurl
	}
	q := u.Query()
	q.Set(k, v)
	u.RawQuery = q.Encode()
	return u.String()
}
