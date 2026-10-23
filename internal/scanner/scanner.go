package scanner

import (
	"context"
	"net/http"
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
}

type Scanner struct {
	opts Options
	sem  chan struct{}
}

func New(o Options) *Scanner {
	if o.Concurrency <= 0 {
		o.Concurrency = 10
	}
	if o.Timeout <= 0 {
		o.Timeout = 15 * time.Second
	}
	return &Scanner{opts: o, sem: make(chan struct{}, o.Concurrency)}
}

func (s *Scanner) Run(ctx context.Context, targets []string) {
	var wg sync.WaitGroup
	results := make(chan model.Result, s.opts.Concurrency*2)

	go func() {
		for r := range results {
			s.opts.Reporter.Report(r)
		}
	}()

	var tick *time.Ticker
	if s.opts.RatePerSec > 0 {
		interval := time.Second / time.Duration(s.opts.RatePerSec)
		if interval <= 0 {
			interval = time.Nanosecond
		}
		tick = time.NewTicker(interval)
		defer tick.Stop()
	}

loop:
	for _, t := range targets {
		select {
		case <-ctx.Done():
			break loop
		case s.sem <- struct{}{}:
		}
		if tick != nil {
			select {
			case <-tick.C:
			case <-ctx.Done():
				<-s.sem
				break loop
			}
		}
		wg.Add(1)
		go func(t string) {
			defer wg.Done()
			defer func() { <-s.sem }()
			res := s.probe(ctx, t)
			select {
			case results <- res:
			case <-ctx.Done():
			}
		}(t)
	}

	wg.Wait()
	close(results)
}

func (s *Scanner) probe(ctx context.Context, target string) model.Result {
	c := buildClient(s.opts)
	res := model.Result{Target: target}

	tctx, cancel := fingerprint.SetDeadline(ctx, s.opts.Timeout*2)
	defer cancel()

	if !s.opts.SkipFinger {
		fp := fingerprint.Detect(tctx, c, target, s.opts.UserAgent)
		res.PHP = fp.IsPHP
		res.Version = fp.Version
		if !fp.IsPHP {
			return res
		}
		if fp.Version != "" && !fingerprint.IsVersionVulnerable(fp.Version, fingerprint.DefaultFixed()) {
			res.Evidence = append(res.Evidence, "version "+fp.Version+" appears patched")
			return res
		}
	}

	if ok, ev := s.check109619(tctx, c, target); ok {
		res.CVEs = append(res.CVEs, "CVE-2026-109619")
		res.Evidence = append(res.Evidence, ev...)
	}

	if ok, ev := s.check109618(tctx, c, target); ok {
		res.CVEs = append(res.CVEs, "CVE-2026-109618")
		res.Evidence = append(res.Evidence, ev...)
	}

	if len(res.CVEs) > 0 {
		res.Vulnerable = true
	}
	return res
}

func (s *Scanner) applyHeaders(req *http.Request) {
	if s.opts.UserAgent == "" {
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; woxeshell/1.0)")
	} else {
		req.Header.Set("User-Agent", s.opts.UserAgent)
	}
	req.Header.Set("Connection", "keep-alive")
	for k, vals := range s.opts.ExtraHeaders {
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}
}

func (s *Scanner) doWithRetry(ctx context.Context, c *http.Client, req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error
	attempts := s.opts.Retries + 1
	if attempts < 1 {
		attempts = 1
	}
	for i := 0; i < attempts; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		resp, err = c.Do(req)
		if err == nil {
			return resp, nil
		}
		time.Sleep(time.Duration(200*(i+1)) * time.Millisecond)
	}
	return resp, err
}