package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"woxeshell/internal/model"
)

var markerRe = regexp.MustCompile(`<\?php echo '([A-Za-z0-9_]+)'`)

func testOptions() Options {
	return Options{
		Concurrency:    4,
		Timeout:        3 * time.Second,
		Retries:        1,
		ProbeSizeBytes: 4 << 20, 
		Pairs:          3,
		Settle:         10 * time.Millisecond,
	}
}

func runProbe(t *testing.T, o Options, url string) model.Result {
	t.Helper()
	s := New(o)
	return s.probe(context.Background(), url)
}

func hasCVE(res model.Result, cve string) bool {
	for _, c := range res.CVEs {
		if c == cve {
			return true
		}
	}
	return false
}

func findEvidence(res model.Result, sub string) bool {
	for _, e := range res.Evidence {
		if strings.Contains(e, sub) {
			return true
		}
	}
	return false
}

func phpExecHandler(t *testing.T) http.HandlerFunc {
	var mu sync.Mutex
	stale := ""
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		m := markerRe.FindSubmatch(body)
		if m == nil {
			w.Write([]byte("static page"))
			return
		}

		out := string(m[1]) + "49"
		if strings.Contains(string(body), "json_encode") {
			mu.Lock()
			out += `|{"G":{"p2s":"` + stale + `"}}`
			mu.Unlock()
		}
		mu.Lock()
		stale = r.URL.Query().Get("p2s")
		mu.Unlock()
		w.Write([]byte(out))
	}
}

func Test109619LeakDetected(t *testing.T) {
	srv := httptest.NewServer(phpExecHandler(t))
	defer srv.Close()

	res := runProbe(t, testOptions(), srv.URL)
	if !res.Vulnerable || !hasCVE(res, "CVE-2026-109619") {
		t.Fatalf("expected CVE-2026-109619, got: %+v", res)
	}
	if !res.Exec {
		t.Fatalf("expected exec_observed=true")
	}
	if !findEvidence(res, "stale request-owned global state") {
		t.Fatalf("expected stale-state evidence, got: %v", res.Evidence)
	}
}

func TestStaticSiteSkipped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("plain static site"))
	}))
	defer srv.Close()

	res := runProbe(t, testOptions(), srv.URL)
	if res.Vulnerable || res.PHP || res.Exec {
		t.Fatalf("expected clean skip, got: %+v", res)
	}
	if res.Error != "" {
		t.Fatalf("reachable non-PHP target must not be an error: %s", res.Error)
	}
}

func TestPHPHeadersNoExec(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.3.10")
		w.Write([]byte("app page"))
	}))
	defer srv.Close()

	res := runProbe(t, testOptions(), srv.URL)
	if !res.PHP || res.Version != "8.3.10" {
		t.Fatalf("expected PHP fingerprint with version, got: %+v", res)
	}
	if res.Vulnerable {
		t.Fatalf("non-executing app must not be vulnerable: %+v", res)
	}
	if !findEvidence(res, "below the fixed release") {
		t.Fatalf("expected version-below-fixed evidence, got: %v", res.Evidence)
	}
}

func Test618OOMSignature(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.ContentLength > 1<<20 {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("PHP Fatal error: Allowed memory size of 134217728 bytes exhausted (tried to allocate 4194304 bytes)"))
			return
		}
		_ = body
		w.Header().Set("X-Powered-By", "PHP/8.3.10")
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	res := runProbe(t, testOptions(), srv.URL)
	if !res.Vulnerable || !hasCVE(res, "CVE-2026-109618") {
		t.Fatalf("expected CVE-2026-109618, got: %+v", res)
	}
	if !findEvidence(res, "memory/OOM signature") {
		t.Fatalf("expected OOM signature evidence, got: %v", res.Evidence)
	}
}

func Test618BodySizeRejectionIsNotVuln(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		if r.ContentLength > 1<<20 {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			w.Write([]byte("request entity too large"))
			return
		}
		w.Header().Set("X-Powered-By", "PHP/8.3.10")
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	res := runProbe(t, testOptions(), srv.URL)
	if res.Vulnerable {
		t.Fatalf("413 rejection must not be reported vulnerable: %+v", res)
	}
	if !findEvidence(res, "rejected oversized body") {
		t.Fatalf("expected rejection evidence, got: %v", res.Evidence)
	}
}

func Test618ResetThenRecoveryIsNotVuln(t *testing.T) {
	var mu sync.Mutex
	cutNext := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		mu.Lock()
		isBig := r.ContentLength > 1<<20
		cut := isBig || cutNext
		if isBig {
			cutNext = true 
		} else if cutNext {
			cutNext = false 
		}
		mu.Unlock()
		if cut {
			hj := w.(http.Hijacker)
			conn, _, _ := hj.Hijack()
			conn.Close()
			return
		}
		w.Header().Set("X-Powered-By", "PHP/8.3.10")
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	res := runProbe(t, testOptions(), srv.URL)
	if res.Vulnerable {
		t.Fatalf("recovery after reset must not be vulnerable: %+v", res)
	}
	if !findEvidence(res, "body-size rejection") {
		t.Fatalf("expected recovery evidence, got: %v", res.Evidence)
	}
}

func Test618WorkerDownAfterBig(t *testing.T) {
	var mu sync.Mutex
	broken := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		mu.Lock()
		br := broken
		if r.ContentLength > 1<<20 {
			broken = true
		}
		mu.Unlock()
		if br {
			hj := w.(http.Hijacker)
			conn, _, _ := hj.Hijack()
			conn.Close()
			return
		}
		w.Header().Set("X-Powered-By", "PHP/8.3.10")
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	o := testOptions()

	res := runProbe(t, o, srv.URL)
	if !res.Vulnerable || !hasCVE(res, "CVE-2026-109618") {
		t.Fatalf("expected CVE-2026-109618 for stuck worker, got: %+v", res)
	}
	if !findEvidence(res, "worker unresponsive") {
		t.Fatalf("expected unresponsive evidence, got: %v", res.Evidence)
	}
}

func Test618ServerHeaderRestart(t *testing.T) {
	var mu sync.Mutex
	replaced := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		if r.ContentLength > 1<<20 {
			mu.Lock()
			replaced = true 
			mu.Unlock()
			w.WriteHeader(200)
			return
		}
		mu.Lock()
		rep := replaced
		mu.Unlock()
		if rep {
			w.Header().Set("Server", "nginx")
		} else {
			w.Header().Set("Server", "Apache")
		}
		w.Header().Set("X-Powered-By", "PHP/8.3.10")
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	res := runProbe(t, testOptions(), srv.URL)
	if !res.Vulnerable || !hasCVE(res, "CVE-2026-109618") {
		t.Fatalf("expected restart indicator, got: %+v", res)
	}
	if !findEvidence(res, "Server header changed") {
		t.Fatalf("expected server-header evidence, got: %v", res.Evidence)
	}
}

func Test618ServerHeaderFlapNotVuln(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Server", fmt.Sprintf("worker-%d", time.Now().UnixNano()%1000))
		w.Header().Set("X-Powered-By", "PHP/8.3.10")
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	res := runProbe(t, testOptions(), srv.URL)
	if res.Vulnerable {
		t.Fatalf("flapping Server header must not be vulnerable: %+v", res)
	}
}

func TestPatchedVersionSkipsProbes(t *testing.T) {
	probeHits := 0
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		probeHits++
		mu.Unlock()
		io.Copy(io.Discard, r.Body)
		w.Header().Set("X-Powered-By", "PHP/8.3.36")
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	res := runProbe(t, testOptions(), srv.URL)
	if res.Vulnerable {
		t.Fatalf("patched version must not be vulnerable: %+v", res)
	}
	if probeHits > 2 {
		t.Fatalf("patched version must skip active probes, got %d requests", probeHits)
	}
	if !findEvidence(res, "skipping active probes") {
		t.Fatalf("expected skip evidence, got: %v", res.Evidence)
	}
}

func TestUnknownVersionBranchStillScans(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("X-Powered-By", "PHP/7.4.33")
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	res := runProbe(t, testOptions(), srv.URL)
	if !findEvidence(res, "no official fix release") {
		t.Fatalf("expected unknown-branch evidence, got: %v", res.Evidence)
	}
	if res.PHP && res.Vulnerable {
		t.Fatalf("non-executing app must not be vulnerable: %+v", res)
	}
}

func TestUnreachableTargetIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() 

	res := runProbe(t, testOptions(), url)
	if res.Error == "" {
		t.Fatalf("expected error result for unreachable target, got: %+v", res)
	}
	if res.Vulnerable {
		t.Fatalf("unreachable target must not be vulnerable")
	}
}

func TestRateLimiterDoesNotDeadlock(t *testing.T) {
	srv := httptest.NewServer(phpExecHandler(t))
	defer srv.Close()

	targets := []string{srv.URL, srv.URL, srv.URL, srv.URL}
	rep := &fakeReporter{}
	o := testOptions()
	o.Reporter = rep
	o.Concurrency = 1
	o.RatePerSec = 50 
	s := New(o)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s.Run(ctx, targets)
	if rep.count != len(targets) {
		t.Fatalf("expected %d results, got %d", len(targets), rep.count)
	}
}

func TestPanicInProbeIsRecovered(t *testing.T) {
	rep := &fakeReporter{}
	o := testOptions()
	o.Reporter = rep
	s := &Scanner{opts: o, client: nil, sem: make(chan struct{}, 1)}
	s.Run(context.Background(), []string{"http://127.0.0.1:1"})
	if rep.count != 1 {
		t.Fatalf("expected 1 recovered result, got %d", rep.count)
	}
}

func TestRedirectTargetStillScanned(t *testing.T) {
	var mu sync.Mutex
	stale := ""
	mux := http.NewServeMux()
	mux.HandleFunc("/app/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		m := markerRe.FindSubmatch(body)
		if m == nil {
			if r.Method == http.MethodGet {
				w.Header().Set("X-Powered-By", "PHP/8.3.10")
				w.Write([]byte("app page"))
				return
			}
			w.Write([]byte("static"))
			return
		}
		out := string(m[1]) + "49"
		mu.Lock()
		if strings.Contains(string(body), "json_encode") {
			out += `|{"G":{"p2s":"` + stale + `"}}`
		}
		stale = r.URL.Query().Get("p2s")
		mu.Unlock()
		w.Write([]byte(out))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/app/", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := runProbe(t, testOptions(), srv.URL)
	if !res.Vulnerable || !hasCVE(res, "CVE-2026-109619") {
		t.Fatalf("expected redirect target to be scanned and vulnerable, got: %+v", res)
	}
	if !findEvidence(res, "active checks redirected to") {
		t.Fatalf("expected redirect evidence, got: %v", res.Evidence)
	}
}

type fakeReporter struct{ count int }

func (f *fakeReporter) Report(r model.Result) { f.count++ }
func (f *fakeReporter) Flush()                {}
func (f *fakeReporter) CountVulnerable() int  { return 0 }
func (f *fakeReporter) CountScanned() int     { return f.count }
func (f *fakeReporter) CountErrors() int      { return 0 }
