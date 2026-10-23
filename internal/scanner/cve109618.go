package scanner

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"woxeshell/internal/payload"
)

func (s *Scanner) check109618(ctx context.Context, c *http.Client, target string) (bool, []string) {
	var ev []string

	baseReq, err := http.NewRequestWithContext(ctx, "POST", target, strings.NewReader("<?php echo 'ok'; ?>"))
	if err != nil {
		return false, nil
	}
	s.applyHeaders(baseReq)
	baseReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	baseResp, err := s.doWithRetry(ctx, c, baseReq)
	if err != nil {
		return false, nil
	}
	io.Copy(io.Discard, baseResp.Body)
	baseResp.Body.Close()
	if baseResp.StatusCode >= 500 {
		return false, nil
	}
	baselineServer := baseResp.Header.Get("Server")

	const probeSize = 32 * 1024 * 1024
	big := payload.OOMProbePayload(probeSize)
	bigReq, err := http.NewRequestWithContext(ctx, "POST", target, strings.NewReader(string(big)))
	if err != nil {
		return false, nil
	}
	s.applyHeaders(bigReq)
	bigReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	bigResp, err := s.doWithRetry(ctx, c, bigReq)
	if err != nil {
		if isConnReset(err) {
			ev = append(ev, "109618: connection reset after oversized request")
			return true, ev
		}
		return false, nil
	}
	bigBody, _ := io.ReadAll(io.LimitReader(bigResp.Body, 16384))
	bigResp.Body.Close()

	time.Sleep(300 * time.Millisecond)

	postReq, err := http.NewRequestWithContext(ctx, "POST", target, strings.NewReader("<?php echo 'ok'; ?>"))
	if err != nil {
		return false, nil
	}
	s.applyHeaders(postReq)
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	postResp, err := s.doWithRetry(ctx, c, postReq)
	if err != nil {
		ev = append(ev, "109618: worker unresponsive after oversized request")
		return true, ev
	}
	defer postResp.Body.Close()

	if srv := postResp.Header.Get("Server"); srv != "" && baselineServer != "" && srv != baselineServer {
		ev = append(ev, "109618: Server header changed after oversized request")
		return true, ev
	}

	if bigResp.StatusCode >= 500 {
		low := strings.ToLower(string(bigBody))
		for _, sig := range []string{"fatal", "memory", "allocate", "out of memory", "oom"} {
			if strings.Contains(low, sig) {
				ev = append(ev, "109618: server returned 5xx with fatal/OOM signature after oversized request")
				return true, ev
			}
		}
	}
	return false, ev
}

func isConnReset(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	for _, sig := range []string{"connection reset", "broken pipe", "unexpected EOF", "EOF"} {
		if strings.Contains(s, sig) {
			return true
		}
	}
	return false
}