package scanner

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"woxeshell/internal/payload"
)

func (s *Scanner) check109618(ctx context.Context, target string) (bool, []string) {
	var ev []string

	baseResp, err := s.postSmall(ctx, target)
	if err != nil {
		return false, append(ev, "109618: baseline request failed: "+err.Error())
	}
	baseStatus := baseResp.StatusCode
	baseServer := baseResp.Header.Get("Server")
	readAndClose(baseResp, 8192, 8192)

	ctrl1Resp, err := s.postSmall(ctx, target)
	if err != nil {
		return false, append(ev, "109618: control request failed before probe: "+err.Error())
	}
	ctrl1Server := ctrl1Resp.Header.Get("Server")
	readAndClose(ctrl1Resp, 8192, 8192)

	size := s.opts.ProbeSizeBytes
	bigReq, err := http.NewRequestWithContext(ctx, "POST",
		addQueryParam(target, "cb", payload.RandomHex(6)),
		payload.NewPatternReader(size))
	if err != nil {
		return false, ev
	}
	s.applyHeaders(bigReq)
	bigReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	bigReq.ContentLength = size 

	bigResp, err := s.client.Do(bigReq)
	if err != nil {
		if isCtxErr(err) {

			return false, ev
		}
		ev = append(ev, fmt.Sprintf("109618: connection error during oversized request: %v", err))
		return s.confirmUnresponsive(ctx, target, ev)
	}
	bigBody := readAndClose(bigResp, 16<<10, 1<<20)

	switch sc := bigResp.StatusCode; {
	case sc == http.StatusRequestEntityTooLarge || sc == http.StatusBadRequest:
		ev = append(ev, fmt.Sprintf("109618: server rejected oversized body with HTTP %d; probe not delivered", sc))
		return false, ev
	case sc >= 500:
		low := strings.ToLower(bigBody)
		for _, sig := range []string{"fatal", "memory", "allocate", "out of memory", "oom", "exhausted"} {
			if strings.Contains(low, sig) {
				ev = append(ev, "109618: 5xx response with memory/OOM signature after oversized request")
				return true, ev
			}
		}
		ev = append(ev, fmt.Sprintf("109618: server returned HTTP %d after oversized request", sc))
	}

	time.Sleep(s.opts.Settle)

	ctrl2Server := ""
	var ctrl2Err error
	for attempt := 0; attempt < 2; attempt++ {
		resp, err := s.postSmall(ctx, target)
		if err == nil {
			ctrl2Server = resp.Header.Get("Server")
			readAndClose(resp, 8192, 8192)
			ctrl2Err = nil
			break
		}
		ctrl2Err = err
		if isCtxErr(err) {
			return false, ev
		}
		time.Sleep(500 * time.Millisecond)
	}
	if ctrl2Err != nil {
		ev = append(ev,
			fmt.Sprintf("109618: worker unresponsive after oversized request (baseline was HTTP %d)", baseStatus))
		return true, ev
	}

	if baseServer != "" && ctrl1Server == baseServer && ctrl2Server != "" && ctrl2Server != baseServer {
		ev = append(ev,
			fmt.Sprintf("109618: Server header changed after oversized request (%q -> %q); worker restart suspected",
				baseServer, ctrl2Server))
		return true, ev
	}

	return false, ev
}


func (s *Scanner) confirmUnresponsive(ctx context.Context, target string, ev []string) (bool, []string) {
	time.Sleep(s.opts.Settle)
	for attempt := 0; attempt < 2; attempt++ {
		resp, err := s.postSmall(ctx, target)
		if err == nil {
			readAndClose(resp, 8192, 8192)
			ev = append(ev,
				"109618: server recovered right after the oversized request; body-size rejection, not an OOM indicator")
			return false, ev
		}
		if isCtxErr(err) {
			return false, ev
		}
		time.Sleep(500 * time.Millisecond)
	}
	ev = append(ev, "109618: worker unresponsive after oversized request (control requests failed twice)")
	return true, ev
}

func (s *Scanner) postSmall(ctx context.Context, target string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "POST",
		addQueryParam(target, "cb", payload.RandomHex(6)),
		strings.NewReader("<?php echo 'ok'; ?>"))
	if err != nil {
		return nil, err
	}
	s.applyHeaders(req)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return s.doWithRetry(ctx, req)
}
