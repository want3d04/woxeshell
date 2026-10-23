package scanner

import (
	"context"
	"io"
	"net/http"
	"strings"

	"woxeshell/internal/payload"
)

func (s *Scanner) check109619(ctx context.Context, c *http.Client, target string) (bool, []string) {
	mA, bodyA := payload.NewMarker()
	mB, bodyB := payload.NewMarker()

	reqA, err := http.NewRequestWithContext(ctx, "POST", target, strings.NewReader(bodyA))
	if err != nil {
		return false, nil
	}
	s.applyHeaders(reqA)
	reqA.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	respA, err := s.doWithRetry(ctx, c, reqA)
	if err != nil {
		return false, nil
	}
	textA, _ := io.ReadAll(io.LimitReader(respA.Body, 128*1024))
	respA.Body.Close()

	if !strings.Contains(string(textA), payload.SuccessCheck(mA)) {
		return false, nil
	}

	reqB, err := http.NewRequestWithContext(ctx, "POST", target, strings.NewReader(bodyB))
	if err != nil {
		return false, nil
	}
	s.applyHeaders(reqB)
	reqB.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	respB, err := s.doWithRetry(ctx, c, reqB)
	if err != nil {
		return false, nil
	}
	defer respB.Body.Close()
	textB, _ := io.ReadAll(io.LimitReader(respB.Body, 128*1024))
	sB := string(textB)

	var ev []string
	if !strings.Contains(sB, payload.SuccessCheck(mB)) {
		return false, ev
	}
	if strings.Contains(sB, payload.SuccessCheck(mA)) {
		ev = append(ev,
			"109619: marker from request A leaked into response B",
			"109619: stale request-owned global state observed on same worker",
		)
		return true, ev
	}
	return false, ev
}