package scanner

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"time"
)

func buildClient(o Options) *http.Client {
	transport := &http.Transport{
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: o.InsecureTLS,
		},
		ForceAttemptHTTP2: false,
	}
	if o.ProxyURL != "" {
		if u, err := url.Parse(o.ProxyURL); err == nil {
			transport.Proxy = http.ProxyURL(u)
		}
	}
	return &http.Client{
		Timeout:   o.Timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}