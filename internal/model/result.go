package model

// Result is the per-target outcome. New fields (at, duration_ms,
// exec_observed, php_source) are additive and omitempty so old JSONL
// consumers keep working.
type Result struct {
	Target     string   `json:"target"`
	Vulnerable bool     `json:"vulnerable"`
	PHP        bool     `json:"php"`
	Version    string   `json:"version,omitempty"`
	CVEs       []string `json:"cves,omitempty"`
	Evidence   []string `json:"evidence,omitempty"`
	Error      string   `json:"error,omitempty"`
	// Exec reports that the target actually executed the PHP probe body
	// (the "php2shell" precondition), as opposed to merely exposing PHP
	// headers.
	Exec bool `json:"exec_observed,omitempty"`
	// PHPSource: "header" | "version-header" | "active-probe" | assumed
	PHPSource  string `json:"php_source,omitempty"`
	At         string `json:"at,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`
}
