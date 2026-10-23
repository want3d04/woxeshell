package model

type Result struct {
	Target     string   `json:"target"`
	Vulnerable bool     `json:"vulnerable"`
	PHP        bool     `json:"php"`
	Version    string   `json:"version,omitempty"`
	CVEs       []string `json:"cves,omitempty"`
	Evidence   []string `json:"evidence,omitempty"`
	Error      string   `json:"error,omitempty"`
}