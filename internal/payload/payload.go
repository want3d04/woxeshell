package payload

import (
	"crypto/rand"
	"encoding/hex"
)

const MarkerPrefix = "P2S_"

func NewMarker() (marker string, body string) {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	marker = MarkerPrefix + hex.EncodeToString(b)
	body = "<?php echo '" + marker + "_' . (7*7); ?>"
	return
}

func SuccessCheck(marker string) string {
	return marker + "_49"
}

func RandomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func OOMProbePayload(sizeBytes int) []byte {
	buf := make([]byte, sizeBytes)
	for i := range buf {
		buf[i] = byte('a' + (i % 26))
	}
	return buf
}