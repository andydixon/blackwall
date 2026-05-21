package service

import (
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"time"
)

// rsaSign produces an RSA-PKCS#1-v1.5 SHA-256 signature over the supplied
// pre-computed digest. SAML XML-DSig wants raw bytes, not a base64 form.
func rsaSign(key *rsa.PrivateKey, digest []byte) ([]byte, error) {
	return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
}

// newFlateReader returns a raw-DEFLATE reader for SAML's HTTP-Redirect
// binding payload. The HTTP-Redirect binding mandates raw-deflate (RFC 1951)
// not zlib (RFC 1950), so we use compress/flate, not compress/zlib.
func newFlateReader(b []byte) io.ReadCloser {
	return flate.NewReader(&byteReader{buf: b})
}

// byteReader is a tiny one-shot io.Reader over a byte slice — avoids
// importing bytes for one use site.
type byteReader struct {
	buf []byte
	pos int
}

func (r *byteReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.buf) {
		return 0, io.EOF
	}
	n := copy(p, r.buf[r.pos:])
	r.pos += n
	return n, nil
}

// x509Template returns a "good enough" self-signed certificate template the
// SAML metadata uses to advertise our signing key. SAML SPs only use this
// cert for signature verification of assertions/responses — never in TLS —
// so a non-CA template with a 10-year validity is fine.
func x509Template() *x509.Certificate {
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	return &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "blackwall-idp",
			Organization: []string{"BlackWall"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
}
