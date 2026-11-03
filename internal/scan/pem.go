package scan

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/dmolina23/pqledger/internal/model"
	"github.com/dmolina23/pqledger/internal/rules"
)

// pqHorizonYear is a heuristic: a quantum-vulnerable certificate that stays
// valid beyond this year gets one severity level more. It follows the NIST
// IR 8547 draft timeline, which deprecates RSA/ECC around 2030.
const pqHorizonYear = 2030

// PEM blocks are matched with a regexp (instead of encoding/pem) so that they
// can also be found inside JSON wallets and connection profiles, where the
// newlines are escaped as the two characters `\n`.
var pemRe = regexp.MustCompile(`(?s)-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END ([A-Z0-9 ]+)-----`)

var bodyCleaner = strings.NewReplacer(`\r`, "", `\n`, "", "\r", "", "\n", "", " ", "", "\t", "")

func scanPEM(rel string, data []byte, emit emitFn) {
	if !bytes.Contains(data, []byte("-----BEGIN")) {
		return
	}
	ctx := fabricContext(rel)
	text := string(data)
	for _, m := range pemRe.FindAllStringSubmatchIndex(text, -1) {
		typ := text[m[2]:m[3]]
		if typ != text[m[6]:m[7]] {
			continue
		}
		body := text[m[4]:m[5]]
		line := 1 + strings.Count(text[:m[0]], "\n")

		switch {
		case typ == "CERTIFICATE":
			if der, ok := decodeBody(body); ok {
				certFinding(rel, line, ctx, der, emit)
			}
		case strings.HasSuffix(typ, "PRIVATE KEY"):
			if typ == "ENCRYPTED PRIVATE KEY" || strings.Contains(body, "ENCRYPTED") {
				f := newFinding("private-key", model.CatPrivateKey, "pem", rel, line, "unknown", "", "unknown",
					"Encrypted private key present; its algorithm cannot be determined without the passphrase")
				f.Context = ctx
				emit(f)
				continue
			}
			if der, ok := decodeBody(body); ok {
				keyFinding(rel, line, ctx, typ, der, emit)
			}
		case typ == "PUBLIC KEY":
			if der, ok := decodeBody(body); ok {
				if pub, err := x509.ParsePKIXPublicKey(der); err == nil {
					alg, param := pubKeyInfo(pub, x509.UnknownPublicKeyAlgorithm)
					f := newFinding("public-key", model.CatPublicKey, "pem", rel, line, alg, param, "signature", "Standalone public key")
					f.Context = ctx
					emit(f)
				}
			}
		}
	}
}

func decodeBody(body string) ([]byte, bool) {
	der, err := base64.StdEncoding.DecodeString(bodyCleaner.Replace(body))
	return der, err == nil
}

func pubKeyInfo(pub any, algo x509.PublicKeyAlgorithm) (alg, param string) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return "RSA", strconv.Itoa(k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA", rules.NormalizeCurve(k.Curve.Params().Name)
	case ed25519.PublicKey:
		return "EdDSA", "Ed25519"
	case *ecdh.PublicKey:
		return "X25519", "Curve25519"
	}
	if algo == x509.DSA {
		return "DSA", ""
	}
	return "unknown", ""
}

func certFinding(rel string, line int, ctx string, der []byte, emit emitFn) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return
	}
	alg, param := pubKeyInfo(cert.PublicKey, cert.PublicKeyAlgorithm)
	sum := sha256.Sum256(cert.Raw)
	info := &model.CertInfo{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		NotBefore:          cert.NotBefore.UTC(),
		NotAfter:           cert.NotAfter.UTC(),
		IsCA:               cert.IsCA,
		SHA256:             hex.EncodeToString(sum[:]),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
	}
	kind := "end-entity"
	if cert.IsCA {
		kind = "CA"
	}
	detail := fmt.Sprintf("%s certificate %q, valid until %s", kind, cert.Subject.String(), cert.NotAfter.UTC().Format("2006-01-02"))

	f := newFinding("cert-public-key", model.CatCertificate, "x509", rel, line, alg, param, "signature", detail)
	if f.Class == model.QuantumVulnerable && cert.NotAfter.Year() > pqHorizonYear {
		f.Severity = f.Severity.Bump()
		f.Detail += fmt.Sprintf(" - outlives the %d deprecation horizon", pqHorizonYear)
	}
	f.Context, f.Cert = ctx, info
	emit(f)

	sig := strings.ToUpper(cert.SignatureAlgorithm.String())
	for _, weak := range []struct{ needle, alg string }{{"MD5", "MD5"}, {"SHA1", "SHA-1"}} {
		if strings.Contains(sig, weak.needle) {
			wf := newFinding("cert-weak-signature-hash", model.CatCertificate, "x509", rel, line, weak.alg, "", "hash",
				"Certificate signed with "+cert.SignatureAlgorithm.String())
			wf.Context, wf.Cert = ctx, info
			emit(wf)
		}
	}
}

func keyFinding(rel string, line int, ctx, typ string, der []byte, emit emitFn) {
	var (
		key any
		err error
	)
	switch typ {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(der)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(der)
	default:
		key, err = x509.ParsePKCS8PrivateKey(der)
	}
	if err != nil {
		return
	}
	var alg, param, prim string
	switch k := key.(type) {
	case *rsa.PrivateKey:
		alg, param, prim = "RSA", strconv.Itoa(k.N.BitLen()), "unknown"
	case *ecdsa.PrivateKey:
		alg, param, prim = "ECDSA", rules.NormalizeCurve(k.Curve.Params().Name), "signature"
	case ed25519.PrivateKey:
		alg, param, prim = "EdDSA", "Ed25519", "signature"
	case *ecdh.PrivateKey:
		alg, param, prim = "X25519", "Curve25519", "key-agree"
	default:
		return
	}
	// Key material is deliberately never copied into the finding.
	f := newFinding("private-key", model.CatPrivateKey, "pem", rel, line, alg, param, prim,
		"Private key present in the scanned tree (key material is never printed); make sure it is not committed to version control")
	f.Context = ctx
	emit(f)
}
