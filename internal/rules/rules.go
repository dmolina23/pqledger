// Package rules holds the algorithm knowledge base: how each algorithm is
// classified against quantum attacks, how severe a finding is, and what to
// migrate to.
package rules

import (
	"strconv"
	"strings"

	"github.com/dmolina23/pqledger/internal/model"
)

// Assessment is the verdict for one algorithm and parameter combination.
type Assessment struct {
	Class          model.Class
	Severity       model.Severity
	Recommendation string
	NISTLevel      int
	HasNISTLevel   bool
}

const (
	sigRec  = "Plan migration to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205); use hybrid or dual signatures where the platform supports them."
	kemRec  = "Plan migration to ML-KEM (FIPS 203), preferably hybrid with X25519/ECDH during the transition."
	bothRec = "Plan migration: ML-DSA/SLH-DSA (FIPS 204/205) for signatures and ML-KEM (FIPS 203) for key establishment, hybrid during the transition."
)

// Assess classifies an algorithm. alg must be a canonical name (see the
// switch below); param is a key size in bits, a curve name or a parameter set
// number, and may be empty. primitive may be empty or "unknown".
func Assess(alg, param, primitive string) Assessment {
	a := Assessment{Class: model.Unknown, Severity: model.Info}
	bits, err := strconv.Atoi(param)
	hasBits := err == nil

	switch alg {
	case "RSA", "DH", "DSA":
		a.Class, a.Severity = model.QuantumVulnerable, model.High
		if hasBits && bits < 2048 {
			a.Severity = model.Critical
		}
		a.NISTLevel, a.HasNISTLevel = 0, true
	case "ECDSA", "ECDH", "ECC", "EdDSA", "X25519":
		a.Class, a.Severity = model.QuantumVulnerable, model.High
		a.NISTLevel, a.HasNISTLevel = 0, true
	case "MD5", "SHA-1":
		a.Class, a.Severity = model.ClassicallyBroken, model.High
		a.NISTLevel, a.HasNISTLevel = 0, true
	case "DES", "RC4":
		a.Class, a.Severity = model.ClassicallyBroken, model.Critical
		a.NISTLevel, a.HasNISTLevel = 0, true
	case "3DES":
		a.Class, a.Severity = model.ClassicallyBroken, model.Medium
		a.NISTLevel, a.HasNISTLevel = 0, true
	case "AES":
		switch {
		case hasBits && bits < 256:
			a.Class, a.Severity = model.QuantumWeakened, model.Low
			a.NISTLevel, a.HasNISTLevel = 1, true
			if bits == 192 {
				a.NISTLevel = 3
			}
		case hasBits:
			a.Class, a.Severity = model.QuantumSafe, model.Info
			a.NISTLevel, a.HasNISTLevel = 5, true
		}
	case "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA-3":
		a.Class = model.QuantumSafe
	case "ML-KEM":
		a.Class = model.QuantumSafe
		a.NISTLevel, a.HasNISTLevel = lookup(param, map[string]int{"512": 1, "768": 3, "1024": 5})
	case "ML-DSA":
		a.Class = model.QuantumSafe
		a.NISTLevel, a.HasNISTLevel = lookup(param, map[string]int{"44": 2, "65": 3, "87": 5})
	case "SLH-DSA":
		a.Class = model.QuantumSafe
	}

	a.Recommendation = recommend(a.Class, alg, primitive, hasBits)
	if a.Severity == model.Critical && a.Class == model.QuantumVulnerable {
		a.Recommendation = "Key size is already weak classically (below 2048 bits): replace it now. " + a.Recommendation
	}
	return a
}

func lookup(k string, m map[string]int) (int, bool) {
	v, ok := m[k]
	return v, ok
}

func recommend(c model.Class, alg, primitive string, hasBits bool) string {
	switch c {
	case model.QuantumVulnerable:
		switch primitive {
		case "signature":
			return sigRec
		case "key-agree", "kem", "pke":
			return kemRec
		}
		return bothRec
	case model.ClassicallyBroken:
		switch alg {
		case "MD5", "SHA-1":
			return "Replace now with SHA-256 or stronger (SHA-384, SHA-3)."
		}
		return "Replace now with AES-256-GCM."
	case model.QuantumWeakened:
		return "Prefer 256-bit keys (AES-256) for long-term confidentiality."
	case model.Unknown:
		if alg == "AES" && !hasBits {
			return "Verify that the key size is 256 bits."
		}
		return "Verify the algorithm and parameters manually."
	}
	return ""
}

// NormalizeHash maps the many spellings of hash names to canonical names.
func NormalizeHash(s string) (string, bool) {
	k := strings.ToLower(strings.NewReplacer("-", "", "_", "", " ", "").Replace(s))
	switch {
	case k == "md5":
		return "MD5", true
	case k == "sha1":
		return "SHA-1", true
	case k == "sha224":
		return "SHA-224", true
	case k == "sha256":
		return "SHA-256", true
	case k == "sha384":
		return "SHA-384", true
	case k == "sha512" || strings.HasPrefix(k, "sha512"):
		return "SHA-512", true
	case strings.HasPrefix(k, "sha3"):
		return "SHA-3", true
	}
	return "", false
}

// NormalizeCurve maps curve aliases (secp256r1, prime256v1, p256...) to a
// canonical name. Unknown names are returned unchanged.
func NormalizeCurve(s string) string {
	k := strings.ToLower(strings.NewReplacer("-", "", "_", "").Replace(s))
	switch k {
	case "p224", "secp224r1":
		return "P-224"
	case "p256", "secp256r1", "prime256v1":
		return "P-256"
	case "p384", "secp384r1":
		return "P-384"
	case "p521", "secp521r1":
		return "P-521"
	case "secp256k1":
		return "secp256k1"
	case "ed25519":
		return "Ed25519"
	case "curve25519", "x25519":
		return "Curve25519"
	}
	return s
}
