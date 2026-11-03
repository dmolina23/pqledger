package rules

import (
	"strings"
	"testing"

	"github.com/dmolina23/pqledger/internal/model"
)

func TestAssess(t *testing.T) {
	cases := []struct {
		alg, param, prim string
		class            model.Class
		sev              model.Severity
	}{
		{"RSA", "1024", "signature", model.QuantumVulnerable, model.Critical},
		{"RSA", "2048", "signature", model.QuantumVulnerable, model.High},
		{"RSA", "", "unknown", model.QuantumVulnerable, model.High},
		{"ECDSA", "P-256", "signature", model.QuantumVulnerable, model.High},
		{"X25519", "Curve25519", "key-agree", model.QuantumVulnerable, model.High},
		{"MD5", "", "hash", model.ClassicallyBroken, model.High},
		{"DES", "", "block-cipher", model.ClassicallyBroken, model.Critical},
		{"3DES", "", "block-cipher", model.ClassicallyBroken, model.Medium},
		{"AES", "128", "block-cipher", model.QuantumWeakened, model.Low},
		{"AES", "256", "block-cipher", model.QuantumSafe, model.Info},
		{"AES", "", "block-cipher", model.Unknown, model.Info},
		{"SHA-256", "", "hash", model.QuantumSafe, model.Info},
		{"ML-KEM", "768", "kem", model.QuantumSafe, model.Info},
		{"something-else", "", "", model.Unknown, model.Info},
	}
	for _, c := range cases {
		got := Assess(c.alg, c.param, c.prim)
		if got.Class != c.class || got.Severity != c.sev {
			t.Errorf("Assess(%s,%s): got %s/%s, want %s/%s", c.alg, c.param, got.Class, got.Severity, c.class, c.sev)
		}
	}
}

func TestRecommendationsMatchPrimitive(t *testing.T) {
	if r := Assess("ECDSA", "P-256", "signature").Recommendation; r == "" || r != sigRec {
		t.Errorf("signatures should point to ML-DSA/SLH-DSA, got %q", r)
	}
	if r := Assess("ECDH", "P-256", "key-agree").Recommendation; r != kemRec {
		t.Errorf("key agreement should point to ML-KEM, got %q", r)
	}
	if r := Assess("RSA", "2048", "unknown").Recommendation; r != bothRec {
		t.Errorf("unknown primitive should give the combined advice, got %q", r)
	}
	if r := Assess("ML-DSA", "65", "signature").Recommendation; r != "" {
		t.Errorf("quantum-safe algorithms need no recommendation, got %q", r)
	}
}

func TestWeakRSAGetsReplaceNowAdvice(t *testing.T) {
	r := Assess("RSA", "1024", "signature").Recommendation
	if !strings.HasPrefix(r, "Key size is already weak") || !strings.HasSuffix(r, sigRec) {
		t.Errorf("RSA-1024 advice should say replace now and still point to PQC, got %q", r)
	}
}

func TestNISTLevels(t *testing.T) {
	a := Assess("ML-DSA", "65", "signature")
	if !a.HasNISTLevel || a.NISTLevel != 3 {
		t.Errorf("ML-DSA-65 should be NIST level 3, got %+v", a)
	}
	if v := Assess("RSA", "2048", ""); !v.HasNISTLevel || v.NISTLevel != 0 {
		t.Errorf("vulnerable algorithms are NIST quantum level 0, got %+v", v)
	}
}

func TestNormalizers(t *testing.T) {
	for in, want := range map[string]string{"secp256r1": "P-256", "prime256v1": "P-256", "P-384": "P-384", "SECP256K1": "secp256k1", "weird": "weird"} {
		if got := NormalizeCurve(in); got != want {
			t.Errorf("NormalizeCurve(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"SHA-1": "SHA-1", "sha256": "SHA-256", "SHA512/256": "SHA-512", "SHA3-256": "SHA-3", "MD5": "MD5"} {
		got, ok := NormalizeHash(in)
		if !ok || got != want {
			t.Errorf("NormalizeHash(%q) = %q,%v, want %q", in, got, ok, want)
		}
	}
	if _, ok := NormalizeHash("blake2"); ok {
		t.Error("unknown hash should not normalize")
	}
}
