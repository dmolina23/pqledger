package scan

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dmolina23/pqledger/internal/model"
)

func write(t *testing.T, root, rel string, data []byte) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func selfSignedCert(t *testing.T, key crypto.Signer, cn string, notAfter time.Time) []byte {
	t.Helper()
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func mustScan(t *testing.T, root string, opt Options) *Result {
	t.Helper()
	res, err := Run(root, opt)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// find returns the findings that match all non-empty criteria.
func find(res *Result, cat model.Category, alg, param string) []model.Finding {
	var out []model.Finding
	for _, f := range res.Findings {
		if (cat == "" || f.Category == cat) && (alg == "" || f.Algorithm == alg) && (param == "" || f.Parameter == param) {
			out = append(out, f)
		}
	}
	return out
}

func TestCertificatesAndKeys(t *testing.T) {
	root := t.TempDir()
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	write(t, root, "msp/signcerts/peer-cert.pem", selfSignedCert(t, ecKey, "peer0", time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)))
	write(t, root, "legacy/short.pem", selfSignedCert(t, rsaKey, "legacy", time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC)))
	keyDER, _ := x509.MarshalPKCS8PrivateKey(ecKey)
	write(t, root, "msp/keystore/abc_sk", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))

	res := mustScan(t, root, Options{})

	long := find(res, model.CatCertificate, "ECDSA", "P-256")
	if len(long) != 1 {
		t.Fatalf("want 1 ECDSA P-256 certificate finding, got %d", len(long))
	}
	if long[0].Severity != model.Critical {
		t.Errorf("certificate valid until 2040 should be bumped to critical, got %s", long[0].Severity)
	}
	if long[0].Context != "hyperledger-fabric" {
		t.Errorf("MSP path should set the Fabric context, got %q", long[0].Context)
	}
	if long[0].Class != model.QuantumVulnerable {
		t.Errorf("unexpected class %s", long[0].Class)
	}

	short := find(res, model.CatCertificate, "RSA", "2048")
	if len(short) != 1 || short[0].Severity != model.High {
		t.Fatalf("RSA-2048 certificate expiring in 2028 should be high, got %+v", short)
	}

	keys := find(res, model.CatPrivateKey, "ECDSA", "P-256")
	if len(keys) != 1 {
		t.Fatalf("want 1 private key finding (keystore/_sk file), got %d", len(keys))
	}
}

func TestEncryptedKeyIsReportedWithoutParsing(t *testing.T) {
	root := t.TempDir()
	write(t, root, "id.key", []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n"))
	res := mustScan(t, root, Options{})
	got := find(res, model.CatPrivateKey, "unknown", "")
	if len(got) != 1 || got[0].Class != model.Unknown {
		t.Fatalf("encrypted key should be one unknown finding, got %+v", res.Findings)
	}
}

func TestEmbeddedPEMInJSONConnectionProfile(t *testing.T) {
	root := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	cert := selfSignedCert(t, key, "ca.org1", time.Date(2032, 1, 1, 0, 0, 0, 0, time.UTC))
	profile, _ := json.Marshal(map[string]any{"peers": map[string]any{"peer0": map[string]any{"tlsCACerts": map[string]any{"pem": string(cert)}}}})
	write(t, root, "connection-org1.json", profile)

	res := mustScan(t, root, Options{})
	if len(find(res, model.CatCertificate, "ECDSA", "P-384")) != 1 {
		t.Fatalf("certificate embedded in JSON was not found: %+v", res.Findings)
	}
}

func TestGoSource(t *testing.T) {
	root := t.TempDir()
	write(t, root, "cc/main.go", []byte(`package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

var _ contractapi.Contract

func f() {
	ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsa.GenerateKey(rand.Reader, 1024)
	sha1.New()
	sha256.Sum256(nil)
}

var _ *rsa.PublicKey
`))
	write(t, root, "cc/main_test.go", []byte("package main\nimport \"crypto/md5\"\nvar _ = md5.New\n"))

	res := mustScan(t, root, Options{})

	if got := find(res, model.CatSource, "ECDSA", "P-256"); len(got) != 1 {
		t.Errorf("want 1 ECDSA P-256 finding, got %d", len(got))
	}
	if got := find(res, model.CatSource, "ECC", ""); len(got) != 0 {
		t.Errorf("the elliptic curve finding should be merged into ECDSA, got %d", len(got))
	}
	rsa1024 := find(res, model.CatSource, "RSA", "1024")
	if len(rsa1024) != 1 || rsa1024[0].Severity != model.Critical {
		t.Errorf("RSA-1024 should be one critical finding, got %+v", rsa1024)
	}
	if got := find(res, model.CatSource, "SHA-1", ""); len(got) != 1 || got[0].Class != model.ClassicallyBroken {
		t.Errorf("SHA-1 not reported as classically broken: %+v", got)
	}
	if got := find(res, model.CatSource, "SHA-256", ""); len(got) != 1 || got[0].Severity != model.Info {
		t.Errorf("SHA-256 should be an info finding: %+v", got)
	}
	if got := find(res, model.CatSource, "MD5", ""); len(got) != 0 {
		t.Errorf("_test.go files must be skipped, got %+v", got)
	}
	for _, f := range res.Findings {
		if f.Context != "hyperledger-fabric" {
			t.Errorf("fabric import should set context on %s:%d", f.Location, f.Line)
		}
	}
}

func TestGoThirdPartyAndPostQuantumImports(t *testing.T) {
	root := t.TempDir()
	write(t, root, "main.go", []byte(`package main

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

var _ = btcec.S256
var _ = mlkem768.Scheme
`))
	res := mustScan(t, root, Options{})
	if got := find(res, model.CatSource, "ECDSA", "secp256k1"); len(got) != 1 || got[0].Context != "bitcoin" {
		t.Errorf("btcec import not detected: %+v", got)
	}
	got := find(res, model.CatSource, "ML-KEM", "768")
	if len(got) != 1 || got[0].Class != model.QuantumSafe || got[0].NISTLevel == nil || *got[0].NISTLevel != 3 {
		t.Errorf("ML-KEM-768 should be quantum-safe with NIST level 3: %+v", got)
	}
}

func TestJava(t *testing.T) {
	root := t.TempDir()
	write(t, root, "A.java", []byte(`import org.hyperledger.fabric.contract.ContractInterface;
class A {
  void f() throws Exception {
    MessageDigest.getInstance("MD5");
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(1024);
    Signature.getInstance("SHA1withECDSA");
    KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
    ec.initialize(new ECGenParameterSpec("secp256r1"));
    Cipher.getInstance("AES/GCM/NoPadding");
  }
}
`))
	res := mustScan(t, root, Options{})
	if len(find(res, model.CatSource, "MD5", "")) != 1 {
		t.Errorf("MD5 not found")
	}
	if got := find(res, model.CatSource, "RSA", "1024"); len(got) != 1 || got[0].Severity != model.Critical {
		t.Errorf("RSA-1024 not found: %+v", got)
	}
	if len(find(res, model.CatSource, "ECDSA", "")) != 1 || len(find(res, model.CatSource, "SHA-1", "")) != 1 {
		t.Errorf("SHA1withECDSA should yield ECDSA and SHA-1 findings")
	}
	if len(find(res, model.CatSource, "ECC", "P-256")) != 1 {
		t.Errorf("EC key pair with secp256r1 should be ECC P-256: %+v", res.Findings)
	}
	if len(find(res, model.CatSource, "AES", "")) != 1 {
		t.Errorf("AES not found")
	}
}

func TestJavaScript(t *testing.T) {
	root := t.TempDir()
	write(t, root, "cc.js", []byte(`const { Contract } = require('fabric-contract-api');
const crypto = require('crypto');
crypto.generateKeyPairSync('rsa', {
  modulusLength: 4096,
});
crypto.createHash('md5');
crypto.createCipheriv('des-ede3-cbc', k, iv);
crypto.createCipheriv('aes-128-cbc', k, iv);
new EC('secp256k1');
`))
	res := mustScan(t, root, Options{})
	if got := find(res, model.CatSource, "RSA", "4096"); len(got) != 1 || got[0].Severity != model.High {
		t.Errorf("RSA-4096 should be one high finding: %+v", got)
	}
	if len(find(res, model.CatSource, "MD5", "")) != 1 || len(find(res, model.CatSource, "3DES", "")) != 1 {
		t.Errorf("MD5 / 3DES missing: %+v", res.Findings)
	}
	if got := find(res, model.CatSource, "AES", "128"); len(got) != 1 || got[0].Class != model.QuantumWeakened {
		t.Errorf("AES-128 should be quantum-weakened: %+v", got)
	}
	if len(find(res, model.CatSource, "ECC", "secp256k1")) != 1 {
		t.Errorf("elliptic secp256k1 missing")
	}
	for _, f := range res.Findings {
		if f.Context != "hyperledger-fabric" {
			t.Errorf("fabric-contract-api should set context")
		}
	}
}

func TestFabricYAML(t *testing.T) {
	root := t.TempDir()
	write(t, root, "core.yaml", []byte(`peer:
  BCCSP:
    Default: SW
    SW:
      Hash: SHA2
      Security: 384
    PKCS11:
      Hash: SHA2
      Security: 256
`))
	write(t, root, "ca.yaml", []byte(`csr:
  keyrequest:
    algo: rsa
    size: 1024   # legacy
`))
	write(t, root, "hsm.yaml", []byte("BCCSP:\n  Default: PKCS11\n"))

	res := mustScan(t, root, Options{})
	if got := find(res, model.CatConfig, "ECDSA", "P-384"); len(got) != 1 {
		t.Errorf("BCCSP software provider with Security 384 should be ECDSA P-384: %+v", res.Findings)
	}
	if got := find(res, model.CatConfig, "SHA-384", ""); len(got) != 1 {
		t.Errorf("BCCSP SHA2 + 384 should be SHA-384: %+v", res.Findings)
	}
	if got := find(res, model.CatConfig, "RSA", "1024"); len(got) != 1 || got[0].Severity != model.Critical {
		t.Errorf("Fabric CA RSA-1024 key request should be critical: %+v", got)
	}
	if got := find(res, model.CatConfig, "PKCS11-HSM", ""); len(got) != 1 {
		t.Errorf("PKCS11 provider should be flagged for manual review")
	}
}

func TestVendorAndGitAreSkipped(t *testing.T) {
	root := t.TempDir()
	src := []byte("package x\nimport \"crypto/md5\"\nvar _ = md5.New\n")
	write(t, root, "vendor/dep/x.go", src)
	write(t, root, ".git/hooks/x.go", src)
	write(t, root, "node_modules/p/x.go", src)

	if res := mustScan(t, root, Options{}); len(res.Findings) != 0 {
		t.Fatalf("vendor/.git/node_modules should be skipped, got %+v", res.Findings)
	}
	if res := mustScan(t, root, Options{IncludeVendor: true}); len(find(res, model.CatSource, "MD5", "")) != 1 {
		t.Fatalf("IncludeVendor should scan vendor/")
	}
}

func TestSingleFileAndMissingPath(t *testing.T) {
	root := t.TempDir()
	write(t, root, "a.go", []byte("package x\nimport \"crypto/md5\"\nvar _ = md5.New\n"))
	res := mustScan(t, filepath.Join(root, "a.go"), Options{})
	if len(res.Findings) != 1 || res.FilesScanned != 1 {
		t.Fatalf("single-file scan failed: %+v", res)
	}
	if _, err := Run(filepath.Join(root, "missing"), Options{}); err == nil {
		t.Fatal("scanning a missing path should fail")
	}
}
