package report

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dmolina23/pqledger/internal/model"
	"github.com/dmolina23/pqledger/internal/scan"
)

func scanTree(t *testing.T) (*scan.Result, string) {
	t.Helper()
	root := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	body := base64.StdEncoding.EncodeToString(der)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.MkdirAll(filepath.Join(root, "msp", "keystore"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "msp", "keystore", "k_sk"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	src := "package x\nimport \"crypto/md5\"\nimport \"crypto/rsa\"\nvar _ = md5.New\nvar _ *rsa.PublicKey\n"
	if err := os.WriteFile(filepath.Join(root, "x.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := scan.Run(root, scan.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return res, body
}

// Private key material must never leak into any report format.
func TestNoKeyMaterialInAnyOutput(t *testing.T) {
	res, body := scanTree(t)
	var text, js, cb bytes.Buffer
	Text(&text, res, "test", TextOptions{MinSeverity: model.Info, Verbose: true})
	if err := JSON(&js, res, "test"); err != nil {
		t.Fatal(err)
	}
	if err := CBOM(&cb, res, "test"); err != nil {
		t.Fatal(err)
	}
	secret := body[:40]
	for name, out := range map[string]string{"text": text.String(), "json": js.String(), "cbom": cb.String()} {
		if strings.Contains(out, secret) || strings.Contains(out, "BEGIN PRIVATE KEY") {
			t.Errorf("%s output leaks private key material", name)
		}
	}
}

func TestCBOMStructure(t *testing.T) {
	res, _ := scanTree(t)
	var buf bytes.Buffer
	if err := CBOM(&buf, res, "1.2.3"); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		BOMFormat    string `json:"bomFormat"`
		SpecVersion  string `json:"specVersion"`
		SerialNumber string `json:"serialNumber"`
		Components   []struct {
			BOMRef           string `json:"bom-ref"`
			CryptoProperties struct {
				AssetType string `json:"assetType"`
			} `json:"cryptoProperties"`
		} `json:"components"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.BOMFormat != "CycloneDX" || doc.SpecVersion != "1.6" || !strings.HasPrefix(doc.SerialNumber, "urn:uuid:") {
		t.Errorf("bad CBOM header: %+v", doc)
	}
	refs := map[string]bool{}
	types := map[string]int{}
	for _, c := range doc.Components {
		if refs[c.BOMRef] {
			t.Errorf("duplicate bom-ref %s", c.BOMRef)
		}
		refs[c.BOMRef] = true
		types[c.CryptoProperties.AssetType]++
	}
	if types["algorithm"] < 3 || types["related-crypto-material"] != 1 {
		t.Errorf("unexpected component mix: %v", types)
	}
}

func TestVerdictAndEmptyOutputs(t *testing.T) {
	empty := &scan.Result{Root: "."}
	var buf bytes.Buffer
	if err := JSON(&buf, empty, "t"); err != nil || !strings.Contains(buf.String(), `"findings": []`) {
		t.Errorf("empty JSON should contain an empty findings array: %s (%v)", buf.String(), err)
	}
	buf.Reset()
	if err := CBOM(&buf, empty, "t"); err != nil || !strings.Contains(buf.String(), `"components": []`) {
		t.Errorf("empty CBOM should contain an empty components array: %s (%v)", buf.String(), err)
	}
	res, _ := scanTree(t)
	if v := Verdict(res.Findings); !strings.Contains(v, "quantum-vulnerable") {
		t.Errorf("verdict should flag quantum-vulnerable crypto, got %q", v)
	}
	if v := Verdict(nil); !strings.HasPrefix(v, "no quantum-vulnerable") {
		t.Errorf("verdict for no findings, got %q", v)
	}
}
