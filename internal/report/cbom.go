package report

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/dmolina23/pqledger/internal/model"
	"github.com/dmolina23/pqledger/internal/scan"
)

// CBOM output follows CycloneDX 1.6: algorithms, certificates and related
// crypto material (keys) are cryptographic-asset components, and every place
// where an asset was seen is recorded as evidence.

type cbomProp struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type occurrence struct {
	Location          string `json:"location"`
	Line              int    `json:"line,omitempty"`
	AdditionalContext string `json:"additionalContext,omitempty"`
}

type evidence struct {
	Occurrences []occurrence `json:"occurrences"`
}

type algProps struct {
	Primitive                string `json:"primitive"`
	ParameterSetIdentifier   string `json:"parameterSetIdentifier,omitempty"`
	Curve                    string `json:"curve,omitempty"`
	NISTQuantumSecurityLevel *int   `json:"nistQuantumSecurityLevel,omitempty"`
}

type certProps struct {
	SubjectName       string `json:"subjectName"`
	IssuerName        string `json:"issuerName"`
	NotValidBefore    string `json:"notValidBefore"`
	NotValidAfter     string `json:"notValidAfter"`
	CertificateFormat string `json:"certificateFormat"`
}

type relatedProps struct {
	Type         string `json:"type"`
	AlgorithmRef string `json:"algorithmRef,omitempty"`
}

type cryptoProps struct {
	AssetType                       string        `json:"assetType"`
	AlgorithmProperties             *algProps     `json:"algorithmProperties,omitempty"`
	CertificateProperties           *certProps    `json:"certificateProperties,omitempty"`
	RelatedCryptoMaterialProperties *relatedProps `json:"relatedCryptoMaterialProperties,omitempty"`
}

type component struct {
	Type             string      `json:"type"`
	BOMRef           string      `json:"bom-ref"`
	Name             string      `json:"name"`
	CryptoProperties cryptoProps `json:"cryptoProperties"`
	Evidence         *evidence   `json:"evidence,omitempty"`
	Properties       []cbomProp  `json:"properties,omitempty"`
}

type toolComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type bom struct {
	BOMFormat    string `json:"bomFormat"`
	SpecVersion  string `json:"specVersion"`
	SerialNumber string `json:"serialNumber"`
	Version      int    `json:"version"`
	Metadata     struct {
		Timestamp string `json:"timestamp"`
		Tools     struct {
			Components []toolComponent `json:"components"`
		} `json:"tools"`
	} `json:"metadata"`
	Components []component `json:"components"`
}

var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

func slug(parts ...string) string {
	return strings.Trim(nonSlug.ReplaceAllString(strings.ToLower(strings.Join(parts, "-")), "-"), "-")
}

func algRef(f model.Finding) string {
	return "crypto/algorithm/" + slug(f.Algorithm, f.Parameter, f.Primitive)
}

func isCurveAlg(a string) bool {
	switch a {
	case "ECDSA", "ECDH", "ECC", "EdDSA", "X25519":
		return true
	}
	return false
}

// CBOM writes a CycloneDX 1.6 Cryptography Bill of Materials.
func CBOM(w io.Writer, res *scan.Result, version string) error {
	var b bom
	b.BOMFormat, b.SpecVersion, b.Version = "CycloneDX", "1.6", 1
	b.SerialNumber = "urn:uuid:" + newUUID()
	b.Metadata.Timestamp = time.Now().UTC().Format(time.RFC3339)
	b.Metadata.Tools.Components = []toolComponent{{Type: "application", Name: "pqledger", Version: version}}

	algs := map[string]*component{}
	algSeverity := map[string]model.Severity{}
	certs := map[string]*component{}
	var keys []component

	for _, f := range res.Findings {
		occ := occurrence{Location: f.Location, Line: f.Line, AdditionalContext: f.Detail}

		// Algorithm component (one per algorithm/parameter/primitive).
		ref := algRef(f)
		c := algs[ref]
		if c == nil {
			name := f.Algorithm
			if f.Parameter != "" {
				name += "-" + f.Parameter
			}
			ap := &algProps{Primitive: f.Primitive, NISTQuantumSecurityLevel: f.NISTLevel}
			if f.Parameter != "" {
				ap.ParameterSetIdentifier = f.Parameter
				if isCurveAlg(f.Algorithm) {
					ap.Curve = f.Parameter
				}
			}
			c = &component{
				Type: "cryptographic-asset", BOMRef: ref, Name: name,
				CryptoProperties: cryptoProps{AssetType: "algorithm", AlgorithmProperties: ap},
				Evidence:         &evidence{},
			}
			algs[ref] = c
		}
		c.Evidence.Occurrences = append(c.Evidence.Occurrences, occ)
		if f.Severity >= algSeverity[ref] {
			algSeverity[ref] = f.Severity
		}

		switch f.Category {
		case model.CatCertificate:
			if f.Cert == nil {
				break
			}
			cc := certs[f.Cert.SHA256]
			if cc == nil {
				cc = &component{
					Type: "cryptographic-asset", BOMRef: "crypto/certificate/" + f.Cert.SHA256[:16], Name: f.Cert.Subject,
					CryptoProperties: cryptoProps{AssetType: "certificate", CertificateProperties: &certProps{
						SubjectName:       f.Cert.Subject,
						IssuerName:        f.Cert.Issuer,
						NotValidBefore:    f.Cert.NotBefore.Format(time.RFC3339),
						NotValidAfter:     f.Cert.NotAfter.Format(time.RFC3339),
						CertificateFormat: "X.509",
					}},
					Evidence: &evidence{},
				}
				certs[f.Cert.SHA256] = cc
			}
			cc.Evidence.Occurrences = append(cc.Evidence.Occurrences, occ)
		case model.CatPrivateKey, model.CatPublicKey:
			kind, label := "private-key", "private key"
			if f.Category == model.CatPublicKey {
				kind, label = "public-key", "public key"
			}
			rp := &relatedProps{Type: kind}
			if f.Algorithm != "unknown" {
				rp.AlgorithmRef = ref
			}
			keys = append(keys, component{
				Type: "cryptographic-asset", BOMRef: fmt.Sprintf("crypto/key/%s-%d", slug(f.Location), f.Line),
				Name:             fmt.Sprintf("%s (%s)", label, strings.TrimSpace(f.Algorithm+" "+f.Parameter)),
				CryptoProperties: cryptoProps{AssetType: "related-crypto-material", RelatedCryptoMaterialProperties: rp},
				Evidence:         &evidence{Occurrences: []occurrence{{Location: f.Location, Line: f.Line}}},
			})
		}
	}

	for ref, c := range algs {
		class := model.Unknown
		for _, f := range res.Findings {
			if algRef(f) == ref {
				class = f.Class
				break
			}
		}
		c.Properties = []cbomProp{
			{"pqledger:class", string(class)},
			{"pqledger:severity", algSeverity[ref].String()},
		}
		b.Components = append(b.Components, *c)
	}
	for _, c := range certs {
		b.Components = append(b.Components, *c)
	}
	b.Components = append(b.Components, keys...)
	sort.Slice(b.Components, func(i, j int) bool { return b.Components[i].BOMRef < b.Components[j].BOMRef })
	if b.Components == nil {
		b.Components = []component{}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(b)
}

func newUUID() string {
	var u [16]byte
	if _, err := rand.Read(u[:]); err != nil {
		return "00000000-0000-4000-8000-000000000000"
	}
	u[6] = (u[6] & 0x0f) | 0x40
	u[8] = (u[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:])
}
