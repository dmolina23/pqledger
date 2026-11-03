// Package model defines the data types shared by scanners and reporters.
package model

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Severity ranks how urgently a finding should be addressed.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = [...]string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < Info || s > Critical {
		return "unknown"
	}
	return severityNames[s]
}

// MarshalJSON encodes the severity as its lower-case name.
func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// Bump raises the severity by one level, capped at Critical.
func (s Severity) Bump() Severity {
	if s >= Critical {
		return Critical
	}
	return s + 1
}

// ParseSeverity converts a name such as "high" into a Severity.
func ParseSeverity(v string) (Severity, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	for i, n := range severityNames {
		if n == v {
			return Severity(i), nil
		}
	}
	return Info, fmt.Errorf("unknown severity %q (use info, low, medium, high or critical)", v)
}

// Class describes how an algorithm fares against quantum (and classical) attacks.
type Class string

const (
	// QuantumVulnerable algorithms are broken by Shor's algorithm (RSA, ECC, DH, DSA).
	QuantumVulnerable Class = "quantum-vulnerable"
	// QuantumWeakened algorithms keep some security but lose margin (e.g. AES-128 under Grover).
	QuantumWeakened Class = "quantum-weakened"
	// ClassicallyBroken algorithms are unsafe regardless of quantum computers.
	ClassicallyBroken Class = "classically-broken"
	// QuantumSafe algorithms are considered resistant (NIST PQC standards, AES-256, SHA-2/3).
	QuantumSafe Class = "quantum-safe"
	// Unknown means the scanner could not determine the algorithm or its parameters.
	Unknown Class = "unknown"
)

// Category says what kind of artifact produced a finding.
type Category string

const (
	CatCertificate Category = "certificate"
	CatPrivateKey  Category = "private-key"
	CatPublicKey   Category = "public-key"
	CatSource      Category = "source"
	CatConfig      Category = "config"
)

// CertInfo carries certificate metadata for certificate findings.
type CertInfo struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	NotBefore          time.Time `json:"notBefore"`
	NotAfter           time.Time `json:"notAfter"`
	IsCA               bool      `json:"isCA"`
	SHA256             string    `json:"sha256"`
	SignatureAlgorithm string    `json:"signatureAlgorithm"`
}

// Finding is one cryptographic asset or usage discovered by a scanner.
type Finding struct {
	RuleID         string    `json:"ruleId"`
	Category       Category  `json:"category"`
	Language       string    `json:"language,omitempty"`
	Location       string    `json:"location"`
	Line           int       `json:"line,omitempty"`
	Algorithm      string    `json:"algorithm"`
	Parameter      string    `json:"parameter,omitempty"`
	Primitive      string    `json:"primitive"`
	Class          Class     `json:"class"`
	Severity       Severity  `json:"severity"`
	NISTLevel      *int      `json:"nistQuantumSecurityLevel,omitempty"`
	Context        string    `json:"context,omitempty"`
	Detail         string    `json:"detail"`
	Recommendation string    `json:"recommendation,omitempty"`
	Cert           *CertInfo `json:"certificate,omitempty"`
}
