package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tree(t *testing.T, src string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

const rsaSrc = "package x\nimport \"crypto/rsa\"\nimport \"crypto/rand\"\nvar _, _ = rsa.GenerateKey(rand.Reader, 2048)\n"

func exec(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestFailOnExitCodes(t *testing.T) {
	dir := tree(t, rsaSrc)
	if code, _, _ := exec("scan", dir); code != 0 {
		t.Errorf("scan without --fail-on should exit 0, got %d", code)
	}
	if code, _, _ := exec("scan", dir, "--fail-on", "high"); code != 2 {
		t.Errorf("RSA-2048 is high; --fail-on high should exit 2, got %d", code)
	}
	if code, _, _ := exec("scan", dir, "--fail-on", "critical"); code != 0 {
		t.Errorf("--fail-on critical should exit 0, got %d", code)
	}
}

func TestFlagsMayFollowThePath(t *testing.T) {
	dir := tree(t, rsaSrc)
	code, out, _ := exec("scan", "--fail-on", "high", dir, "-f", "json")
	if code != 2 || !strings.Contains(out, `"algorithm": "RSA"`) {
		t.Errorf("flags before and after PATH should both work: code=%d out=%q", code, out)
	}
}

func TestUsageErrors(t *testing.T) {
	dir := tree(t, rsaSrc)
	for _, args := range [][]string{
		{},
		{"nope"},
		{"scan"},
		{"scan", dir, dir},
		{"scan", dir, "-f", "xml"},
		{"scan", dir, "--min-severity", "extreme"},
		{"scan", dir, "--fail-on", "extreme"},
		{"scan", filepath.Join(dir, "missing")},
	} {
		if code, _, _ := exec(args...); code != 1 {
			t.Errorf("%v should exit 1, got %d", args, code)
		}
	}
}

func TestVersionAndOutputFile(t *testing.T) {
	if code, out, _ := exec("version"); code != 0 || !strings.HasPrefix(out, "pqledger ") {
		t.Errorf("version: code=%d out=%q", code, out)
	}
	dir := tree(t, rsaSrc)
	file := filepath.Join(t.TempDir(), "cbom.json")
	if code, out, _ := exec("scan", dir, "-f", "cbom", "-o", file); code != 0 || out != "" {
		t.Fatalf("writing to a file should leave stdout empty: code=%d out=%q", code, out)
	}
	data, err := os.ReadFile(file)
	if err != nil || !strings.Contains(string(data), `"bomFormat": "CycloneDX"`) {
		t.Errorf("CBOM file not written correctly: %v", err)
	}
}
