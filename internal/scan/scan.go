// Package scan walks a directory tree and extracts cryptographic findings
// from source code, certificates, keys and configuration files.
package scan

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dmolina23/pqledger/internal/model"
	"github.com/dmolina23/pqledger/internal/rules"
)

const maxFileSize = 2 << 20 // files larger than 2 MiB are skipped

// Options tunes a scan.
type Options struct {
	// IncludeVendor also scans vendor/ directories (skipped by default because
	// they mostly contain third-party code).
	IncludeVendor bool
}

// Result is the outcome of a scan.
type Result struct {
	Root         string
	FilesScanned int
	Findings     []model.Finding
}

type emitFn func(model.Finding)

var skipDirs = map[string]bool{".git": true, "node_modules": true, ".idea": true, ".vscode": true}

// Run scans root, which may be a directory or a single file.
func Run(root string, opt Options) (*Result, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	res := &Result{Root: root}
	emit := func(f model.Finding) { res.Findings = append(res.Findings, f) }

	if !info.IsDir() {
		if scanFile(root, filepath.Base(root), info.Size(), emit) {
			res.FilesScanned++
		}
		finalize(res)
		return res, nil
	}

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entries are skipped, not fatal
		}
		if d.IsDir() {
			if path != root && (skipDirs[d.Name()] || (d.Name() == "vendor" && !opt.IncludeVendor)) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		if scanFile(path, filepath.ToSlash(rel), fi.Size(), emit) {
			res.FilesScanned++
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking %s: %w", root, err)
	}
	finalize(res)
	return res, nil
}

var pemExts = map[string]bool{
	".pem": true, ".crt": true, ".cer": true, ".cert": true, ".key": true,
	".pub": true, ".id": true, ".json": true, ".yaml": true, ".yml": true,
}

var jsExts = map[string]bool{".js": true, ".mjs": true, ".cjs": true, ".ts": true}

// scanFile dispatches a file to the scanners that apply to it and reports
// whether the file was read.
func scanFile(path, rel string, size int64, emit emitFn) bool {
	if size > maxFileSize {
		return false
	}
	name := strings.ToLower(filepath.Base(path))
	ext := filepath.Ext(name)

	isGo := ext == ".go" && !strings.HasSuffix(name, "_test.go")
	isJava := ext == ".java"
	isJS := jsExts[ext] && !strings.HasSuffix(name, ".d.ts") && !strings.HasSuffix(name, ".min.js")
	isYAML := ext == ".yaml" || ext == ".yml"
	isPEM := pemExts[ext] || strings.HasSuffix(name, "_sk") || fabricContext(rel) != ""

	if !isGo && !isJava && !isJS && !isYAML && !isPEM {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	switch {
	case isGo:
		scanGo(path, rel, data, emit)
	case isJava:
		scanJava(rel, data, emit)
	case isJS:
		scanJS(rel, data, emit)
	}
	if isYAML {
		scanFabricYAML(rel, data, emit)
	}
	if isPEM {
		scanPEM(rel, data, emit)
	}
	return true
}

// fabricContext returns "hyperledger-fabric" when the path looks like a Fabric
// MSP / crypto-material layout or a connection profile.
func fabricContext(rel string) string {
	lower := strings.ToLower(rel)
	for _, seg := range strings.Split(lower, "/") {
		switch seg {
		case "msp", "signcerts", "cacerts", "keystore", "tlscacerts", "admincerts",
			"intermediatecerts", "peerorganizations", "ordererorganizations":
			return "hyperledger-fabric"
		}
	}
	base := lower[strings.LastIndex(lower, "/")+1:]
	if strings.HasPrefix(base, "connection-") && strings.HasSuffix(base, ".json") {
		return "hyperledger-fabric"
	}
	return ""
}

func newFinding(rule string, cat model.Category, lang, rel string, line int, alg, param, prim, detail string) model.Finding {
	a := rules.Assess(alg, param, prim)
	if prim == "" {
		prim = "unknown"
	}
	f := model.Finding{
		RuleID:         rule,
		Category:       cat,
		Language:       lang,
		Location:       rel,
		Line:           line,
		Algorithm:      alg,
		Parameter:      param,
		Primitive:      prim,
		Class:          a.Class,
		Severity:       a.Severity,
		Detail:         detail,
		Recommendation: a.Recommendation,
	}
	if a.HasNISTLevel {
		lvl := a.NISTLevel
		f.NISTLevel = &lvl
	}
	return f
}

// finalize removes duplicates and sorts findings deterministically: most
// severe first, then by location and line.
func finalize(res *Result) {
	seen := map[string]bool{}
	out := res.Findings[:0]
	for _, f := range res.Findings {
		k := fmt.Sprintf("%s|%s|%d|%s|%s|%s", f.Category, f.Location, f.Line, f.Algorithm, f.Parameter, f.RuleID)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, f)
	}
	res.Findings = out
	sort.SliceStable(res.Findings, func(i, j int) bool {
		a, b := res.Findings[i], res.Findings[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.Location != b.Location {
			return a.Location < b.Location
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Algorithm < b.Algorithm
	})
}
