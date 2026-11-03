// Package report renders scan results as text, JSON or a CycloneDX CBOM.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/dmolina23/pqledger/internal/model"
	"github.com/dmolina23/pqledger/internal/scan"
)

// Summary counts findings by severity.
func Summary(fs []model.Finding) map[string]int {
	out := map[string]int{}
	for _, f := range fs {
		out[f.Severity.String()]++
	}
	return out
}

// Verdict gives a one-line conclusion for a set of findings.
func Verdict(fs []model.Finding) string {
	var vuln, broken bool
	for _, f := range fs {
		switch f.Class {
		case model.QuantumVulnerable:
			vuln = true
		case model.ClassicallyBroken:
			broken = true
		}
	}
	switch {
	case vuln:
		return "quantum-vulnerable cryptography in use: migration planning needed"
	case broken:
		return "no quantum-vulnerable cryptography found, but classically broken algorithms are in use"
	}
	return "no quantum-vulnerable cryptography found"
}

// TextOptions controls the human-readable report.
type TextOptions struct {
	MinSeverity model.Severity
	Verbose     bool
}

// Text writes the human-readable report.
func Text(w io.Writer, res *scan.Result, version string, opt TextOptions) {
	fmt.Fprintf(w, "pqledger %s - scanned %s (%d files)\n\n", version, res.Root, res.FilesScanned)

	var shown []model.Finding
	for _, f := range res.Findings {
		if f.Severity >= opt.MinSeverity {
			shown = append(shown, f)
		}
	}

	if len(shown) > 0 {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "SEVERITY\tALGORITHM\tPARAM\tCLASS\tLOCATION")
		for _, f := range shown {
			loc := f.Location
			if f.Line > 0 {
				loc = fmt.Sprintf("%s:%d", f.Location, f.Line)
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", f.Severity, f.Algorithm, dash(f.Parameter), f.Class, loc)
			if opt.Verbose {
				fmt.Fprintf(tw, "\t\t\t\t  %s\n", f.Detail)
				if f.Context != "" {
					fmt.Fprintf(tw, "\t\t\t\t  context: %s\n", f.Context)
				}
			}
		}
		tw.Flush()
		fmt.Fprintln(w)
	}

	counts := Summary(res.Findings)
	var parts []string
	for _, s := range []string{"critical", "high", "medium", "low", "info"} {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	if len(parts) == 0 {
		parts = []string{"no findings"}
	}
	fmt.Fprintf(w, "Findings: %s\n", strings.Join(parts, " | "))
	fmt.Fprintf(w, "Verdict:  %s\n", Verdict(res.Findings))

	guidance := map[string]map[string]bool{}
	for _, f := range shown {
		if f.Recommendation == "" {
			continue
		}
		if guidance[f.Recommendation] == nil {
			guidance[f.Recommendation] = map[string]bool{}
		}
		guidance[f.Recommendation][f.Algorithm] = true
	}
	if len(guidance) > 0 {
		fmt.Fprintln(w, "\nMigration guidance:")
		var recs []string
		for r := range guidance {
			recs = append(recs, r)
		}
		sort.Strings(recs)
		for _, r := range recs {
			var algs []string
			for a := range guidance[r] {
				algs = append(algs, a)
			}
			sort.Strings(algs)
			fmt.Fprintf(w, "  %s: %s\n", strings.Join(algs, ", "), r)
		}
	}
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

type jsonReport struct {
	Tool         string          `json:"tool"`
	Version      string          `json:"version"`
	Root         string          `json:"root"`
	FilesScanned int             `json:"filesScanned"`
	Verdict      string          `json:"verdict"`
	Summary      map[string]int  `json:"summary"`
	Findings     []model.Finding `json:"findings"`
}

// JSON writes the full findings list as JSON.
func JSON(w io.Writer, res *scan.Result, version string) error {
	findings := res.Findings
	if findings == nil {
		findings = []model.Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(jsonReport{
		Tool:         "pqledger",
		Version:      version,
		Root:         res.Root,
		FilesScanned: res.FilesScanned,
		Verdict:      Verdict(res.Findings),
		Summary:      Summary(res.Findings),
		Findings:     findings,
	})
}
