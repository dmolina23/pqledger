// Command pqledger scans a project or network directory for cryptography that
// is vulnerable to quantum computers, with first-class support for
// Hyperledger Fabric.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/dmolina23/pqledger/internal/model"
	"github.com/dmolina23/pqledger/internal/report"
	"github.com/dmolina23/pqledger/internal/scan"
)

// version is overridden at build time: -ldflags "-X main.version=v0.1.0".
var version = "0.1.0-dev"

const usage = `pqledger - post-quantum readiness scanner for blockchain and DLT networks

Usage:
  pqledger scan [flags] PATH
  pqledger version

Flags for scan:
  -f, --format string        text, json or cbom (default "text")
  -o, --output string        write the report to a file instead of stdout
      --min-severity string  lowest severity shown in text output (default "low")
      --fail-on string       exit with status 2 if a finding has at least this severity
      --include-vendor       also scan vendor/ directories
  -v, --verbose              show details for every finding in text output

Exit status: 0 = ok, 1 = error, 2 = findings at or above --fail-on.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 1
	}
	switch args[0] {
	case "version", "--version":
		fmt.Fprintln(stdout, "pqledger", version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	case "scan":
		return runScan(args[1:], stdout, stderr)
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
	return 1
}

func runScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		format, output, minSev, failOn string
		includeVendor, verbose         bool
	)
	fs.StringVar(&format, "format", "text", "")
	fs.StringVar(&format, "f", "text", "")
	fs.StringVar(&output, "output", "", "")
	fs.StringVar(&output, "o", "", "")
	fs.StringVar(&minSev, "min-severity", "low", "")
	fs.StringVar(&failOn, "fail-on", "", "")
	fs.BoolVar(&includeVendor, "include-vendor", false, "")
	fs.BoolVar(&verbose, "verbose", false, "")
	fs.BoolVar(&verbose, "v", false, "")

	// The flag package stops at the first positional argument; loop so that
	// flags may appear before and after PATH.
	var paths []string
	for {
		if err := fs.Parse(args); err != nil {
			return 1
		}
		if fs.NArg() == 0 {
			break
		}
		paths = append(paths, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if len(paths) != 1 {
		fmt.Fprint(stderr, "scan needs exactly one PATH\n\n", usage)
		return 1
	}

	min, err := model.ParseSeverity(minSev)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	var failSev model.Severity
	if failOn != "" {
		if failSev, err = model.ParseSeverity(failOn); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
	}
	format = strings.ToLower(format)
	if format != "text" && format != "json" && format != "cbom" {
		fmt.Fprintf(stderr, "error: unknown format %q (use text, json or cbom)\n", format)
		return 1
	}

	res, err := scan.Run(paths[0], scan.Options{IncludeVendor: includeVendor})
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}

	out := stdout
	if output != "" {
		file, err := os.Create(output)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 1
		}
		defer file.Close()
		out = file
	}

	switch format {
	case "json":
		err = report.JSON(out, res, version)
	case "cbom":
		err = report.CBOM(out, res, version)
	default:
		report.Text(out, res, version, report.TextOptions{MinSeverity: min, Verbose: verbose})
	}
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}

	if failOn != "" {
		for _, f := range res.Findings {
			if f.Severity >= failSev {
				return 2
			}
		}
	}
	return 0
}
