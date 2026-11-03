package scan

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"

	"github.com/dmolina23/pqledger/internal/model"
)

// op describes how one selector of a standard-library package maps to an
// algorithm. Empty fields fall back to the package defaults.
type op struct{ alg, param, prim string }

type goPkg struct {
	alg, prim string
	ops       map[string]op
}

var nistCurves = map[string]op{
	"P224": {param: "P-224"}, "P256": {param: "P-256"}, "P384": {param: "P-384"}, "P521": {param: "P-521"},
}

var goPkgs = map[string]goPkg{
	"crypto/rsa": {alg: "RSA", prim: "signature", ops: map[string]op{
		"GenerateKey": {prim: "unknown"}, "SignPKCS1v15": {}, "SignPSS": {}, "VerifyPKCS1v15": {}, "VerifyPSS": {},
		"EncryptOAEP": {prim: "pke"}, "EncryptPKCS1v15": {prim: "pke"},
		"DecryptOAEP": {prim: "pke"}, "DecryptPKCS1v15": {prim: "pke"},
	}},
	"crypto/ecdsa": {alg: "ECDSA", prim: "signature", ops: map[string]op{
		"GenerateKey": {}, "Sign": {}, "SignASN1": {}, "Verify": {}, "VerifyASN1": {},
	}},
	"crypto/ecdh": {alg: "ECDH", prim: "key-agree", ops: map[string]op{
		"P256": {param: "P-256"}, "P384": {param: "P-384"}, "P521": {param: "P-521"},
		"X25519": {alg: "X25519", param: "Curve25519"},
	}},
	"crypto/elliptic": {alg: "ECC", prim: "unknown", ops: nistCurves},
	"crypto/ed25519": {alg: "EdDSA", prim: "signature", ops: map[string]op{
		"GenerateKey": {param: "Ed25519"}, "Sign": {param: "Ed25519"}, "Verify": {param: "Ed25519"}, "NewKeyFromSeed": {param: "Ed25519"},
	}},
	"crypto/dsa": {alg: "DSA", prim: "signature", ops: map[string]op{
		"GenerateKey": {}, "GenerateParameters": {}, "Sign": {}, "Verify": {},
	}},
	"crypto/md5":  {alg: "MD5", prim: "hash", ops: map[string]op{"New": {}, "Sum": {}}},
	"crypto/sha1": {alg: "SHA-1", prim: "hash", ops: map[string]op{"New": {}, "Sum": {}}},
	"crypto/sha256": {alg: "SHA-256", prim: "hash", ops: map[string]op{
		"New": {}, "Sum256": {}, "New224": {alg: "SHA-224"}, "Sum224": {alg: "SHA-224"},
	}},
	"crypto/sha512": {alg: "SHA-512", prim: "hash", ops: map[string]op{
		"New": {}, "Sum512": {}, "New384": {alg: "SHA-384"}, "Sum384": {alg: "SHA-384"},
		"New512_256": {}, "Sum512_256": {}, "New512_224": {}, "Sum512_224": {},
	}},
	"crypto/des": {alg: "DES", prim: "block-cipher", ops: map[string]op{
		"NewCipher": {}, "NewTripleDESCipher": {alg: "3DES"},
	}},
	"crypto/rc4": {alg: "RC4", prim: "stream-cipher", ops: map[string]op{"NewCipher": {}}},
	"crypto/aes": {alg: "AES", prim: "block-cipher", ops: map[string]op{"NewCipher": {}}},
	"crypto/mlkem": {alg: "ML-KEM", prim: "kem", ops: map[string]op{
		"GenerateKey768": {param: "768"}, "GenerateKey1024": {param: "1024"},
		"NewDecapsulationKey768": {param: "768"}, "NewDecapsulationKey1024": {param: "1024"},
		"NewEncapsulationKey768": {param: "768"}, "NewEncapsulationKey1024": {param: "1024"},
	}},
}

type thirdParty struct{ prefix, alg, param, prim, ctx string }

// Third-party packages that are reported at import level.
var goThirdParty = []thirdParty{
	{"github.com/btcsuite/btcd/btcec", "ECDSA", "secp256k1", "signature", "bitcoin"},
	{"github.com/decred/dcrd/dcrec/secp256k1", "ECDSA", "secp256k1", "signature", "blockchain"},
	{"github.com/ethereum/go-ethereum/crypto", "ECDSA", "secp256k1", "signature", "ethereum"},
	{"golang.org/x/crypto/curve25519", "X25519", "Curve25519", "key-agree", ""},
	{"golang.org/x/crypto/ed25519", "EdDSA", "Ed25519", "signature", ""},
}

func circlRule(p string) (alg, param, prim string, ok bool) {
	if !strings.HasPrefix(p, "github.com/cloudflare/circl/") {
		return
	}
	l := strings.ToLower(p)
	digits := trailingDigits(l)
	switch {
	case strings.Contains(l, "mlkem"), strings.Contains(l, "kyber"):
		return "ML-KEM", digits, "kem", true
	case strings.Contains(l, "mldsa"):
		return "ML-DSA", digits, "signature", true
	case strings.Contains(l, "dilithium"):
		return "ML-DSA", "", "signature", true
	case strings.Contains(l, "slhdsa"):
		return "SLH-DSA", "", "signature", true
	}
	return
}

func trailingDigits(s string) string {
	i := len(s)
	for i > 0 && s[i-1] >= '0' && s[i-1] <= '9' {
		i--
	}
	return s[i:]
}

// packageName returns the identifier a file uses for an import path.
func packageName(imp *ast.ImportSpec, p string) string {
	if imp.Name != nil {
		if imp.Name.Name == "_" || imp.Name.Name == "." {
			return ""
		}
		return imp.Name.Name
	}
	parts := strings.Split(p, "/")
	last := parts[len(parts)-1]
	if len(parts) > 1 && len(last) >= 2 && last[0] == 'v' && trailingDigits(last) == last[1:] {
		last = parts[len(parts)-2] // module major-version suffix, e.g. btcec/v2
	}
	return last
}

func scanGo(path, rel string, data []byte, emit emitFn) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, data, parser.SkipObjectResolution)
	if err != nil {
		return // not valid Go (or generated template): skip silently
	}

	var found []model.Finding
	add := func(pos token.Pos, alg, param, prim, detail string) {
		found = append(found, newFinding("go-"+strings.ToLower(alg), model.CatSource, "go", rel,
			fset.Position(pos).Line, alg, param, prim, detail))
	}

	names := map[string]string{} // identifier -> import path (crypto packages only)
	fabric := false
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		if strings.HasPrefix(p, "github.com/hyperledger/fabric") {
			fabric = true
		}
		if _, ok := goPkgs[p]; ok {
			if n := packageName(imp, p); n != "" {
				names[n] = p
			}
			continue
		}
		for _, tp := range goThirdParty {
			if strings.HasPrefix(p, tp.prefix) {
				add(imp.Pos(), tp.alg, tp.param, tp.prim, "Imports "+p)
				if last := &found[len(found)-1]; tp.ctx != "" {
					last.Context = tp.ctx
				}
				break
			}
		}
		if alg, param, prim, ok := circlRule(p); ok {
			add(imp.Pos(), alg, param, prim, "Imports "+p)
		}
	}

	used := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		p, ok := names[id.Name]
		if !ok {
			return true
		}
		pkg := goPkgs[p]
		spec, ok := pkg.ops[sel.Sel.Name]
		if !ok {
			return true
		}
		alg, prim := first(spec.alg, pkg.alg), first(spec.prim, pkg.prim)
		param := spec.param
		switch {
		case p == "crypto/rsa" && sel.Sel.Name == "GenerateKey" && len(call.Args) >= 2:
			if lit, ok := call.Args[1].(*ast.BasicLit); ok && lit.Kind == token.INT {
				param = lit.Value
			}
		case p == "crypto/ecdsa" && sel.Sel.Name == "GenerateKey" && len(call.Args) >= 1:
			param = curveArg(call.Args[0], names)
		}
		used[p] = true
		add(call.Pos(), alg, param, prim, "Calls "+id.Name+"."+sel.Sel.Name)
		return true
	})

	// Packages that are imported but only used through types (e.g. *rsa.PrivateKey).
	for _, imp := range f.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		if pkg, ok := goPkgs[p]; ok && !used[p] {
			add(imp.Pos(), pkg.alg, "", pkg.prim, "Imports "+p)
		}
	}

	found = dedupeECC(found)
	ctx := ""
	if fabric {
		ctx = "hyperledger-fabric"
	}
	for _, fd := range found {
		if fd.Context == "" {
			fd.Context = ctx
		}
		emit(fd)
	}
}

func curveArg(e ast.Expr, names map[string]string) string {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return ""
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok || names[id.Name] != "crypto/elliptic" {
		return ""
	}
	return nistCurves[sel.Sel.Name].param
}

// dedupeECC merges a generic "ECC curve" finding into an ECDSA/ECDH finding
// that sits on the same line, so `ecdsa.GenerateKey(elliptic.P256(), ...)`
// yields one finding instead of two.
func dedupeECC(in []model.Finding) []model.Finding {
	specific := map[int]bool{}
	for _, f := range in {
		if f.Algorithm == "ECDSA" || f.Algorithm == "ECDH" {
			specific[f.Line] = true
		}
	}
	out := in[:0:0]
	for _, f := range in {
		if f.Algorithm == "ECC" && specific[f.Line] {
			continue
		}
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Line < out[j].Line })
	return out
}

func first(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
