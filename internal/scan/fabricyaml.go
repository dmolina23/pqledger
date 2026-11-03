package scan

import (
	"regexp"
	"strings"

	"github.com/dmolina23/pqledger/internal/model"
)

// The scanner understands just enough YAML (indentation-based key/value
// blocks) to read Fabric's core.yaml, orderer.yaml and fabric-ca config files
// without pulling in a YAML dependency.

var (
	reBCCSP  = regexp.MustCompile(`^(\s*)BCCSP:\s*(#.*)?$`)
	reKeyReq = regexp.MustCompile(`^(\s*)keyrequest:\s*(#.*)?$`)
	reKV     = regexp.MustCompile(`^\s*([A-Za-z_][\w-]*):\s*(.*?)\s*$`)
)

type yamlKV struct {
	line     int
	key, val string
}

func scanFabricYAML(rel string, data []byte, emit emitFn) {
	text := string(data)
	if !strings.Contains(text, "BCCSP") && !strings.Contains(text, "keyrequest") {
		return
	}
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		l = strings.TrimRight(l, "\r")
		if m := reBCCSP.FindStringSubmatch(l); m != nil {
			bccspBlock(rel, blockKVs(lines, i, len(m[1])), emit)
		} else if m := reKeyReq.FindStringSubmatch(l); m != nil {
			keyRequestBlock(rel, blockKVs(lines, i, len(m[1])), emit)
		}
	}
}

// blockKVs returns the key/value pairs nested under the block that starts at
// lines[start] and has the given indentation.
func blockKVs(lines []string, start, indent int) []yamlKV {
	var out []yamlKV
	for i := start + 1; i < len(lines); i++ {
		l := strings.TrimRight(lines[i], "\r")
		trim := strings.TrimSpace(l)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		if len(l)-len(strings.TrimLeft(l, " ")) <= indent {
			break
		}
		if m := reKV.FindStringSubmatch(l); m != nil {
			out = append(out, yamlKV{i + 1, m[1], cleanValue(m[2])})
		}
	}
	return out
}

func cleanValue(v string) string {
	if i := strings.Index(v, " #"); i >= 0 {
		v = v[:i]
	}
	if strings.HasPrefix(v, "#") {
		return ""
	}
	return strings.Trim(strings.TrimSpace(v), `"'`)
}

func bccspBlock(rel string, kvs []yamlKV, emit emitFn) {
	var (
		def, hash, sec    string
		defLine, hashLine int
		section           string
	)
	for _, kv := range kvs {
		switch {
		case kv.val == "":
			section = kv.key
		case kv.key == "Default":
			def, defLine = strings.ToUpper(kv.val), kv.line
		case kv.key == "Hash" && section == "SW":
			hash, hashLine = strings.ToUpper(kv.val), kv.line
		case kv.key == "Security" && section == "SW":
			sec = kv.val
		}
	}

	switch def {
	case "SW":
		curve := map[string]string{"256": "P-256", "384": "P-384"}[sec]
		f := newFinding("fabric-bccsp-sw", model.CatConfig, "yaml", rel, defLine, "ECDSA", curve, "signature",
			"Fabric BCCSP software provider signs with ECDSA; the curve follows Security="+sec)
		f.Context = "hyperledger-fabric"
		emit(f)
	case "PKCS11":
		f := newFinding("fabric-bccsp-pkcs11", model.CatConfig, "yaml", rel, defLine, "PKCS11-HSM", "", "unknown",
			"HSM-backed BCCSP: the algorithms depend on the HSM configuration, audit it separately")
		f.Context = "hyperledger-fabric"
		emit(f)
	}

	if hash != "" {
		alg := ""
		switch {
		case hash == "SHA2" && sec == "384":
			alg = "SHA-384"
		case hash == "SHA2":
			alg = "SHA-256"
		case hash == "SHA3":
			alg = "SHA-3"
		}
		if alg != "" {
			f := newFinding("fabric-bccsp-hash", model.CatConfig, "yaml", rel, hashLine, alg, "", "hash",
				"Fabric BCCSP hash family "+hash+" with Security="+sec)
			f.Context = "hyperledger-fabric"
			emit(f)
		}
	}
}

func keyRequestBlock(rel string, kvs []yamlKV, emit emitFn) {
	var algo, size string
	var line int
	for _, kv := range kvs {
		switch kv.key {
		case "algo":
			algo, line = strings.ToLower(kv.val), kv.line
		case "size":
			size = kv.val
		}
	}
	var alg, param string
	switch algo {
	case "ecdsa":
		alg, param = "ECDSA", map[string]string{"256": "P-256", "384": "P-384", "521": "P-521"}[size]
	case "rsa":
		alg, param = "RSA", size
	default:
		return
	}
	f := newFinding("fabric-ca-keyrequest", model.CatConfig, "yaml", rel, line, alg, param, "signature",
		"Fabric CA key request: algo="+algo+" size="+size)
	f.Context = "hyperledger-fabric"
	emit(f)
}
