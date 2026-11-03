package scan

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/dmolina23/pqledger/internal/model"
	"github.com/dmolina23/pqledger/internal/rules"
)

// ---------------------------------------------------------------- Java

var (
	javaGetInstance = regexp.MustCompile(`(KeyPairGenerator|KeyFactory|Cipher|Signature|MessageDigest|KeyAgreement|KeyGenerator)\s*\.\s*getInstance\(\s*"([^"]+)"`)
	javaInitialize  = regexp.MustCompile(`(?:initialize|init)\(\s*(\d+)`)
	javaECSpec      = regexp.MustCompile(`ECGenParameterSpec\(\s*"([^"]+)"`)
)

// spec is a normalized (algorithm, parameter, primitive) triple.
type spec struct{ alg, param, prim string }

func scanJava(rel string, data []byte, emit emitFn) {
	lines := strings.Split(string(data), "\n")
	ctx := ""
	if strings.Contains(string(data), "org.hyperledger.fabric") {
		ctx = "hyperledger-fabric"
	}
	for i, line := range lines {
		for _, m := range javaGetInstance.FindAllStringSubmatch(line, -1) {
			end := i + 7
			if end > len(lines) {
				end = len(lines)
			}
			look := strings.Join(lines[i:end], "\n")
			for _, s := range javaSpecs(m[1], m[2], look) {
				f := newFinding("java-"+strings.ToLower(s.alg), model.CatSource, "java", rel, i+1, s.alg, s.param, s.prim,
					m[1]+".getInstance(\""+m[2]+"\")")
				f.Context = ctx
				emit(f)
			}
		}
	}
}

func javaSpecs(kind, name, look string) []spec {
	u := strings.ToUpper(name)
	switch kind {
	case "MessageDigest":
		if h, ok := rules.NormalizeHash(name); ok {
			return []spec{{h, "", "hash"}}
		}
	case "KeyPairGenerator", "KeyFactory":
		return javaKeyAlg(u, look)
	case "KeyAgreement":
		switch u {
		case "ECDH":
			return []spec{{"ECDH", "", "key-agree"}}
		case "DH", "DIFFIEHELLMAN":
			return []spec{{"DH", "", "key-agree"}}
		case "XDH", "X25519":
			return []spec{{"X25519", "Curve25519", "key-agree"}}
		}
	case "Signature":
		return javaSignature(u)
	case "Cipher":
		switch strings.SplitN(u, "/", 2)[0] {
		case "RSA":
			return []spec{{"RSA", "", "pke"}}
		case "AES":
			return []spec{{"AES", "", "block-cipher"}}
		case "DES":
			return []spec{{"DES", "", "block-cipher"}}
		case "DESEDE", "3DES", "TRIPLEDES":
			return []spec{{"3DES", "", "block-cipher"}}
		case "RC4", "ARCFOUR":
			return []spec{{"RC4", "", "stream-cipher"}}
		}
	case "KeyGenerator":
		switch u {
		case "AES":
			return []spec{{"AES", firstGroup(javaInitialize, look), "block-cipher"}}
		case "DES":
			return []spec{{"DES", "", "block-cipher"}}
		case "DESEDE":
			return []spec{{"3DES", "", "block-cipher"}}
		}
	}
	return nil
}

func javaKeyAlg(u, look string) []spec {
	switch {
	case u == "RSA" || u == "RSASSA-PSS":
		return []spec{{"RSA", firstGroup(javaInitialize, look), "unknown"}}
	case u == "EC" || u == "ECDSA":
		curve := firstGroup(javaECSpec, look)
		if curve == "" {
			switch firstGroup(javaInitialize, look) {
			case "256":
				curve = "P-256"
			case "384":
				curve = "P-384"
			case "521":
				curve = "P-521"
			}
		}
		return []spec{{"ECC", rules.NormalizeCurve(curve), "unknown"}}
	case u == "DSA":
		return []spec{{"DSA", firstGroup(javaInitialize, look), "signature"}}
	case u == "DH" || u == "DIFFIEHELLMAN":
		return []spec{{"DH", firstGroup(javaInitialize, look), "key-agree"}}
	case u == "ED25519" || u == "EDDSA":
		return []spec{{"EdDSA", "Ed25519", "signature"}}
	case u == "X25519" || u == "XDH":
		return []spec{{"X25519", "Curve25519", "key-agree"}}
	case strings.Contains(u, "KYBER") || strings.Contains(u, "ML-KEM"):
		return []spec{{"ML-KEM", "", "kem"}}
	case strings.Contains(u, "DILITHIUM") || strings.Contains(u, "ML-DSA"):
		return []spec{{"ML-DSA", "", "signature"}}
	case strings.Contains(u, "SPHINCS") || strings.Contains(u, "SLH-DSA"):
		return []spec{{"SLH-DSA", "", "signature"}}
	}
	return nil
}

// javaSignature handles names such as SHA256withRSA, SHA1withECDSA, Ed25519.
func javaSignature(u string) []spec {
	var out []spec
	if i := strings.Index(u, "WITH"); i >= 0 {
		hash, key := u[:i], u[i+4:]
		switch {
		case strings.Contains(key, "RSA"):
			out = append(out, spec{"RSA", "", "signature"})
		case strings.Contains(key, "ECDSA"):
			out = append(out, spec{"ECDSA", "", "signature"})
		case strings.Contains(key, "DSA"):
			out = append(out, spec{"DSA", "", "signature"})
		}
		if h, ok := rules.NormalizeHash(hash); ok && (h == "MD5" || h == "SHA-1") {
			out = append(out, spec{h, "", "hash"})
		}
		return out
	}
	switch {
	case u == "ED25519" || u == "EDDSA":
		return []spec{{"EdDSA", "Ed25519", "signature"}}
	case strings.HasPrefix(u, "RSASSA-PSS"):
		return []spec{{"RSA", "", "signature"}}
	case strings.Contains(u, "ML-DSA") || strings.Contains(u, "DILITHIUM"):
		return []spec{{"ML-DSA", "", "signature"}}
	case strings.Contains(u, "SLH-DSA") || strings.Contains(u, "SPHINCS"):
		return []spec{{"SLH-DSA", "", "signature"}}
	}
	return nil
}

func firstGroup(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

// ------------------------------------------------------- JavaScript / TS

var (
	jsGenKey   = regexp.MustCompile(`generateKeyPair(?:Sync)?\(\s*['"](rsa|rsa-pss|dsa|ec|ed25519|ed448|x25519|x448|dh)['"]`)
	jsSign     = regexp.MustCompile(`create(?:Sign|Verify)\(\s*['"]([^'"]+)['"]`)
	jsHash     = regexp.MustCompile(`createHash\(\s*['"]([^'"]+)['"]`)
	jsCipher   = regexp.MustCompile(`createCipheriv\(\s*['"]([^'"]+)['"]`)
	jsECDH     = regexp.MustCompile(`createECDH\(\s*['"]([^'"]+)['"]`)
	jsDH       = regexp.MustCompile(`createDiffieHellman(?:Group)?\(`)
	jsElliptic = regexp.MustCompile(`new\s+(?:\w+\.)?[eE][cC]\(\s*['"]([^'"]+)['"]`)
	jsModulus  = regexp.MustCompile(`modulusLength\s*:\s*(\d+)`)
	jsCurve    = regexp.MustCompile(`namedCurve\s*:\s*['"]([^'"]+)['"]`)
)

func scanJS(rel string, data []byte, emit emitFn) {
	text := string(data)
	ctx := ""
	for _, marker := range []string{"fabric-contract-api", "fabric-shim", "fabric-network"} {
		if strings.Contains(text, marker) {
			ctx = "hyperledger-fabric"
		}
	}
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		end := i + 6
		if end > len(lines) {
			end = len(lines)
		}
		look := strings.Join(lines[i:end], "\n")
		var specs []spec

		if m := jsGenKey.FindStringSubmatch(line); m != nil {
			specs = append(specs, jsKeyPair(m[1], look)...)
		}
		if m := jsSign.FindStringSubmatch(line); m != nil {
			specs = append(specs, jsSignSpecs(m[1])...)
		}
		if m := jsHash.FindStringSubmatch(line); m != nil {
			if h, ok := rules.NormalizeHash(m[1]); ok {
				specs = append(specs, spec{h, "", "hash"})
			}
		}
		if m := jsCipher.FindStringSubmatch(line); m != nil {
			specs = append(specs, jsCipherSpecs(m[1])...)
		}
		if m := jsECDH.FindStringSubmatch(line); m != nil {
			specs = append(specs, spec{"ECDH", rules.NormalizeCurve(m[1]), "key-agree"})
		}
		if jsDH.MatchString(line) {
			specs = append(specs, spec{"DH", "", "key-agree"})
		}
		if m := jsElliptic.FindStringSubmatch(line); m != nil {
			c := rules.NormalizeCurve(m[1])
			if c == "Ed25519" {
				specs = append(specs, spec{"EdDSA", c, "signature"})
			} else {
				specs = append(specs, spec{"ECC", c, "unknown"})
			}
		}
		for _, s := range specs {
			f := newFinding("js-"+strings.ToLower(s.alg), model.CatSource, "javascript", rel, i+1, s.alg, s.param, s.prim,
				strings.TrimSpace(line))
			f.Context = ctx
			emit(f)
		}
	}
}

func jsKeyPair(kind, look string) []spec {
	switch kind {
	case "rsa", "rsa-pss":
		return []spec{{"RSA", firstGroup(jsModulus, look), "unknown"}}
	case "dsa":
		return []spec{{"DSA", firstGroup(jsModulus, look), "signature"}}
	case "ec":
		return []spec{{"ECC", rules.NormalizeCurve(firstGroup(jsCurve, look)), "unknown"}}
	case "ed25519", "ed448":
		return []spec{{"EdDSA", rules.NormalizeCurve(kind), "signature"}}
	case "x25519", "x448":
		return []spec{{"X25519", "Curve25519", "key-agree"}}
	case "dh":
		return []spec{{"DH", "", "key-agree"}}
	}
	return nil
}

func jsSignSpecs(name string) []spec {
	u := strings.ToUpper(name)
	var out []spec
	switch {
	case strings.Contains(u, "RSA"):
		out = append(out, spec{"RSA", "", "signature"})
	case strings.Contains(u, "ECDSA"):
		out = append(out, spec{"ECDSA", "", "signature"})
	}
	if i := strings.LastIndex(u, "-"); i >= 0 {
		u = u[i+1:]
	}
	if h, ok := rules.NormalizeHash(u); ok {
		out = append(out, spec{h, "", "hash"})
	}
	return out
}

func jsCipherSpecs(name string) []spec {
	lower := strings.ToLower(name)
	if strings.HasPrefix(lower, "des-ede3") || strings.HasPrefix(lower, "des3") {
		return []spec{{"3DES", "", "block-cipher"}}
	}
	parts := strings.Split(lower, "-")
	switch parts[0] {
	case "aes":
		param := ""
		if len(parts) > 1 {
			if _, err := strconv.Atoi(parts[1]); err == nil {
				param = parts[1]
			}
		}
		return []spec{{"AES", param, "block-cipher"}}
	case "des":
		return []spec{{"DES", "", "block-cipher"}}
	case "rc4":
		return []spec{{"RC4", "", "stream-cipher"}}
	}
	return nil
}
