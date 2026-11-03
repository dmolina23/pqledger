# pqledger

**Post-quantum readiness scanner for blockchain and DLT networks, starting with Hyperledger Fabric.**

[![CI](https://github.com/dmolina23/pqledger/actions/workflows/ci.yml/badge.svg)](https://github.com/dmolina23/pqledger/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`pqledger` finds the cryptography in your project or network directory that a
large quantum computer would break (RSA, ECDSA, ECDH, DSA, DH, Ed25519, X25519), ranks it, and
tells you what to migrate to. It is a single Go binary with **zero third-party
dependencies**, and it can emit a [CycloneDX 1.6 CBOM](https://cyclonedx.org/capabilities/cbom/)
(Cryptography Bill of Materials) that is validated against the official schema in CI.

## Why another scanner?

General-purpose scanners for post-quantum cryptography already exist (see
[Related projects](#related-projects)). They look at application source code.
A permissioned ledger has a different problem: most of its cryptography is **not in
the code**. It lives in artifacts that generic tools do not read:

- X.509 identities in MSP directories (`signcerts/`, `cacerts/`, `tlscacerts/`, `keystore/*_sk`)
- certificates embedded in JSON connection profiles and wallets
- peer/orderer configuration (`core.yaml`, `orderer.yaml`: the BCCSP provider)
- Fabric CA key requests (`keyrequest: algo / size`)
- chaincode in **all three** Fabric languages: Go, Java and JavaScript/TypeScript

A ledger also keeps signed data for as long as the chain exists, and enrollment and
CA certificates are often long-lived, so the migration window is worth knowing early.
`pqledger` flags certificates that outlive the 2030 deprecation horizon.

## Quick start

```sh
go install github.com/dmolina23/pqledger/cmd/pqledger@latest

pqledger scan ./my-fabric-network
pqledger scan ./my-chaincode -f json
pqledger scan . -f cbom -o cbom.json
pqledger scan . --fail-on high          # exit status 2 if anything is high or worse (CI gate)
```

Or from source: `git clone`, then `make build` (binary in `bin/`).

### Try the demo

```sh
make demo      # generates a Fabric-like MSP tree with openssl, then scans examples/
```

Excerpt of the real output (`--min-severity critical`):

```text
pqledger dev - scanned examples (14 files)

SEVERITY  ALGORITHM  PARAM  CLASS               LOCATION
critical  ECDSA      P-256  quantum-vulnerable  _generated/connection-org1.json:7
critical  ECDSA      P-256  quantum-vulnerable  _generated/crypto/.../msp/cacerts/ca.org1.example.com-cert.pem:1
critical  ECDSA      P-256  quantum-vulnerable  _generated/crypto/.../msp/signcerts/peer0.org1.example.com-cert.pem:1
critical  ECDSA      P-256  quantum-vulnerable  _generated/crypto/.../tls/server.crt:1
critical  RSA        2048   quantum-vulnerable  _generated/legacy/legacy-ca.pem:1
critical  RSA        1024   quantum-vulnerable  chaincode-go/main.go:34

Findings: 6 critical | 16 high | 4 info
Verdict:  quantum-vulnerable cryptography in use: migration planning needed
```

Use `-v` for the reason behind each finding and `--min-severity info` to see everything.

### Tried on a real project

A shallow clone of [`hyperledger/fabric-samples`](https://github.com/hyperledger/fabric-samples)
(Nov 2026): 609 files scanned in about 0.1 s, 18 high findings. All of them are
ECDSA P-256 coming from `core.yaml` BCCSP settings, Fabric CA key requests and an
HSM sample, which I checked by hand against the source lines. Results will drift as that repo changes.

## What it detects

| Artifact | What is read | Examples |
|---|---|---|
| X.509 certificates | PEM files, MSP layouts, PEM embedded in JSON/YAML | public key algorithm and size/curve, validity, weak signature hash (MD5, SHA-1) |
| Private / public keys | PKCS#1, PKCS#8, SEC1, PKIX | algorithm and size only; **key material is never printed** |
| Go source | `go/ast`, stdlib and a few third-party packages | `crypto/rsa`, `ecdsa`, `ecdh`, `ed25519`, `md5`, `sha1`, `des`, `rc4`, `aes`, `crypto/mlkem`, btcec, go-ethereum, circl |
| Java source | `getInstance(...)` calls | `KeyPairGenerator`, `Signature`, `Cipher`, `MessageDigest`, `KeyAgreement`, key size via `initialize` |
| JavaScript / TypeScript | Node `crypto` and `elliptic` calls | `generateKeyPairSync`, `createSign`, `createHash`, `createCipheriv`, `createECDH` |
| Fabric configuration | `core.yaml`, `orderer.yaml`, Fabric CA config | BCCSP default provider, hash family and security level, CA key requests, PKCS11 (flagged for manual review) |

Post-quantum algorithms (ML-KEM, ML-DSA, SLH-DSA) are recognised and reported as
`quantum-safe` so that a migrated codebase does not show up as a gap.

## How findings are classified

| Class | Meaning | Typical severity |
|---|---|---|
| `quantum-vulnerable` | broken by Shor's algorithm: RSA, ECC/ECDSA/ECDH, EdDSA, X25519, DH, DSA | high (critical below 2048 bits) |
| `classically-broken` | unsafe today: MD5, SHA-1, DES, RC4, 3DES | high / critical / medium |
| `quantum-weakened` | margin reduced by Grover's algorithm: AES-128/192 | low |
| `quantum-safe` | NIST PQC standards, AES-256, SHA-2/SHA-3 | info |
| `unknown` | parameters could not be determined (for example AES with a runtime key size) | info |

Severity is a **heuristic**, not a compliance verdict. One rule worth knowing: a
quantum-vulnerable certificate valid beyond 2030 is bumped one level. The year
follows the deprecation timeline in the NIST IR 8547 draft; adjust it to your own policy.

Migration advice targets the NIST standards FIPS 203 (ML-KEM), FIPS 204 (ML-DSA)
and FIPS 205 (SLH-DSA), in hybrid mode during the transition. Whether a given platform
can actually use them yet is a separate question that depends on the platform.

## Output formats

- `text` (default): table, summary, verdict and migration guidance
- `json`: every finding with rule id, location, class, severity, NIST quantum level and context
- `cbom`: CycloneDX 1.6 with algorithm, certificate and key assets and evidence
  (file and line) for every place an asset was seen. `make cbom` validates it against the
  official JSON schema.

### Use it in CI

```yaml
- run: go install github.com/dmolina23/pqledger/cmd/pqledger@latest
- run: pqledger scan . --fail-on high -f cbom -o cbom.json
- uses: actions/upload-artifact@v4
  with: { name: cbom, path: cbom.json }
```

## Limitations

Please read these before trusting a clean result.

- **Static analysis only.** It reads files; it does not connect to running peers or orderers,
  so TLS cipher suites negotiated at runtime are not seen.
- **Java and JavaScript use pattern matching, not a parser.** Algorithms passed through variables
  or constants are missed; key sizes are read from nearby lines and may be absent.
- **Go is parsed properly**, but only a curated list of packages is recognised.
- **Dependencies are not inspected yet** (`go.mod`, `pom.xml`, `package.json`).
- The Fabric BCCSP rule encodes the documented default behaviour (software provider signs with
  ECDSA, curve following `Security`). Verify it against your Fabric version.
- Certificate and key detection depends on file naming and location heuristics for files without
  a standard extension.

## Roadmap

- [ ] Dependency manifests (Go, Maven, npm) as library inventory in the CBOM
- [ ] SARIF output for GitHub code scanning
- [ ] Live probing of peer/orderer TLS endpoints
- [ ] Channel configuration (`configtx.yaml`) and genesis block inspection
- [ ] Other ledgers: Hyperledger Besu / Ethereum (Solidity, secp256k1), Rust-based chains
- [ ] Tree-sitter based Java and TypeScript analysis
- [ ] Reusable GitHub Action

## Related projects

`pqledger` is not trying to replace these; it covers ledger artifacts they do not read.

- [IBM CBOMkit / sonar-cryptography](https://github.com/PQCA/sonar-cryptography): CBOM generation from source via SonarQube
- [Keylens](https://github.com/keylens/cbom): Rust CLI for Python and JavaScript
- [pqcheck](https://pypi.org/project/pqcheck/) and [pqc-audit](https://pypi.org/project/pqc-audit): Python scanners with CBOM output

## Development

```sh
make test        # go test -race -cover ./...
make vet fmt-check
make cbom        # build, scan the examples, validate the CBOM against the CycloneDX 1.6 schema
```

The project layout is `cmd/pqledger` (CLI), `internal/scan` (one scanner per artifact type),
`internal/rules` (algorithm knowledge base) and `internal/report` (text, JSON, CBOM).
A new rule usually means one table entry in `internal/rules` or `internal/scan` plus a test.

A security property is enforced by tests: private key material never appears in any output format.

Contributions are welcome: open an issue describing the artifact or language you want covered.

## License

Apache-2.0, see [LICENSE](LICENSE).
