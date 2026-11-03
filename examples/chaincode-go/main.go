//go:build ignore

// Example: Fabric chaincode (Go) with several kinds of cryptography.
// This file is scanner input only; it is excluded from the build.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type AssetContract struct {
	contractapi.Contract
}

// SignReceipt signs a transfer receipt with a freshly generated key.
func (c *AssetContract) SignReceipt(ctx contractapi.TransactionContextInterface, payload []byte) ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payload)
	return ecdsa.SignASN1(rand.Reader, key, digest[:])
}

// LegacyEscrowKey still creates an RSA key for an old escrow integration.
func (c *AssetContract) LegacyEscrowKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 1024)
}

// Checksum uses SHA-1 for a legacy interface.
func (c *AssetContract) Checksum(payload []byte) []byte {
	h := sha1.New()
	h.Write(payload)
	return h.Sum(nil)
}
