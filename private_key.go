// Copyright 2014 Ryan Rogers. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package persona

import (
	"bytes"
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// Minimum supported key sizes.
const (
	MinKeySizeDSA = 2048
	MinKeySizeRSA = 2048
)

// Error messages.
const (
	errPrivateKeyTooSmall        = "private key is %d bits, should be at least %d bits."
	errPrivateKeyUndefined       = "private key is undefined."
	errUnsupportedEllipticCurve  = "unsupported elliptic curve."
	errUnsupportedPrivateKeyType = "unsupported private key type."
)

// SupportedEllipticCurves is a curve-to-label mapping of the supported
// elliptic curves.
var SupportedEllipticCurves = map[elliptic.Curve]string{
	elliptic.P224(): "P-224",
	elliptic.P256(): "P-256",
	elliptic.P384(): "P-384",
	elliptic.P521(): "P-521",
}

// PrivateKey represents the private key that is used for all of Persona's
// cryptographic operations.
type PrivateKey struct {
	key        interface{}
	supportDoc interface{}
}

// PublicKeyDSA represents a DSA public key.
type PublicKeyDSA struct {
	Algorithm string `json:"algorithm"`
	G         string `json:"g"`
	P         string `json:"p"`
	Q         string `json:"q"`
	Y         string `json:"y"`
}

// PublicKeyECDSA represents an ECDSA public key.
// FIXME: I'm not 100% certain that the parameters here are correct.
type PublicKeyECDSA struct {
	Algorithm string `json:"algorithm"`
	Curve     string `json:"crv"`
	X         string `json:"x"`
	Y         string `json:"y"`
}

// PublicKeyRSA represents an RSA public key.
type PublicKeyRSA struct {
	Algorithm string `json:"algorithm"`
	N         string `json:"n"`
	E         string `json:"e"`
}

var privateKey *PrivateKey

// SetPrivateKey uses the supplied private key.
func SetPrivateKey(key interface{}) error {
	privKey := &PrivateKey{
		key: key,
	}

	switch k := key.(type) {
	case *dsa.PrivateKey:
		if k.PublicKey.Q.BitLen() < MinKeySizeDSA {
			return fmt.Errorf(errPrivateKeyTooSmall, k.PublicKey.Q.BitLen(), MinKeySizeDSA)
		}

		privKey.supportDoc = PublicKeyDSA{
			Algorithm: PrivateKeyTypeToAlgorithm["DSA"],
			G:         fmt.Sprintf("%02x", k.PublicKey.G),
			P:         fmt.Sprintf("%02x", k.PublicKey.P),
			Q:         fmt.Sprintf("%02x", k.PublicKey.Q),
			Y:         fmt.Sprintf("%02x", k.PublicKey.Y),
		}
	case *ecdsa.PrivateKey:
		curve, supported := SupportedEllipticCurves[k.PublicKey.Curve]
		if !supported {
			return fmt.Errorf(errUnsupportedEllipticCurve)
		}

		privKey.supportDoc = PublicKeyECDSA{
			Algorithm: PrivateKeyTypeToAlgorithm["ECDSA"],
			Curve:     curve,
			X:         k.PublicKey.X.String(),
			Y:         k.PublicKey.Y.String(),
		}
	case *rsa.PrivateKey:
		if k.PublicKey.N.BitLen() < MinKeySizeRSA {
			return fmt.Errorf(errPrivateKeyTooSmall, k.PublicKey.N.BitLen(), MinKeySizeRSA)
		}

		privKey.supportDoc = PublicKeyRSA{
			Algorithm: PrivateKeyTypeToAlgorithm["RSA"],
			N:         k.PublicKey.N.String(),
			E:         fmt.Sprintf("%d", k.PublicKey.E),
		}
		k.Precompute()
	default:
		return fmt.Errorf(errUnsupportedPrivateKeyType)
	}

	privateKey = privKey
	return nil
}

// SupportDoc returns the public-key component of the support document.
func (pk *PrivateKey) SupportDoc() (interface{}, error) {
	if pk.key == nil {
		return nil, fmt.Errorf(errPrivateKeyUndefined)
	}

	return pk.supportDoc, nil
}

// IdCertHeader returns the header for an ID certificate.
func (pk *PrivateKey) IdCertHeader() (header IdentityCertificateHeader, err error) {
	if pk.key == nil {
		err = fmt.Errorf(errPrivateKeyUndefined)
		return
	}

	switch key := pk.key.(type) {
	case *dsa.PrivateKey:
		header = IdentityCertificateHeader{
			Alg: fmt.Sprintf("%s%d", PrivateKeyTypeToAlgorithm["DSA"], key.PublicKey.Q.BitLen()/8),
		}
	case *ecdsa.PrivateKey:
		header = IdentityCertificateHeader{
			Alg: fmt.Sprintf("%s%d", PrivateKeyTypeToAlgorithm["ECDSA"], key.PublicKey.X.BitLen()),
		}
	case *rsa.PrivateKey:
		header = IdentityCertificateHeader{
			Alg: fmt.Sprintf("%s%d", PrivateKeyTypeToAlgorithm["RSA"], key.PublicKey.N.BitLen()/8),
		}
	default:
		// This should not be reachable.
		panic(errUnsupportedPrivateKeyType)
	}

	return
}

// Sign signs the provided data.
func (pk *PrivateKey) Sign(data []byte) (signature []byte, err error) {
	if pk.key == nil {
		err = fmt.Errorf(errPrivateKeyUndefined)
		return
	}

	switch key := pk.key.(type) {
	case *dsa.PrivateKey:
		signature, err = signDSA(key, data)
	case *ecdsa.PrivateKey:
		signature, err = signECDSA(key, data)
	case *rsa.PrivateKey:
		signature, err = signRSA(key, data)
	default:
		// This should not be reachable.
		panic(errUnsupportedPrivateKeyType)
	}

	return
}

func signDSA(key *dsa.PrivateKey, data []byte) (sig []byte, err error) {
	r, s, err := dsa.Sign(rand.Reader, key, data)
	if err == nil {
		sig = bytes.Join([][]byte{r.Bytes(), s.Bytes()}, []byte(""))
	}
	return
}

func signECDSA(key *ecdsa.PrivateKey, data []byte) (sig []byte, err error) {
	r, s, err := ecdsa.Sign(rand.Reader, key, data)
	if err == nil {
		sig = bytes.Join([][]byte{r.Bytes(), s.Bytes()}, []byte(""))
	}
	return
}

func signRSA(key *rsa.PrivateKey, data []byte) (sig []byte, err error) {
	return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, data)
}
