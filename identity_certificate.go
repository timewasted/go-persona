// Copyright 2014 Ryan Rogers. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package persona

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// idCertExpMaxDuration is the max duration, in seconds, for all issued ID
// certificates.
const idCertExpMaxDuration = SessionMaxDuration

// idCertIatFuzzDuration is the time, in seconds, to fuzz the issued-at time
// for all issued ID certificates.
const idCertIatFuzzDuration = -10

// Error messages.
const (
	errWriteExpectedBytes = "expected to write %d bytes, instead wrote %d."
)

// IdentityCertificateHeader is the header for an identity certificate.
type IdentityCertificateHeader struct {
	Alg string `json:"alg"`
}

// IdentityCertificatePrincipal is the principal element of an identity
// certificate.
type IdentityCertificatePrincipal struct {
	Email string `json:"email"`
}

// IdentityCertificate represents an identity certificate.
type IdentityCertificate struct {
	Iat       int64                        `json:"iat,string"`
	Exp       int64                        `json:"exp,string"`
	Iss       string                       `json:"iss"`
	PublicKey map[string]string            `json:"public-key"`
	Principal IdentityCertificatePrincipal `json:"principal"`
}

func identityCertificate(req RequestGenerateCertificate) (cert string, err error) {
	var output bytes.Buffer
	b64Encoder := base64.NewEncoder(base64.URLEncoding, &output)
	defer b64Encoder.Close()
	jsonEncoder := json.NewEncoder(b64Encoder)

	// Create the ID certificate header.
	idCertHeader, err := privateKey.IdCertHeader()
	if err != nil {
		return
	}
	if err = jsonEncoder.Encode(idCertHeader); err != nil {
		return
	}
	if err = output.WriteByte('.'); err != nil {
		return
	}

	// Create the ID certificate.
	if req.Duration > idCertExpMaxDuration {
		req.Duration = idCertExpMaxDuration
	}
	idCert := IdentityCertificate{
		Iat:       time.Now().Add(idCertIatFuzzDuration).Unix() * int64(time.Millisecond),
		Exp:       time.Now().Add(idCertExpMaxDuration).Unix() * int64(time.Millisecond),
		Iss:       "timewasted.me", // FIXME: Don't hardcode the issuer
		PublicKey: req.PublicKey,
		Principal: IdentityCertificatePrincipal{
			Email: req.Email,
		},
	}
	if err = jsonEncoder.Encode(idCert); err != nil {
		return
	}

	// Sign the concatenated header/certificate.
	var n int
	h := sha256.New()
	n, err = h.Write(output.Bytes())
	if err != nil {
		return
	}
	if n != output.Len() {
		err = fmt.Errorf(errWriteExpectedBytes, output.Len(), n)
		return
	}
	sig, err := privateKey.Sign(h.Sum(nil))
	if err != nil {
		return
	}

	// Append the signature to the ID certificate.
	if err = output.WriteByte('.'); err != nil {
		return
	}
	n, err = b64Encoder.Write(sig)
	if err != nil {
		return
	}
	if n != len(sig) {
		err = fmt.Errorf(errWriteExpectedBytes, len(sig), n)
		return
	}

	cert = output.String()
	return
}
