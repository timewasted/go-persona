// Copyright 2014 Ryan Rogers. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package persona

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"io/ioutil"
	"os"
	"strings"
)

// Error messages.
const (
	errEncryptedKeysNotSupported = "encrypted private keys are not currently supported."
	errInvalidAuthenticationUrl  = "authentication URL '%s' is invalid."
	errInvalidCertificateUrl     = "certificate URL '%s' is invalid."
	errInvalidDelegationHost     = "delegation host '%s' is invalid."
	errInvalidProvisioningUrl    = "provisioning URL '%s' is invalid."
	errInvalidSessionUrl         = "session URL '%s' is invalid."
	errKeyTypeNotSupported       = "'%s' is not a supported private key type."
	errNoValidPemBlock           = "'%s' does not contain a valid PEM block."
	errUnsupportedSessionStore   = "session store '%s' is not currently supported."
)

// SupportedPrivateKeyTypes is a list of the supported private key types.
//
// FIXME: DSA is only unsupported due to Go not having a builtin
// Parse<x>PrivateKey function that handles DSA keys.
//
// FIXME: ECDSA is not well documented in the Persona specs, so support is
// questionable.
var SupportedPrivateKeyTypes = map[string]bool{
	//	"DSA": true,
	"ECDSA": true,
	"RSA":   true,
}

// PrivateKeyTypeToAlgorithm is a human-to-Persona mapping of supported private
// key type algorithms.
//
// FIXME: ECDSA is not well documented in the Persona specs, so I'm not sure
// that "EC" is proper for ECDSA keys.
var PrivateKeyTypeToAlgorithm = map[string]string{
	"DSA":   "DS",
	"ECDSA": "EC",
	"RSA":   "RS",
}

// Configuration represents the Persona IdP configuration file.
type Configuration struct {
	PrivateKey struct {
		Type string `json:"type"`
		File string `json:"file"`
	} `json:"private-key"`
	Authentication struct {
		Url      string `json:"url"`
		Template string `json:"template"`
		Disabled bool   `json:"disabled"`
	} `json:"authentication"`
	Provisioning struct {
		Url      string `json:"url"`
		Template string `json:"template"`
		Disabled bool   `json:"disabled"`
	} `json:"provisioning"`
	Delegation struct {
		Delegate bool   `json:"delegate"`
		Host     string `json:"host"`
	} `json:"delegation"`
	Session struct {
		Url     string `json:"url"`
		Store   string `json:"store"`
		Backing string `json:"backing"`
	} `json:"session"`
	CertificateUrl string `json:"certificate-url"`
}

// LoadConfig loads a Configuration from the provided file.
func LoadConfig(filePath string) (config *Configuration, err error) {
	file, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	if err = decoder.Decode(&config); err != nil {
		return
	}

	if err = ValidateConfig(config); err != nil {
		return
	}

	return
}

// DecodeConfig loads a Configuration from the provided JSON structure.
func DecodeConfig(rawJson []byte) (config *Configuration, err error) {
	if err = json.Unmarshal(rawJson, &config); err != nil {
		return
	}
	if err = ValidateConfig(config); err != nil {
		return
	}

	return
}

// ValidateConfig validates that provided Configuration.
func ValidateConfig(config *Configuration) (err error) {
	if err = validateDelegation(config); err != nil {
		return
	}
	if config.Delegation.Delegate {
		return
	}

	if err = validatePrivateKey(config); err != nil {
		return
	}
	if err = validateAuthentication(config); err != nil {
		return
	}
	if err = validateProvisioning(config); err != nil {
		return
	}
	if err = validateSession(config); err != nil {
		return
	}
	if err = validateCertificateUrl(config); err != nil {
		return
	}

	return
}

func validateDelegation(config *Configuration) (err error) {
	if config.Delegation.Delegate {
		// TODO: Better validation.
		if len(config.Delegation.Host) == 0 {
			err = fmt.Errorf(errInvalidDelegationHost, config.Delegation.Host)
			return
		}
	}

	return
}

func validatePrivateKey(config *Configuration) (err error) {
	config.PrivateKey.Type = strings.ToUpper(config.PrivateKey.Type)
	if _, supported := SupportedPrivateKeyTypes[config.PrivateKey.Type]; !supported {
		err = fmt.Errorf(errKeyTypeNotSupported, config.PrivateKey.Type)
		return
	}

	keyFileContents, err := ioutil.ReadFile(config.PrivateKey.File)
	if err != nil {
		return
	}
	pemBlock, _ := pem.Decode(keyFileContents)
	if pemBlock == nil {
		err = fmt.Errorf(errNoValidPemBlock, config.PrivateKey.File)
		return
	}
	if x509.IsEncryptedPEMBlock(pemBlock) {
		err = fmt.Errorf(errEncryptedKeysNotSupported)
		return
	}

	// First try to parse it as a PKCS#8 private key.
	var privKey interface{}
	privKey, err = x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		// Not a PKCS#8 private key. Try something else.
		switch config.PrivateKey.Type {
		case "ECDSA":
			privKey, err = x509.ParseECPrivateKey(pemBlock.Bytes)
		case "RSA":
			privKey, err = x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
		}
		if err != nil {
			return
		}
	}
	err = SetPrivateKey(privKey)

	return
}

func validateAuthentication(config *Configuration) (err error) {
	// TODO: Better validation
	if len(config.Authentication.Url) == 0 {
		err = fmt.Errorf(errInvalidAuthenticationUrl, config.Authentication.Url)
		return
	}
	AuthenticationTemplateParams["URL"] = config.Authentication.Url
	if !config.Authentication.Disabled {
		AuthenticationTemplate, err = template.ParseFiles(config.Authentication.Template)
	}

	return
}

func validateProvisioning(config *Configuration) (err error) {
	// TODO: Better validation.
	if len(config.Provisioning.Url) == 0 {
		err = fmt.Errorf(errInvalidProvisioningUrl, config.Provisioning.Url)
		return
	}
	ProvisioningTemplateParams["URL"] = config.Provisioning.Url
	if !config.Provisioning.Disabled {
		ProvisioningTemplate, err = template.ParseFiles(config.Provisioning.Template)
	}

	return
}

func validateSession(config *Configuration) (err error) {
	// TODO: Better validation.
	if len(config.Session.Url) == 0 {
		err = fmt.Errorf(errInvalidSessionUrl, config.Session.Url)
		return
	}

	if sessionBacking == nil {
		switch config.Session.Store {
		case "sqlite":
			sessionBacking = &SQLiteBacking{}
			if err = sessionBacking.Open(config.Session.Backing); err != nil {
				return
			}
		default:
			err = fmt.Errorf(errUnsupportedSessionStore, config.Session.Store)
			return
		}
	}

	return
}

func validateCertificateUrl(config *Configuration) (err error) {
	// TODO: Better validation.
	if len(config.CertificateUrl) == 0 {
		err = fmt.Errorf(errInvalidCertificateUrl, config.CertificateUrl)
		return
	}

	return
}
