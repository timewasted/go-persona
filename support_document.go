// Copyright 2014 Ryan Rogers. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package persona

import (
	"encoding/json"
)

// SupportDocumentURL is the URL to the BrowserID support document.
const SupportDocumentURL = "/.well-known/browserid"

// SupportDocument is a BrowserID support document.
type SupportDocument struct {
	PublicKey      interface{} `json:"public-key"`
	Authentication string      `json:"authentication"`
	Provisioning   string      `json:"provisioning"`
}

// DelegatedSupportDocument is a BrowserID support document that delegates
// its duties to a different host.
type DelegatedSupportDocument struct {
	Authority string `json:"authority"`
}

var supportDocJson []byte

// GenerateSupportDocument reads the given configuration and returns a support
// document based on that configuration.
func GenerateSupportDocument(config *Configuration) (doc []byte, err error) {
	var supportDoc interface{}

	if config.Delegation.Delegate {
		supportDoc = DelegatedSupportDocument{
			Authority: config.Delegation.Host,
		}
	} else {
		var pubKeySupportDoc interface{}
		pubKeySupportDoc, err = privateKey.SupportDoc()
		if err != nil {
			return
		}

		supportDoc = SupportDocument{
			PublicKey:      pubKeySupportDoc,
			Authentication: config.Authentication.Url,
			Provisioning:   config.Provisioning.Url,
		}
	}

	supportDocJson, err = json.Marshal(supportDoc)
	if err != nil {
		return
	}

	doc = supportDocJson
	return
}
