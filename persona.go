// Copyright 2014 Ryan Rogers. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package persona implements a Mozilla Persona Identity Provider.
package persona

import (
	"encoding/json"
	"html/template"
	"io/ioutil"
	"net/http"
)

// Templates used to render the authentication and provisioning pages.
var (
	AuthenticationTemplate *template.Template
	ProvisioningTemplate   *template.Template
)

// Parameters passed to the authentication and provisioning templates.
var (
	AuthenticationTemplateParams = make(map[string]interface{})
	ProvisioningTemplateParams   = make(map[string]interface{})
)

// RequestCheckSession represents the body of a CheckSession request.
type RequestCheckSession struct {
	Email string `json:"email"`
}

// RequestGenerateCertificate represents the body of a GenerateCertificate
// request.
type RequestGenerateCertificate struct {
	Email     string            `json:"email"`
	PublicKey map[string]string `json:"public-key"`
	Duration  int               `json:"duration,string"`
}

// BrowserID responds with the BrowserID support document.
func BrowserID(w http.ResponseWriter, r *http.Request) {
	if r.Method != "HEAD" && r.Method != "GET" {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", ContentTypeJson)
	w.Write(supportDocJson)

	/*
		// FIXME: Remove this debugging code.
		cert, err := identityCertificate(RequestGenerateCertificate{
			Email: "ryan@timewasted.me",
			PublicKey: map[string]string{
				"algorithm": "RS",
				"n":         "15498874758090276039465094105837231567265546373975960480941122651107772824121527483107402353899846252489837024870191707394743196399582959425513904762996756672089693541009892030848825079649783086005554442490232900875792851786203948088457942416978976455297428077460890650409549242124655536986141363719589882160081480785048965686285142002320767066674879737238012064156675899512503143225481933864507793118457805792064445502834162315532113963746801770187685650408560424682654937744713813773896962263709692724630650952159596951348264005004375017610441835956073275708740239518011400991972811669493356682993446554779893834303",
				"e":         "65537",
			},
			Duration: 86400,
		})
		if err == nil {
			w.Header().Set("Content-Type", ContentTypePlain)
			w.Write([]byte(cert))
		}
	*/
}

// Authentication responds with the authentication page template.
func Authentication(w http.ResponseWriter, r *http.Request) {
	if r.Method != "HEAD" && r.Method != "GET" {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", ContentTypeHtml)
	AuthenticationTemplate.Execute(w, AuthenticationTemplateParams)
}

// Provisioning responds with the provisioning page template.
func Provisioning(w http.ResponseWriter, r *http.Request) {
	if r.Method != "HEAD" && r.Method != "GET" {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", ContentTypeHtml)
	ProvisioningTemplate.Execute(w, ProvisioningTemplateParams)
}

// CheckSession responds with StatusOK (200) if the given user has a valid
// session, or StatusUnauthorized (401) if not. On error, it responds with
// StatusInternalServerError (500).
func CheckSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	if sessionBacking == nil {
		http.Error(w, errSessionBackingUndefined, http.StatusInternalServerError)
		return
	}

	// TODO: Support multipart forms as well (or instead of)?
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var sessionRequest RequestCheckSession
	if err = json.Unmarshal(body, &sessionRequest); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	hasSession, err := sessionBacking.HasSession(sessionRequest.Email)
	if !hasSession {
		http.Error(w, "User is not authorized.", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", ContentTypePlain)
	w.WriteHeader(http.StatusOK)
}

// GenerateCertificate responds with a signed identity certificate on success.
// On error, it responds with StatusInternalServerError (500).
func GenerateCertificate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	if sessionBacking == nil {
		http.Error(w, errSessionBackingUndefined, http.StatusInternalServerError)
		return
	}

	// TODO: Support multipart forms as well (or instead of)?
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var certificateRequest RequestGenerateCertificate
	if err = json.Unmarshal(body, &certificateRequest); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	idCert, err := identityCertificate(certificateRequest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", ContentTypeJson)
	w.Write([]byte(idCert))
}
