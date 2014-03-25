// Copyright 2014 Ryan Rogers. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/timewasted/go-persona"
	"github.com/timewasted/go-server"
)

var (
	personaConfigPath = flag.String("persona-config", "./persona-config.json", "Path to the persona configuration file.")
	serverConfigPath  = flag.String("server-config", "./server-config.json", "Path to the web server configuration file.")
)

var signalChan = make(chan os.Signal, 1)
var webServer *server.Server

func init() {
	signal.Notify(signalChan, os.Interrupt, syscall.SIGQUIT, syscall.SIGTERM)
}

func main() {
	var err error

	personaConfig, err := persona.LoadConfig(*personaConfigPath)
	if err != nil {
		log.Fatalln("Failed to load the Persona configuration:", err)
	}
	defer persona.CloseSessionBacking()
	_, err = persona.GenerateSupportDocument(personaConfig)
	if err != nil {
		log.Fatalln("Failed to generate support document:", err)
	}

	serverConfig, err := loadConfig(*serverConfigPath)
	if err != nil {
		log.Fatalln("Failed to load the server configuration:", err)
	}

	webServer = server.New()
	for serverIndex, server := range serverConfig.Servers {
		if err = webServer.Listen(server.Addr); err != nil {
			log.Fatalf("Failed to create listener for address '%s': %s\n", server.Addr, err)
		}
		for keyIndex, keyPair := range server.KeyPairs {
			if err = webServer.AddTLSCertificate([]byte(keyPair.Cert), []byte(keyPair.Key)); err != nil {
				log.Fatalf("Failed to add TLS certificate %d to '%s': %s\n", keyIndex, server.Addr, err)
			}
			serverConfig.Servers[serverIndex].KeyPairs[keyIndex].Cert = ""
			serverConfig.Servers[serverIndex].KeyPairs[keyIndex].Key = ""
		}
	}

	webServer.HandleFunc(persona.SupportDocumentURL, persona.CompressResponse(persona.BrowserID))
	if !personaConfig.Authentication.Disabled {
		webServer.HandleFunc(personaConfig.Authentication.Url, persona.CompressResponse(persona.Authentication))
	}
	if !personaConfig.Provisioning.Disabled {
		webServer.HandleFunc(personaConfig.Provisioning.Url, persona.CompressResponse(persona.Provisioning))
	}
	webServer.HandleFunc(personaConfig.Session.Url, persona.CheckSession)
	webServer.HandleFunc(personaConfig.CertificateUrl, persona.GenerateCertificate)
	webServer.Serve()

	for {
		<-signalChan
		break
	}
	log.Println("Exiting.")
}
