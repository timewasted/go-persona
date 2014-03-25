// Copyright 2014 Ryan Rogers. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

type configuration struct {
	Servers []struct {
		Addr     string `json:"addr"`
		KeyPairs []struct {
			Cert string `json:"cert"`
			Key  string `json:"key"`
		} `json:"key-pairs"`
	} `json:"servers"`
}

func loadConfig(filePath string) (config *configuration, err error) {
	file, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	if err = decoder.Decode(&config); err != nil {
		return
	}

	if err = validateConfig(config); err != nil {
		return
	}

	return
}

func validateConfig(config *configuration) (err error) {
	if len(config.Servers) == 0 {
		return fmt.Errorf("at least one server must be defined.")
	}

	var certContents, keyContents []byte
	for serverIndex, server := range config.Servers {
		// Validate Addr.
		// TODO: Better validation.
		if len(server.Addr) == 0 {
			return fmt.Errorf("server address '%s' is invalid.", server.Addr)
		}

		// Validate KeyPairs.
		if len(server.KeyPairs) == 0 {
			return fmt.Errorf("server '%s' must have at least one key pair defined.", server.Addr)
		}
		for keyIndex, keyPair := range server.KeyPairs {
			certContents, err = ioutil.ReadFile(keyPair.Cert)
			if err != nil {
				return
			}
			keyContents, err = ioutil.ReadFile(keyPair.Key)
			if err != nil {
				return
			}

			config.Servers[serverIndex].KeyPairs[keyIndex].Cert = string(certContents)
			config.Servers[serverIndex].KeyPairs[keyIndex].Key = string(keyContents)
		}
	}

	return
}
