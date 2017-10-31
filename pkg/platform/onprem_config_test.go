// Copyright 2017 Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package platform

import (
	"testing"
)

func TestOnpremConfigDefaultValue(t *testing.T) {
	c := &OnPremClientConfig{}

	flags := c.GetFlagSet()
	_ = flags.Parse([]string{})

	if c.RootCACertFile != flags.Lookup("root-cert").DefValue {
		t.Errorf("Onprem Default Config Flag: wrong default value. Expected %s, Actual %s",
			flags.Lookup("root-cert").DefValue, c.RootCACertFile)
	}

	if c.KeyFile != flags.Lookup("key").DefValue {
		t.Errorf("Onprem Default Config Flag: wrong default value. Expected %s, Actual %s",
			flags.Lookup("key").DefValue, c.KeyFile)
	}

	if c.CertChainFile != flags.Lookup("cert-chain").DefValue {
		t.Errorf("Onprem Default Config Flag: wrong default value. Expected %s, Actual %s",
			flags.Lookup("cert-chain").DefValue, c.CertChainFile)
	}
}

func TestOnPremFlag(t *testing.T) {
	c := &OnPremClientConfig{}

	flags := c.GetFlagSet()
	certLoc := "/etc/cert-chain.pem"
	keyLoc := "/etc/key.pem"
	rootLoc := "/etc/root-cert.pem"
	_ = flags.Parse([]string{
		"--cert-chain", certLoc,
		"--key", keyLoc,
		"--root-cert", rootLoc,
	})

	if c.CertChainFile != certLoc {
		t.Errorf("Onprem Config: wrong value. Actual %s, Expected %s", c.CertChainFile, certLoc)
	}

	if c.KeyFile != keyLoc {
		t.Errorf("Onprem Config: wrong value. Actual %s, Expected %s", c.KeyFile, keyLoc)
	}

	if c.RootCACertFile != rootLoc {
		t.Errorf("Onprem Config: wrong value. Actual %s, Expected %s", c.RootCACertFile, rootLoc)
	}
}
