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
	flag "github.com/spf13/pflag"
)

// OnPremClientConfig ...
type OnPremClientConfig struct {
	// Root CA cert file to validate the gRPC service in CA.
	RootCACertFile string
	// The private key file
	KeyFile string
	// The cert chain file
	CertChainFile string
}

// GetFlagSet ...
func (c *OnPremClientConfig) GetFlagSet() *flag.FlagSet {
	flags := flag.NewFlagSet("onprem", flag.ContinueOnError)
	flags.StringVar(&c.CertChainFile, "cert-chain",
		"/etc/certs/cert-chain.pem", "Node Agent identity cert file")
	flags.StringVar(&c.KeyFile,
		"key", "/etc/certs/key.pem", "Node identity private key file")
	flags.StringVar(&c.RootCACertFile, "root-cert",
		"/etc/certs/root-cert.pem", "Root Certificate file")
	return flags
}
