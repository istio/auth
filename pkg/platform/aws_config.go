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

// AwsClientConfig ...
type AwsClientConfig struct {
	// Root CA cert file to validate the gRPC service in CA.
	RootCACertFile string
}

// GetFlagSet ...
func (c *AwsClientConfig) GetFlagSet() *flag.FlagSet {
	flags := flag.NewFlagSet("aws", flag.ContinueOnError)
	flags.StringVar(&c.RootCACertFile, "root-cert",
		"/etc/certs/root-cert.pem", "Root Certificate file")
	return flags
}
