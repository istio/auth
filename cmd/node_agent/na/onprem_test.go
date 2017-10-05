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

package na

import (
	"testing"

	"google.golang.org/grpc"
)

func TestGetServiceIdentity(t *testing.T) {
	testCases := map[string]struct {
		config      *Config
		options     []grpc.DialOption
		filename    string
		expectedID  string
		expectedErr string
	}{
		"Good cert1": {
			config: &Config{
				CertChainFile:  "",
				KeyFile:        "",
				RootCACertFile: "",
			},
			filename:    "testdata/cert-chain-good.pem",
			expectedID:  "spiffe://cluster.local/ns/default/sa/default",
			expectedErr: "",
		},
		"Good cert2": {
			config: &Config{
				CertChainFile:  "",
				KeyFile:        "",
				RootCACertFile: "",
			},
			filename:    "testdata/cert-chain-good2.pem",
			expectedID:  "spiffe://cluster.local/ns/default/sa/default",
			expectedErr: "",
		},
		"Bad cert format": {
			config: &Config{
				CertChainFile:  "",
				KeyFile:        "",
				RootCACertFile: "",
			},
			filename:    "testdata/cert-chain-bad1.pem",
			expectedID:  "",
			expectedErr: "Invalid PEM encoded certificate",
		},
		"Wrong file": {
			config: &Config{
				CertChainFile:  "",
				KeyFile:        "",
				RootCACertFile: "",
			},
			filename:    "testdata/cert-chain-bad2.pem",
			expectedID:  "",
			expectedErr: "open testdata/cert-chain-bad2.pem: no such file or directory",
		},
	}

	for id, c := range testCases {
		onprem := onPremPlatformImpl{c.filename}
		identity, err := onprem.GetServiceIdentity()
		if c.expectedErr != "" {
			if err == nil {
				t.Errorf("%s: no error is returned.", id)
			}
			if err.Error() != c.expectedErr {
				t.Errorf("%s: incorrect error message: %s VS %s", id, err.Error(), c.expectedErr)
			}
		} else if identity != c.expectedID {
			t.Errorf("%s: GetServiceIdentity returns identity: %s. It should be %s.", id, identity, c.expectedID)
		}
	}
}

func TestGetDialOptions2(t *testing.T) {
	testCases := map[string]struct {
		config      *Config
		options     []grpc.DialOption
		expectedErr string
	}{
		"Good cert": {
			config: &Config{
				CertChainFile:  "testdata/cert.pem",
				KeyFile:        "testdata/priv.pem",
				RootCACertFile: "testdata/cert.ca.pem",
			},
			expectedErr: "",
		},
		"Loaing failure": {
			config: &Config{
				CertChainFile:  "testdata/cert.pem",
				KeyFile:        "testdata/priv_not_exist.pem",
				RootCACertFile: "testdata/cert.ca.pem",
			},
			expectedErr: "Cannot load key pair: open testdata/priv_not_exist.pem: no such file or directory",
		},
		"Loaing root cert failure": {
			config: &Config{
				CertChainFile:  "testdata/cert.pem",
				KeyFile:        "testdata/priv.pem",
				RootCACertFile: "testdata/cert_not_exist.ca.pem",
			},
			expectedErr: "Failed to read CA cert: open testdata/cert_not_exist.ca.pem: no such file or directory",
		},
	}

	for id, c := range testCases {
		onprem := onPremPlatformImpl{""}

		options, err := onprem.GetDialOptions(c.config)
		t.Logf("%v %v %v", id, options, err)

		for _, option := range options {
			t.Logf("%v", option)
		}

		if len(c.expectedErr) > 0 {
			if err == nil {
				t.Errorf("Succeeded. Error expected: %v", err)
			} else if err.Error() != c.expectedErr {
				t.Errorf("%s: incorrect error message: %s VS %s", id, err.Error(), c.expectedErr)
			}
		} else if err != nil {
			t.Errorf("Unexpected Error: %v", err)
		}
	}
}
