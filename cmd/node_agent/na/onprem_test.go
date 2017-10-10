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
	"bytes"
	"testing"
)

func TestGetServiceIdentity(t *testing.T) {
	testCases := map[string]struct {
		filename    string
		expectedID  string
		expectedErr string
	}{
		"Good cert1": {
			filename:    "testdata/cert-chain-good.pem",
			expectedID:  "spiffe://cluster.local/ns/default/sa/default",
			expectedErr: "",
		},
		"Good cert2": {
			filename:    "testdata/cert-chain-good2.pem",
			expectedID:  "spiffe://cluster.local/ns/default/sa/default",
			expectedErr: "",
		},
		"Bad cert format": {
			filename:    "testdata/cert-chain-bad1.pem",
			expectedID:  "",
			expectedErr: "Invalid PEM encoded certificate",
		},
		"Wrong file": {
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

func TestGetAgentCredential(t *testing.T) {
	testCases := map[string]struct {
		filename      string
		expectedBytes []byte
		expectedErr   string
	}{
		"Existing cert": {
			filename: "testdata/cert-chain-good2.pem",
			expectedBytes: []byte(`-----BEGIN CERTIFICATE-----
MIICJDCCAY2gAwIBAgIRAISsfIdj+hB82Gzeg+hKaTMwDQYJKoZIhvcNAQELBQAw
GzEZMBcGA1UECgwQaW50ZXJtZWRpYXRlX29yZzAeFw0xNzA4MzAyMTA0NDlaFw0x
NzA4MzAyMjA0NDlaMAsxCTAHBgNVBAoTADCBnzANBgkqhkiG9w0BAQEFAAOBjQAw
gYkCgYEAvh7gHHpZ55TwnPz7XEITzur76h0IbvK4sUAeDpcl4rnLE7CqUqLkr7gN
M2KqTrWziQvK4ylGjxtY4VVu54Bek6nGxnu3QVGUqqRQrFIGCk7zXsfkkaR/RaCy
1yUPzl3BBuarfI5tpswKMTX2Vs9W3HKLfybdBDSZTh9EJ7puHKcCAwEAAaN4MHYw
DgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAM
BgNVHRMBAf8EAjAAMDcGA1UdEQQwMC6GLHNwaWZmZTovL2NsdXN0ZXIubG9jYWwv
bnMvZGVmYXVsdC9zYS9kZWZhdWx0MA0GCSqGSIb3DQEBCwUAA4GBAGsN2+8fOwts
TOI3vkuSlhCeLwV6Kj2Qby17ABabDMIPGMa8Z5DPesUHsO3alXEPDfKveHHJlUHW
iASwRa/mTqJhPmlgLMkj6yveE0WN8ElTNoNOv9kqnuZYtvi9tpds+Hhkc+1+ZqXm
ez8W3DDgwfvHQOzz9qnTQBxHcKktLA62
-----END CERTIFICATE-----
`),
			expectedErr: "",
		},
		"Missing cert": {
			filename:      "testdata/fake-cert.pem",
			expectedBytes: nil,
			expectedErr:   "Failed to read cert file: testdata/fake-cert.pem",
		},
	}

	for id, c := range testCases {
		onprem := onPremPlatformImpl{c.filename}
		cred, err := onprem.GetAgentCredential()
		if c.expectedErr != "" {
			if err == nil {
				t.Errorf("%s: no error is returned.", id)
			}
			if err.Error() != c.expectedErr {
				t.Errorf("%s: incorrect error message: %s VS %s", id, err.Error(), c.expectedErr)
			}
		} else if !bytes.Equal(cred, c.expectedBytes) {
			t.Errorf("%s: GetAgentCredential returns bytes: %s. It should be %s.", id, cred, c.expectedBytes)
		}
	}
}
