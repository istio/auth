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

package certmanager

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/golang/glog"
)

func parsePemEncodedCertificate(pb []byte) *x509.Certificate {
	b, _ := pem.Decode(pb)
	if b == nil {
		glog.Fatalf("Invalid PEM encoding: %s", pb)
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		glog.Fatalf("Failed to parse X.509 certificate (error: %s)", err)
	}
	return cert
}

func parsePemEncodedPrivateKey(pb []byte) *rsa.PrivateKey {
	b, _ := pem.Decode(pb)
	if b == nil {
		glog.Fatalf("Invalid PEM encoding: %s", pb)
	}
	key, err := x509.ParsePKCS1PrivateKey(b.Bytes)
	if err != nil {
		glog.Fatalf("Failed to parse RSA private key (error: %s)", err)
	}
	return key
}
