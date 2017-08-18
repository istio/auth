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

package pki

import (
	"crypto/x509/pkix"
	"encoding/asn1"
)

// OIDSubjectAltName is the OID for Subject Alternative Name.
// See http://www.alvestrand.no/objectid/2.5.29.17.html.
var OIDSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// ExtractSANExtensions returns a list of SAN extensions from a given set of
// pkix.Extension.
func ExtractSANExtensions(exts []pkix.Extension) []pkix.Extension {
	sans := []pkix.Extension{}
	for _, ext := range exts {
		if ext.Id.Equal(OIDSubjectAltName) {
			sans = append(sans, ext)
		}
	}
	return sans
}
