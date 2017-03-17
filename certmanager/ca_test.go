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
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"testing"
)

func TestSelfSignedIstioCA(t *testing.T) {
	ca, err := NewSelfSignedIstioCA()
	if err != nil {
		t.Errorf("Failed to create a self-signed CA: %v", err)
	}

	name := "foo"
	namespace := "bar"

	cb, _ := ca.Generate(name, namespace)
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(cb)

	rootPool := x509.NewCertPool()
	rootPool.AppendCertsFromPEM(ca.GetRootCertificate())

	cert := parsePemEncodedCertificate(cb)
	chain, err := cert.Verify(x509.VerifyOptions{
		Intermediates: certPool,
		Roots:         rootPool,
	})
	if len(chain) == 0 || err != nil {
		t.Error("Failed to verify generated cert")
	}

	foundSAN := false
	for _, ee := range cert.Extensions {
		if ee.Id.Equal(oidSubjectAltName) {
			foundSAN = true
			id := fmt.Sprintf("istio:%s.%s.cluster.local", name, namespace)
			rv := asn1.RawValue{Tag: tagURI, Class: asn1.ClassContextSpecific, Bytes: []byte(id)}
			bs, err := asn1.Marshal([]asn1.RawValue{rv})
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(bs, ee.Value) {
				t.Errorf("SAN field does not match: %s is expected but actual is %s", bs, ee.Value)
			}
		}
	}
	if !foundSAN {
		t.Errorf("Generated certificate does not contain a SAN field")
	}
}

// Pass in unmatched chain and cert to make sure the `verify` method yeilds an error.
func TestInvalidIstioCAOptions(t *testing.T) {
	rootCert := `
-----BEGIN CERTIFICATE-----
MIIC8zCCAdugAwIBAgIRANxlBfqFFE029VJJikrWc0MwDQYJKoZIhvcNAQELBQAw
GDEWMBQGA1UEChMNcm9vdC5pc3Rpby5pbzAeFw0xNzAzMTcwNjE5MzdaFw0xODAz
MTcwNjE5MzdaMBgxFjAUBgNVBAoTDXJvb3QuaXN0aW8uaW8wggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDBLg1HIiYv2OntrX+c1OECzY1GTGqaxd1/ZCVJ
VonOICbluOwyOm3qFMCHyIKHFo0esxLb0Abe6gJFXsKzBP6uy6gHGzhUVNv6rgqc
s8n+z8tv5iZ9wI9B5OVTQrhk8ckRJJH4d/KUCuIRTuBFpgbPocBVCbXMQPpXEiev
lXWC2QawaBtqy0SgCBA20MdePwFQfNRaKMDsojI9fGFadE5uNm5XeIbfv1CMUJqW
SXFAiN3kFvaZnY2zSvqMk1z1fO6v1X0s0eEggOVSpZX6SqSlqAi1Qeh5D2JaHOc6
fJVm1Hgm0oFr7OZudR1fqbE3DyWUegTidOqass8GPrsJao39AgMBAAGjODA2MA4G
A1UdDwEB/wQEAwICBDATBgNVHSUEDDAKBggrBgEFBQcDATAPBgNVHRMBAf8EBTAD
AQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAR5CVl/lWgx48EItMMrL5dEF7XCqCGpTGQ
o9cYY49SzmJpB+4P2PTRxM450rwxd96onqxBtFOh4kg5S1mMIEMnfjLWiDYbDi5C
4ojH+vbngUgwnxhWrvUzVEW/KadFawk8QmujZ/YoprS6opJfdCzoz9+svzamxyRL
0smXcf7gSojDNoJj3mjM4V6xYwnHc//c0JCG4wwI0lFLncYAn64eNJ01j2TGt4Ld
dPZ+sgFbkqk5ysr/aBdeFmsVXV1gwIq9oDE1/1u3FpQG1uIo6ypCLjGezUclhlWA
/ypD9U276Kq4xHBYeY+5N+URGjWX4upCvxwlHw1/Mtsx5MqzLusg
-----END CERTIFICATE-----
	`

	// This signing cert is not signed by the root cert.
	signingCert := `
-----BEGIN CERTIFICATE-----
MIIDDzCCAfegAwIBAgIQekURFPcbMYGqJsZFBDJTJzANBgkqhkiG9w0BAQsFADAZ
MRcwFQYDVQQKEw5pbnRlci5pc3Rpby5pbzAeFw0xNzAzMTcwNjE5MzhaFw0xODAz
MTcwNjE5MzhaMBgxFjAUBgNVBAoTDWxlYWYuaXN0aW8uaW8wggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQC3YqJHcHyaubFLaxZLSCo1TvFjMx3p3wSUqdck
ZBMrYv0jYm9u5g27KZwST5Pn/U4o+smHLsWZHBe1+6x/rPJyapVXUrh5CZC3zqeA
Yh3O6PXNdqxFbAnPWTImrjFJST/fzAJQaQmrOySaIb95pIyL2fLArIJG70XYinJn
Rn1ATsxB7boPCnN5HplUmIwY6cn0s8vewD+WPYFw5OQCM+AqTEKI7w/vs21La2bZ
uQlwv2wAirWx+maTaszIXf6wfR5uGIZcA+f5hm/CfrojgxuP07uffcMfJ0QD3D8B
sXra4aw83gVvCLj5W0XqhX+q/CQiCtQj1BwSohqwu5ik7CFRAgMBAAGjVDBSMA4G
A1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAA
MB0GA1UdEQQWMBSGEmlzdGlvOnRlc3Qtc2VydmljZTANBgkqhkiG9w0BAQsFAAOC
AQEAOHeOZiBr0NZuGCedaZr9h2iZ/7mVWI9DOc1s+08yJUi8PHlCf3iM6DswclnI
KW9hGJH33qQ/yIGMDdBszOg4xrOEsycNhjFTkv3CNGyY+9EnSOfx84DJ2Gx2iNH2
a336nANg26Dg+/6JRvklt0Q0aTCinOFCNkjFhZhJrmt20Y3hm95JrWlInjVo4rzP
Lejoo1Mb9YWexOZyBFlpV+hrMCLsydf39H3USzU+zMmuZsMWMQehk1hR4kL6baiJ
f6oeWrQbZ1Mh4qNI8ddSQSSoNQIMGOaqSwEoRqPI++K7u1R3PiRWfdWFJ3vFPBmA
+cSwovW04OMkYzmSqpVoLNkZFQ==
-----END CERTIFICATE-----
	`

	signingKey := `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAt2KiR3B8mrmxS2sWS0gqNU7xYzMd6d8ElKnXJGQTK2L9I2Jv
buYNuymcEk+T5/1OKPrJhy7FmRwXtfusf6zycmqVV1K4eQmQt86ngGIdzuj1zXas
RWwJz1kyJq4xSUk/38wCUGkJqzskmiG/eaSMi9nywKyCRu9F2IpyZ0Z9QE7MQe26
DwpzeR6ZVJiMGOnJ9LPL3sA/lj2BcOTkAjPgKkxCiO8P77NtS2tm2bkJcL9sAIq1
sfpmk2rMyF3+sH0ebhiGXAPn+YZvwn66I4Mbj9O7n33DHydEA9w/AbF62uGsPN4F
bwi4+VtF6oV/qvwkIgrUI9QcEqIasLuYpOwhUQIDAQABAoIBADHhcEaCQEJNs/3R
mPTNIj3xxRK4erB8auCM+en6FoS8niIbyjed96oq/Tq1zoNRkQrwfBR7EmA9Fe34
EMmBn0ij2Q8xft/dTDHS0hjHl1gKYaGLX/xaEKkHl+6RfvJyLB+RfCenCmw64A/U
kiJiMaBwnejug1kMCDGIJuoUcEknLyKdyzFJmPux2uF0awvE4C+QYLEyBRRF9R8Q
wqa7uRA1tNY9yE3KfgVJEq/vj5v1XYU/IHANwoaLUlVJa5zFcxX/KlpqrycOtDG7
ZrAosWKuZckz+aRIFMHVNrx68s7yK83IcUckQnyqc82Z+XWcjyD/9AmrNE2vrZNZ
4ctZ88kCgYEAwXBQLI4/XeFoEv1tHGAQeit79NtffAYxao9Ws5lb7/MDfhL+uIsc
KVsSbGrV/m6bA629+QOq7yROIQIrNIxZB8O9A4imhXYfIEOexPStNXNXFFAx63ox
qe2wHHffO1/fVOJc9CZZtem738wxIUpDpqeajz1xsbEbm/tTaRiXiN8CgYEA8rHz
SnqbUMyMsnexck3q60CblonJgmqxkOgTuOAe+JM2bX2vVeB1NCUYJyOS8ZFHdLj7
0Svoxtijn520K3LpERKWGV03RtuNwF3+bQSQxXaXW79m6kgEx+2lXNk+DVyqH/pe
J6oWPpawbKM62SRYuFYPk1/GXmt2pqVx/gN5K88CgYEAvKa3WizEed9564NC5Th+
+VbtRgioX8F+cikm6nM3aZU8I7mMuBfbOC38ksXCu6fNAFJygqdkDmP+2kxOLKpv
rZXlAcxEcsaXZpTsA7OINSeulj374WZDhzEq3yi9Ch/fI967vtSkCzjPpFx00b2m
qqKspuPKvPw4K/B5EXcNWksCgYA1m3Dt5p8f/c6mLSIY6XUWebLkUZMdJ4wJQfn5
QCgXKA1Bqh1sjqPU3My0+HqguUJbWfDlhxlnsrqRqzf80OkCSGS3PYvULvLkpt5o
HjYMJ+HO9jw5S6cisi9wjtvR/8HkRl09zagUMxzNIlEBXbHrJbdTCji66mnO7YR8
YzAEqQKBgGCcCclv5XvmT1jRhyWsVxsrnVr3PGqcbJXo9nrt7GOpyBD4PxBiEwSJ
6ve/LVmG67aYTW689LzBrxasJ2lkAwLO7LxEvECJOStMNH9xNcpaiH5QPixhsoLA
yC/FqzgYraRYohKtO0Cpjual6wkoUN0cKUOFOTeSVnIKaShFE3pP
-----END RSA PRIVATE KEY-----
	`

	opts := &IstioCAOptions{
		SigningCertBytes: []byte(signingCert),
		SigningKeyBytes:  []byte(signingKey),
		RootCertBytes:    []byte(rootCert),
	}

	ca, err := NewIstioCA(opts)
	if ca != nil || err == nil {
		t.Errorf("Expecting an error but an Istio CA is wrongly instantiated")
	}

	errMsg := "invalid parameters: cannot verify the signing cert with the provided root chain and cert pool"
	if err.Error() != errMsg {
		t.Errorf("Unexpected error message: expecting '%s' but the actual is '%s'", errMsg, err.Error())
	}
}
