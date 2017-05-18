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

// Provides utility methods to generate X.509 certificates with different
// options. This implementation is Largely inspired from
// https://golang.org/src/crypto/tls/generate_cert.go.

package certmanager

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/golang/glog"
)

// CertOptions contains options for generating a new certificate.
type CertOptions struct {
	// Comma-separated hostnames and IPs to generate a certificate for.
	// This can also be set to the identity running the workload,
	// like kubernetes service account.
	Host string

	// The validity bounds of the issued certificate.
	NotBefore, NotAfter time.Time

	// Signer certificate (PEM encoded).
	SignerCert *x509.Certificate

	// Signer private key (PEM encoded).
	SignerPriv crypto.PrivateKey

	// Organization for this certificate.
	Org string

	// Whether this certificate should be a Cerificate Authority.
	IsCA bool

	// Whether this cerificate is self-signed.
	IsSelfSigned bool

	// Whether this certificate is for a client.
	IsClient bool

	// Whether this certificate is for a server.
	IsServer bool

	// The size of RSA private key to be generated.
	RSAKeySize int
}

const (
	// OID tag values for X.509 SAN field (see https://tools.ietf.org/html/rfc5280#appendix-A.2)
	tagDNSName = 2
	tagURI     = 6
	tarIP      = 7

	// The URI scheme for Istio identities.
	uriScheme = "spiffe"
)

// See http://www.alvestrand.no/objectid/2.5.29.17.html.
var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// GenCert generates a X.509 certificate with the given options.
func GenCert(options CertOptions) ([]byte, []byte) {
	// Generates a RSA private&public key pair.
	// The public key will be bound to the certficate generated below. The
	// private key will be used to sign this certificate in the self-signed
	// case, otherwise the certificate is signed by the signer private key
	// as specified in the CertOptions.
	priv, err := rsa.GenerateKey(rand.Reader, options.RSAKeySize)
	if err != nil {
		glog.Fatalf("RSA key generation failed with error %s.", err)
	}
	template := genCertTemplate(options)
	signerCert, signerKey := &template, crypto.PrivateKey(priv)
	if !options.IsSelfSigned {
		signerCert, signerKey = options.SignerCert, options.SignerPriv
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, signerCert, &priv.PublicKey, signerKey)
	if err != nil {
		glog.Fatalf("Could not create certificate (err = %s).", err)
	}

	// Returns the certificate that carries the RSA public key as well as
	// the corresponding private key.
	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	privDer := x509.MarshalPKCS1PrivateKey(priv)
	privPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privDer})
	return certPem, privPem
}

// LoadSignerCredsFromFiles loads the signer cert&key from the given files.
//   signerCertFile: cert file name
//   signerPrivFile: private key file name
func LoadSignerCredsFromFiles(signerCertFile string, signerPrivFile string) (*x509.Certificate, crypto.PrivateKey) {
	signerCertBytes, err := ioutil.ReadFile(signerCertFile)
	if err != nil {
		glog.Fatalf("Reading cert file failed with error %s.", err)
	}

	signerPrivBytes, err := ioutil.ReadFile(signerPrivFile)
	if err != nil {
		glog.Fatalf("Reading private key file failed with error %s.", err)
	}

	cert := ParsePemEncodedCertificate(signerCertBytes)
	key := parsePemEncodedKey(cert.PublicKeyAlgorithm, signerPrivBytes)

	return cert, key
}

func genSerialNum() *big.Int {
	serialNumLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNum, err := rand.Int(rand.Reader, serialNumLimit)
	if err != nil {
		glog.Fatalf("Failed to generate serial number: %s.", err)
	}
	return serialNum
}

// genCertTemplate generates a certificate template with the given options.
func genCertTemplate(options CertOptions) x509.Certificate {
	var keyUsage x509.KeyUsage
	if options.IsCA {
		// If the cert is a CA cert, the private key is allowed to sign other certificate.
		keyUsage = x509.KeyUsageCertSign
	} else {
		// Otherwise the private key is allowed for digital signature and key encipherment.
		keyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	}

	extKeyUsages := []x509.ExtKeyUsage{}
	if options.IsServer {
		extKeyUsages = append(extKeyUsages, x509.ExtKeyUsageServerAuth)
	}
	if options.IsClient {
		extKeyUsages = append(extKeyUsages, x509.ExtKeyUsageClientAuth)
	}

	template := x509.Certificate{
		SerialNumber: genSerialNum(),
		Subject: pkix.Name{
			Organization: []string{options.Org},
		},
		NotBefore:             options.NotBefore,
		NotAfter:              options.NotAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsages,
		BasicConstraintsValid: true,
	}

	if h := options.Host; len(h) > 0 {
		s := buildSubjectAltNameExtension(h)
		template.ExtraExtensions = []pkix.Extension{s}
	}

	if options.IsCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	return template
}

func buildSubjectAltNameExtension(host string) pkix.Extension {
	rawValues := []asn1.RawValue{}
	for _, h := range strings.Split(host, ",") {
		var rv *asn1.RawValue
		if ip := net.ParseIP(h); ip != nil {
			// Use the 4-byte representation of the IP address when possible.
			if eip := ip.To4(); eip != nil {
				ip = eip
			}
			rv = &asn1.RawValue{Tag: tarIP, Class: asn1.ClassContextSpecific, Bytes: ip}
		} else {
			tag := tagDNSName
			if strings.HasPrefix(h, uriScheme+":") {
				// Use URI for Istio identities
				tag = tagURI
			}
			rv = &asn1.RawValue{Tag: tag, Class: asn1.ClassContextSpecific, Bytes: []byte(h)}
		}
		rawValues = append(rawValues, *rv)
	}

	bs, err := asn1.Marshal(rawValues)
	if err != nil {
		glog.Fatalf("Failed to marshal the raw values for SAN field (err: %s)", err)
	}

	return pkix.Extension{Id: oidSubjectAltName, Value: bs}
}
