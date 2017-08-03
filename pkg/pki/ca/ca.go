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

package ca

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"istio.io/auth/pkg/pki"
)

const (
	// The size of a private key for a leaf certificate.
	keySize = 1024

	// The size of a private key for a self-signed Istio CA.
	caKeySize = 2048
)

// CertificateAuthority contains methods to be supported by a CA.
type CertificateAuthority interface {
	Generate(name, namespace string) (chain, key []byte)
	GetRootCertificate() []byte
}

// IstioCAOptions holds the configurations for creating an Istio CA.
type IstioCAOptions struct {
	CertChainBytes   []byte
	CertTTL          time.Duration
	SigningCertBytes []byte
	SigningKeyBytes  []byte
	RootCertBytes    []byte
}

// IstioCA generates keys and certificates for Istio identities.
type IstioCA struct {
	certTTL     time.Duration
	signingCert *x509.Certificate
	signingKey  crypto.PrivateKey

	certChainBytes []byte
	rootCertBytes  []byte
}

// NewSelfSignedIstioCA returns a new IstioCA instance using self-signed certificate.
func NewSelfSignedIstioCA(caCertTTL, certTTL time.Duration, org string) (*IstioCA, error) {
	now := time.Now()
	options := CertOptions{
		NotBefore:    now,
		NotAfter:     now.Add(caCertTTL),
		Org:          org,
		IsCA:         true,
		IsSelfSigned: true,
		RSAKeySize:   caKeySize,
	}
	pemCert, pemKey := GenCert(options)

	opts := &IstioCAOptions{
		CertTTL:          certTTL,
		SigningCertBytes: pemCert,
		SigningKeyBytes:  pemKey,
		RootCertBytes:    pemCert,
	}
	return NewIstioCA(opts)
}

// NewIstioCA returns a new IstioCA instance.
func NewIstioCA(opts *IstioCAOptions) (*IstioCA, error) {
	ca := &IstioCA{certTTL: opts.CertTTL}

	ca.certChainBytes = copyBytes(opts.CertChainBytes)
	ca.rootCertBytes = copyBytes(opts.RootCertBytes)

	var err error
	ca.signingCert, err = pki.ParsePemEncodedCertificate(opts.SigningCertBytes)
	if err != nil {
		return nil, err
	}

	ca.signingKey, err = pki.ParsePemEncodedKey(opts.SigningKeyBytes)
	if err != nil {
		return nil, err
	}

	if err := ca.verify(); err != nil {
		return nil, err
	}

	return ca, nil
}

// Generate returns a certificate chain and a key for the Istio identity defined by
// the name and the namespace.
func (ca IstioCA) Generate(name, namespace string) (chain, key []byte) {
	// Currently the domain is always set to "cluster.local" since we only
	// support in-cluster identities.
	id := fmt.Sprintf("%s://cluster.local/ns/%s/sa/%s", uriScheme, namespace, name)
	now := time.Now()
	options := CertOptions{
		Host:         id,
		NotBefore:    now,
		NotAfter:     now.Add(ca.certTTL),
		SignerCert:   ca.signingCert,
		SignerPriv:   ca.signingKey,
		IsCA:         false,
		IsClient:     true,
		IsSelfSigned: false,
		IsServer:     true,
		RSAKeySize:   keySize,
	}
	cert, key := GenCert(options)
	chain = append(cert, ca.certChainBytes...)

	return
}

// GetRootCertificate returns the PEM-encoded root certificate.
func (ca IstioCA) GetRootCertificate() []byte {
	return copyBytes(ca.rootCertBytes)
}

// verify that the cert chain, root cert and signing key/cert match.
func (ca IstioCA) verify() error {
	// Create another CertPool to hold the root.
	rcp := x509.NewCertPool()
	rcp.AppendCertsFromPEM(ca.rootCertBytes)

	icp := x509.NewCertPool()
	icp.AppendCertsFromPEM(ca.certChainBytes)

	opts := x509.VerifyOptions{
		Intermediates: icp,
		Roots:         rcp,
	}

	chains, err := ca.signingCert.Verify(opts)
	if len(chains) == 0 || err != nil {
		return errors.New(
			"invalid parameters: cannot verify the signing cert with the provided root chain and cert pool")
	}
	return nil
}

func copyBytes(src []byte) []byte {
	bs := make([]byte, len(src))
	copy(bs, src)
	return bs
}
