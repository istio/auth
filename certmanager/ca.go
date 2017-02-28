package certmanager

// CertificateAuthority contains methods to be supported by a CA.
type CertificateAuthority interface {
	Generate(name string) (key, cert []byte)
}
