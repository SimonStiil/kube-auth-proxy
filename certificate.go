package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierros "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Good documentation:
// https://gist.github.com/samuel/8b500ddd3f6118d052b5e6bc16bc4c09
// https://gist.github.com/gambol99/d55afd69217b8e2dd727be99f0a20e7d

type Certificate struct {
	*ecdsa.PrivateKey
	*x509.Certificate
	name     string
	key      []byte
	cert     []byte
	lastUsed time.Time
}

const (
	Certificate_Common_Name  = "/CN="
	Certificate_Organization = "/O="
	// Types for PEM Conversion
	TYPE_PRIV_KEY            = "EC PRIVATE KEY"
	TYPE_CERTIFICATE_REQUEST = "CERTIFICATE REQUEST"
	TYPE_CERTIFICATE         = "CERTIFICATE"

	//Secret key for Certificate
	SECRET_KEY_KEY              = "key"
	SECRET_KEY_CERT             = "cert"
	LABLE_KEY                   = "auth.stiil.dk/clientcertificates"
	LABLE_KEY_GENERATED         = "generated"
	LABLE_VERSION               = "auth.stiil.dk/version"
	LABLE_EXPIRATION            = "auth.stiil.dk/expiration"
	LABLE_EXPIRATION_UNASSIGNED = "unknown"
	// Time format compliant with kubernetes labels
	LABEL_TIME_FORMAT = "2006-01-02T15.04.05Z07.00"
	// Label validator
	LABEL_TIME_VALIDATOR                = "(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?"
	CERTIFICATE_ABOUTTOEXPIRE_THRESHOLD = time.Hour
)

// Main Certificate handler function.
// Get secret, and Convert if available, if not expired use, otherwire reissue a new certificate
func NewClientAuth(client *KubeClient, name string) (*Certificate, error) {
	// Get Secret
	// TODO : Should have some caching
	secret, err := client.GetSecret(name)
	if apierros.IsNotFound(err) {
		log.Printf("No secret found for user %v creating new certificate\n", name)
		return NewCertificate(client, name)
	} else {
		// Check for Expiration
		val, ok := secret.Labels[LABLE_EXPIRATION]
		expired := !ok || val == LABLE_EXPIRATION_UNASSIGNED
		if !expired {
			expiration, err := stringToTime(secret.Labels[LABLE_EXPIRATION])
			expired = time.Now().Add(CERTIFICATE_ABOUTTOEXPIRE_THRESHOLD).After(expiration) || err != nil
		}
		if expired {
			client.DeleteSecret(name)
			log.Printf("Secret found for user %v, but expired, creating new certificate\n", name)
			return NewCertificate(client, name)
		}
		log.Printf("Secret for user %v reading certificate\n", name)
		return CertificateFromSecret(secret)
	}
}

func CertificateFromSecret(secret *corev1.Secret) (*Certificate, error) {
	// Create a certificate from a Secret if is available
	// Append content to New Certificate object
	cert := &Certificate{
		name: secret.Name,
		key:  secret.Data[SECRET_KEY_KEY],
		cert: secret.Data[SECRET_KEY_CERT],
	}
	// Decode the needed information and add it to the object
	pemPrivkey, _ := pem.Decode(cert.key)
	if pemPrivkey.Type == TYPE_PRIV_KEY {
		var err error
		// Pem Private key for reissuing
		cert.PrivateKey, err = x509.ParseECPrivateKey(pemPrivkey.Bytes)
		if err != nil {
			return nil, err
		}
		cert.UpdateLastUsed()
		return cert, nil
	} else {
		return nil, fmt.Errorf("wrong keytype from secret : %v", pemPrivkey.Type)
	}
}

// Full function for certificate creation
func NewCertificate(client *KubeClient, name string) (*Certificate, error) {
	cert := &Certificate{name: name}
	err := cert.createEllipticKey()
	if err != nil {
		return nil, err
	}
	csrbytes, err := cert.createEllipticCSR(name)
	if err != nil {
		return nil, err
	}
	_, err = client.CreateCSR(name, csrbytes)
	if err != nil {
		return nil, err
	}
	err = client.ApproveCSR(name)
	if err != nil {
		return nil, err
	}
	cert.cert, err = client.GetSignedCertificate(name)
	if err != nil {
		return nil, err
	}
	_, err = client.CreateSecret(name, cert.makeSecret(name))
	if err != nil {
		return nil, err
	}
	err = client.DeleteCSR(name)
	if err != nil {
		log.Printf("Warning: Issue deleting CSR: %+v", err)
	}
	cert.UpdateLastUsed()
	return cert, err
}

func (cert *Certificate) UpdateLastUsed() {
	cert.lastUsed = time.Now()
}

func (cert *Certificate) Stale() bool {
	return cert.lastUsed.Add(time.Minute * 30).Before(time.Now())
}

func (cert *Certificate) GetTLSCert() (tls.Certificate, error) {
	// Get a tls.Certificate from this
	return tls.X509KeyPair(cert.cert, cert.key)
}

func (cert *Certificate) makeSecret(name string) *corev1.Secret {
	// Create secret description from Certificate
	// Create data map
	data := make(map[string][]byte)
	data[SECRET_KEY_KEY] = cert.key
	data[SECRET_KEY_CERT] = cert.cert
	// Get Label content
	decodedCert, err := cert.getCertificateNotAfterTime()
	expiration := LABLE_EXPIRATION_UNASSIGNED
	if err == nil {
		expiration = timeToString(decodedCert)
	} else {
		log.Printf("Error reading certificate date: %+v", err)
	}
	//Create description
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				LABLE_KEY:        LABLE_KEY_GENERATED,
				LABLE_VERSION:    genereateHash(data),
				LABLE_EXPIRATION: expiration,
			},
		},
		Data: data,
	}
}

func (cert *Certificate) createEllipticKey() error {
	var err error
	// Generate an elipticcurve private key using Prime256
	cert.PrivateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	// Convert Privatekey to DER
	privkey, err := x509.MarshalECPrivateKey(cert.PrivateKey)
	// Convert DER to PEM
	cert.key = pem.EncodeToMemory(&pem.Block{Type: TYPE_PRIV_KEY, Bytes: privkey})
	if err != nil {
		return err
	}
	return nil
}

// --- Testing Only ---
func publicKey(priv interface{}) interface{} {
	// Still don't understand why this would be needed.
	// But just using cert.PrivateKey.PublicKey made CreateCertificate fail below
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		// Only this part should ever be used
		return &k.PublicKey
	default:
		return nil
	}
}

func (cert *Certificate) testCreateEllipticCert(user string, groups ...string) error {
	// Create an testing certificate for testing functions in certificate_test
	// (Could be used for selfsigned certificate in other projects)
	subject := new(pkix.Name)
	if len(user) > 0 {
		subject.CommonName = user
	}
	if len(groups) > 0 {
		subject.Organization = groups
	}
	// Create a template for the certificaten
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               *subject,
		NotBefore:             time.Now().Add(time.Hour * -5),
		NotAfter:              time.Now().Add(time.Hour * 24 * 5),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	// Create the actual certificate in DER
	testCertificate, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(cert.PrivateKey), cert.PrivateKey)
	if err != nil {
		return err
	}
	// Convert DER to PEM
	cert.cert = pem.EncodeToMemory(&pem.Block{
		Type: TYPE_CERTIFICATE, Bytes: testCertificate,
	})
	return nil
}

func (cert *Certificate) GetPEMCert() string {
	// Get the PEM Cert for printing
	return string(cert.cert)
}

func (cert *Certificate) GetPEMKey() string {
	// Get the PEM Key for printing
	return string(cert.key)
}

// --- End Testing Only ---

func (cert *Certificate) createEllipticCSR(user string, groups ...string) ([]byte, error) {
	// Create a Certificate Signing request for signing in the KubeAPIServer
	subject := new(pkix.Name)
	// Create subject for User and groups as \CN and \O.
	// See https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#create-private-key
	if len(user) > 0 {
		subject.CommonName = user
	}
	if len(groups) > 0 {
		subject.Organization = groups
	}
	// Very simple template having only subject
	template := x509.CertificateRequest{Subject: *subject}
	// Create the signing request in DER
	csrCertificate, err := x509.CreateCertificateRequest(rand.Reader, &template, cert.PrivateKey)
	if err != nil {
		return nil, err
	}
	// Convert DER to PEM
	pemCSR := pem.EncodeToMemory(&pem.Block{
		Type: TYPE_CERTIFICATE_REQUEST, Bytes: csrCertificate,
	})
	return pemCSR, nil
}

func (cert *Certificate) getCertificate() (*x509.Certificate, error) {
	// Get x509 certificae from PEM
	if cert.Certificate != nil {
		return cert.Certificate, nil
	}
	// Decode the PEM encaptulation
	pemPublicCert, _ := pem.Decode(cert.cert)
	if pemPublicCert.Type == TYPE_CERTIFICATE {
		// Only caring about CERTIFICATE type
		// parce the certificate bytes
		return x509.ParseCertificate(pemPublicCert.Bytes)
	} else {
		return nil, fmt.Errorf("wrong keytype from secret : %v", pemPublicCert.Type)
	}
}
func (cert *Certificate) getCertificateNotAfterTime() (*time.Time, error) {
	// Firct convert the certificate from PEM to x509 then read NotAfter
	decodedeCert, err := cert.getCertificate()
	if err != nil {
		return nil, err
	}
	return &decodedeCert.NotAfter, nil
}
func (cert *Certificate) IsAboutToExpire() bool {
	// Find is a certificate about to expire based on threshold
	expiration, err := cert.getCertificateNotAfterTime()
	if err != nil {
		return true
	}
	return time.Now().Add(CERTIFICATE_ABOUTTOEXPIRE_THRESHOLD).After(*expiration)
}

// Some Helper Time to String and String to Time functions
func timeToString(t *time.Time) string {
	return t.Format(LABEL_TIME_FORMAT)
}
func stringToTime(s string) (time.Time, error) {
	return time.Parse(LABEL_TIME_FORMAT, s)
}
