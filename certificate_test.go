package main

import (
	"testing"
)

func Test_Certificate(t *testing.T) {
	cert := &Certificate{}
	t.Run("Generate Key", func(t *testing.T) {
		err := cert.createEllipticKey()
		if err != nil {
			t.Error(err)
		}
	})
	t.Run("Generate Test SelfSigned Certificate", func(t *testing.T) {
		err := cert.testCreateEllipticCert("test")
		if err != nil {
			t.Error(err)
		}
	})
	//	t.Run("Print Test Certificates", func(t *testing.T) {
	//		t.Log(cert.GetPEMKey())
	//		t.Log(cert.GetPEMCert())
	//	})
	t.Run("Get Certificate Expiration", func(t *testing.T) {
		expiration, err := cert.getCertificateExpiration()
		if err != nil {
			t.Error(err)
		}
		t.Log(timeToString(expiration))
	})
}
