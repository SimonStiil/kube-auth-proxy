package main

import (
	"log"
	"sync"
	"time"
)

type CertificateStorage struct {
	storage *sync.Map
}

func NewCertificateStorage() *CertificateStorage {
	cs := &CertificateStorage{storage: new(sync.Map)}
	go cs.cleanupTask()
	return cs
}

func (CS *CertificateStorage) GetCertificate(client *KubeClient, name string) (*Certificate, error) {
	cert, ok := CS.storage.Load(name)
	log.Printf("Unable to read certificate for user: %v", ok)
	if ok {
		certOfType, ok := cert.(*Certificate)
		log.Printf("Unable to cast *Certificate for user: %v", ok)
		if ok {
			certOfType.UpdateLastUsed()
			log.Println("Using cached certificate")
			return certOfType, nil
		}
	}
	certOfType, err := NewClientAuth(client, name)
	if err != nil {
		return nil, err
	}
	CS.storage.Store(name, certOfType)
	return certOfType, nil
}
func (CS *CertificateStorage) cleanupTask() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		var count, deleted uint32
		CS.storage.Range(func(key, value any) bool {
			count += 1
			if key != nil && value != nil {
				certOfType, ok := value.(*Certificate)
				if ok {
					if certOfType.Stale() {
						deleted += 1
						CS.storage.Delete(key)
					}
				}
				return true
			}
			return false
		})
		log.Printf("Cleanup of %v Certificates, Removed %v stale certs.", count, deleted)
	}
}
