package main

import (
	"log"
	"sync"
	"time"
)

type CertificateStorage struct {
	storage *sync.Map
	client  *KubeClient
}

func NewCertificateStorage(client *KubeClient) *CertificateStorage {
	cs := &CertificateStorage{storage: new(sync.Map), client: client}
	go cs.cleanupTask()
	return cs
}

func (CS *CertificateStorage) GetCertificate(name string) (*Certificate, error) {
	cert, ok := CS.storage.Load(name)
	if ok {
		certOfType, ok := cert.(*Certificate)
		if ok {
			if certOfType.IsAboutToExpire() {
				log.Println("Cached certificate is about to expire renewing")
			} else {
				certOfType.UpdateLastUsed()
				log.Println("Using cached certificate")
				return certOfType, nil
			}
		} else {
			log.Printf("Unable to cast *Certificate for user: %v", name)
		}
	} else {
		log.Printf("Unable to read certificate for user: %v", name)
	}
	certOfType, err := NewClientAuth(CS.client, name)
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
