package main

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	v1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierros "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

// Good documentation:
// https://github.com/coreos/kapprover/blob/master/pkg/approvers/always/always.go
// https://pkg.go.dev/k8s.io/kubernetes/pkg/apis/certificates

type KubeClient struct {
	expiration int32
	clientset  *kubernetes.Clientset
	context.Context
	namespace   string
	caCertPool  *x509.CertPool
	certificate *tls.Certificate
}

const (
	CERTIFICATE_EXPIRATION_SECONDS = 60 * 60 * 24 * 5 // 5 Days default
	// Call timeout for getting Signed Certificate
	CERTIFICATE_FETCH_TIMEOUT_SECONDS    = 10
	CERTIFICATE_WAIT_TIMEOUT_MILISECONDS = 100
)

func NewKubeClient(kubernetesConfig KubernetesConfig) (*KubeClient, error) {
	// Create main kubeclient for accessing secrets and signing mechanism
	// See ./deployment/authorization.yaml for RBAC requirements
	flag.Parse()
	var config *rest.Config
	var err error
	// Locate a config for "Out of Cluster" usage
	if kubernetesConfig.KubeConfig == "" {
		if home := homedir.HomeDir(); home != "" {
			homeConfig := filepath.Join(home, ".kube", "config")
			if _, err := os.Stat(homeConfig); err == nil {
				kubernetesConfig.KubeConfig = homeConfig
			}
		}
	}
	if kubernetesConfig.KubeConfig != "" {
		log.Printf("@I Using kubeconfig in: %v\n", kubernetesConfig.KubeConfig)
		config, err = clientcmd.BuildConfigFromFlags("", kubernetesConfig.KubeConfig)
		if err != nil {
			return nil, err
		}
	} else {
		// If no out of cluster confing found try in cluster
		config, err = rest.InClusterConfig()
		log.Println("@I Using in Cluster Configuration")
		if err != nil {
			return nil, err
		}
	}
	// Get CA Certificate for cluster for usage in proxy mode
	caCertPool := x509.NewCertPool()
	if config.CAFile != "" {
		caCert, err := os.ReadFile(config.CAFile)
		if err != nil {
			log.Printf("@I Error reading CA Certificate file (%v): %+v\n", config.CAFile, err)
		} else {
			log.Printf("@D Read CA Certificate from file (%v)\n", config.CAFile)
			caCertPool.AppendCertsFromPEM(caCert)
		}
	}
	if len(config.CAData) > 0 {
		log.Printf("@D Read CA Certificate from CAData\n")
		caCertPool.AppendCertsFromPEM(config.CAData)
	}

	var certificate tls.Certificate
	if len(config.CertData) > 0 && len(config.KeyData) > 0 {
		certificate, err = tls.X509KeyPair(config.CertData, config.KeyData)
		log.Printf("@D Read Certificate from CertData && KeyData\n")
	} else {
		var certKey []byte
		if config.KeyFile != "" {
			certKey, err = os.ReadFile(config.KeyFile)
			if err != nil {
				log.Printf("@I Error reading Certificate key file (%v): %+v\n", config.KeyFile, err)
			}
		}
		var cert []byte
		if config.KeyFile != "" {
			cert, err = os.ReadFile(config.CertFile)
			if err != nil {
				log.Printf("@I Error reading Certificate key file (%v): %+v\n", config.CertFile, err)
			}
		}
		log.Printf("@D Read Certificate from CertFile && KeyFile\n")
		certificate, err = tls.X509KeyPair(cert, certKey)
	}
	client := &KubeClient{expiration: CERTIFICATE_EXPIRATION_SECONDS, Context: context.Background(), namespace: kubernetesConfig.Namespace, caCertPool: caCertPool}
	if err == nil {
		client.certificate = &certificate
	} else {
		log.Printf("@F Error reading Certificate From Kubeconfig\n")
		os.Exit(123)
	}

	// create the clientset
	client.clientset, err = kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func (kube *KubeClient) GetCSR(name string) (*v1.CertificateSigningRequest, error) {
	return kube.clientset.CertificatesV1().CertificateSigningRequests().Get(kube.Context, name, metav1.GetOptions{})
}

func (kube *KubeClient) DeleteCSR(name string) error {
	return kube.clientset.CertificatesV1().CertificateSigningRequests().Delete(kube.Context, name, metav1.DeleteOptions{})
}

func (kube *KubeClient) GetSignedCertificate(name string) ([]byte, error) {
	// Get signed certificate, This can take a few attempts. Will retry every 100 miliseconds
	end := time.Now().Add(CERTIFICATE_FETCH_TIMEOUT_SECONDS * time.Second)
	for {
		// Timeout
		if time.Now().After(end) {
			break
		}
		csr, err := kube.GetCSR(name)
		if err != nil {
			// If no CSR Exists break with error
			if apierros.IsNotFound(err) {
				return nil, err
			}
		}
		if csr.Status.Certificate != nil && len(csr.Status.Certificate) > 0 {
			return csr.Status.Certificate, nil
		}
		time.Sleep(time.Millisecond * CERTIFICATE_WAIT_TIMEOUT_MILISECONDS)
	}
	// Timeout
	return nil, errors.New("timeout waiting for signed certificate")
}

func (kube *KubeClient) CreateCSR(name string, csr []byte) (*v1.CertificateSigningRequest, error) {
	// Create a CSR with a PEM Encoded []byte
	return kube.clientset.CertificatesV1().CertificateSigningRequests().Create(kube.Context,
		&v1.CertificateSigningRequest{
			ObjectMeta: metav1.ObjectMeta{
				Name:   name,
				Labels: map[string]string{"auth.stiil.dk/clientcertificates": "generated"},
			}, Spec: v1.CertificateSigningRequestSpec{
				// Required to be a client certificate for the API Server
				SignerName: "kubernetes.io/kube-apiserver-client",
				// Required to be a client certificate for the API Server
				Usages:            []v1.KeyUsage{v1.UsageClientAuth},
				ExpirationSeconds: &kube.expiration,
				Request:           csr,
			}}, metav1.CreateOptions{})
}

func (kube *KubeClient) ApproveCSR(name string) error {
	// First get the CSR
	csr, err := kube.GetCSR(name)
	if err != nil {
		return err
	}
	// Append new Approved status
	csr.Status.Conditions = append(csr.Status.Conditions,
		v1.CertificateSigningRequestCondition{
			Type:   v1.CertificateApproved,
			Reason: "Auto Approved by kube-auth-proxy",
			Status: corev1.ConditionTrue,
		})
	// Send updated status
	_, err = kube.clientset.CertificatesV1().CertificateSigningRequests().UpdateApproval(kube.Context, csr.GetName(), csr, metav1.UpdateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func genereateHash(data map[string][]byte) string {
	// Helper function for adding a secret SHA1 hash on the secret for the content. Not currently used for anything usefull
	hash := sha1.New()
	hash.Write([]byte(
		fmt.Sprintf("%+v", data),
	))
	bytes := hash.Sum(nil)
	return fmt.Sprintf("%x", bytes)
}

func (kube *KubeClient) GetSecret(name string) (*corev1.Secret, error) {
	return kube.clientset.CoreV1().Secrets(kube.namespace).Get(kube.Context, name, metav1.GetOptions{})
}

func (kube *KubeClient) CreateSecret(name string, secretTemplate *corev1.Secret) (*corev1.Secret, error) {
	return kube.clientset.CoreV1().Secrets(kube.namespace).Create(context.Background(), secretTemplate, metav1.CreateOptions{})
}

func (kube *KubeClient) DeleteSecret(name string) error {
	return kube.clientset.CoreV1().Secrets(kube.namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
}

func (kube *KubeClient) updateSecret(name string, secretTemplate *corev1.Secret) (*corev1.Secret, error) {
	return kube.clientset.CoreV1().Secrets(kube.namespace).Update(context.Background(), secretTemplate, metav1.UpdateOptions{})
}
