package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

type Proxy struct {
	LDAPAuth          *LDAPAuth
	KubeClient        *KubeClient
	Config            *MainConfig
	certificaeStorage *CertificateStorage
}

func (proxy *Proxy) StartProxy(config ProxyConfig) error {
	// Start up the proxy.
	proxy.certificaeStorage = NewCertificateStorage(proxy.KubeClient)

	// Assing order of Handler Functions
	http.HandleFunc("/", proxy.BasicAuth(proxy.ProxyHander()))
	hostString := fmt.Sprintf("%s:%s", config.Host, config.Port)
	// If we have TLS Certificates tart in TLS Mode
	if _, err := os.Stat(config.TLS.Certificate); err == nil {
		if _, err := os.Stat(config.TLS.Key); err == nil {
			log.Printf("Proxy TLS on %v", hostString)
			return http.ListenAndServeTLS(hostString, config.TLS.Certificate, config.TLS.Key, nil)
		}
	}
	log.Printf("Proxy on %v", hostString)
	return http.ListenAndServe(hostString, nil)
}

// Good Documentation:
// https://www.alexedwards.net/blog/basic-authentication-in-go
// https://medium.com/@matryer/the-http-handler-wrapper-technique-in-golang-updated-bc7fbcffa702
func (proxy *Proxy) BasicAuth(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// http Handler function for Basic Auth
		username, password, ok := r.BasicAuth()
		if ok {
			// Test Login with LDAP
			success, err := proxy.LDAPAuth.TestLogin(username, password)
			if err != nil {
				log.Printf("LDAP Error %+v", err)
				http.Error(w, "Internal Server Error ", http.StatusInternalServerError)
				return
			}
			if !success {
				log.Printf("LDAP Login Failed for user %+v", username)
				w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			// If login ok Serve.
			next.ServeHTTP(w, r)
		} else {
			log.Printf("Basic Auth not read correctly %+v", r.Header)
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	})
}

var removeRequestHeaderKeys = [...]string{
	"Authorization",
	"Accept-Encoding",
}

// BAD NON FUNCTIONAL DOCS... but a start
// https://github.com/davidfstr/nanoproxy/blob/master/nanoproxy.go
// Good examples:
// https://stackoverflow.com/questions/34724160/go-http-send-incoming-http-request-to-an-other-server-using-client-do

func (proxy *Proxy) ProxyHander() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, _, ok := r.BasicAuth()
		// Since we already logged in we expect everything to be okay. Just need the Username
		// TODO: Parse the username from previous authentication + Groups
		if ok {
			// Get an auth certificate either from Secret og new Certitificate
			cert, err := proxy.certificaeStorage.GetCertificate(username)
			//cert, err := NewClientAuth(proxy.KubeClient, username)
			if err != nil {
				log.Printf("Error creating certificate : %+v\n", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			tlsCert, err := cert.GetTLSCert()
			if err != nil {
				log.Printf("Error creating TLS certificate : %+v\n", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			// Setup HTTP Client from Certificate and CA
			httpClient := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						RootCAs:      proxy.KubeClient.caCertPool,
						Certificates: []tls.Certificate{tlsCert},
					},
				},
			}
			// Read body to proxy
			body, err := io.ReadAll(r.Body)
			if proxy.Config.Verbose {
				log.Printf("> %v %v %+v %v\n- %+v", username, r.Method, r.URL.Path, len(body), r.Header)
			}
			if err != nil {
				log.Printf("Error reading origin body: %+v", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			// Create a URL from request
			url := fmt.Sprintf("%s://%s%s", "https", proxy.Config.Kubernetes.Host, r.RequestURI)
			// Create new Request
			proxyReq, err := http.NewRequest(r.Method, url, bytes.NewReader(body))
			// Adding headers
			proxyReq.Header = make(http.Header)
			for headerKey, headerValue := range r.Header {
				skip := false
				for _, testKey := range removeRequestHeaderKeys {
					if headerKey == testKey {
						skip = true
					}
				}
				if !skip {
					// f headerValue
					proxyReq.Header[headerKey] = headerValue
				}
			}
			// Do Request
			proxyResp, err := httpClient.Do(proxyReq)
			if err != nil {
				log.Printf("I %v %v %v %+v", username, r.Method, r.URL.Path, err)
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			// Read body to return
			defer proxyResp.Body.Close()
			proxyBody, err := io.ReadAll(proxyResp.Body)
			if proxy.Config.Verbose {
				log.Printf("< %v %v %v %v %+v %v\n- %+v", username, r.Method, r.URL.Path, proxyResp.StatusCode, proxyResp.Status, len(proxyBody), proxyResp.Header)
			}
			if err != nil {
				log.Printf("Error reading proxy body: %+v", err)
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			// Copy response headers
			respH := w.Header()
			// log.Printf("Response Headers: %+v", proxyResp.Header)
			for key, value := range proxyResp.Header {
				respH[key] = value
			}
			// Write body and statuscode.
			w.WriteHeader(proxyResp.StatusCode)
			w.Write(proxyBody)
		}
	})
}
