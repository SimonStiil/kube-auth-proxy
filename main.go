package main

import (
	"fmt"
	"log"

	"github.com/spf13/viper"
)

const (
	//	user         = "uid=golang-test,cn=users,dc=simon,dc=stiil,dc=dk"
	//	password     = "gEK7PnVwNTLfuuJoJMYksLx62Vkqa7wt"
	testuser     = "testuser"
	testpassword = "R6nWUmnwNxVJ9Hzv5W4KpGXy3biKpSyk"
)

// Good documentation:
// https://dev.to/breda/secret-key-encryption-with-go-using-aes-316d
// https://venilnoronha.io/a-step-by-step-guide-to-mtls-in-go
// https://github.com/davidfstr/nanoproxy/blob/master/nanoproxy.go
// https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/

type MainConfig struct {
	LDAP          LDAPConfig
	Kubernetes    KubernetesConfig
	Proxy         ProxyConfig
	Verbose       bool
	Impersonation bool
}
type ProxyConfig struct {
	Port string
	Host string
	TLS  TLSConfig
}
type TLSConfig struct {
	Certificate string
	Key         string
}
type LDAPConfig struct {
	URL                 string
	Group               string
	BaseDN              string
	BindDN              string
	BindPassword        string
	OuBase              string
	SearchUserFilter    string
	SearchGroupFilter   string
	MembershipAtributes string
	CACertificate       string
}
type KubernetesConfig struct {
	KubeConfig string
	Namespace  string
	Host       string
}

// Setting defaults for configuration if no file exists.
func LoadConfig() MainConfig {
	viper.AddConfigPath(".")
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.SetDefault("Verbose", false)
	viper.SetDefault("Impersonation", true)
	viper.SetDefault("Proxy.Host", "")
	viper.SetDefault("Proxy.Port", "8080")
	viper.SetDefault("Kubernetes.KubeConfig", "")
	viper.SetDefault("Kubernetes.Namespace", "kube-auth-proxy")
	viper.SetDefault("Kubernetes.Host", "kubernetes.default")
	viper.SetDefault("LDAP.SearchUserFilter", "(&(uid=%s)(memberOf=%s))")
	viper.SetDefault("LDAP.SearchGroupFilter", "(&(cn=%s)(objectClass=groupOfNames))")
	viper.BindEnv("LDAP.BindPassword", "LDAP_BIND_PASSWORD")
	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		panic(fmt.Errorf("fatal error config file: %w", err))
	}
	var Config MainConfig
	viper.Unmarshal(&Config)
	return Config
}
func main() {
	Config := LoadConfig()
	// Create LDAP Object
	LDAP := &LDAPAuth{LDAPConfig: Config.LDAP}
	// Create KubeClient Object
	client, err := NewKubeClient(Config.Kubernetes)
	if err != nil {
		log.Printf("Error creating kubeconfig : %+v\n", err)
		return
	}
	// Start up the proxy.
	// Setup and start the Proxy
	proxy := &Proxy{LDAPAuth: LDAP, KubeClient: client, Config: &Config}
	if !Config.Impersonation {
		proxy.certificaeStorage = NewCertificateStorage(client)
	}
	proxy.StartProxy(Config.Proxy)
}
