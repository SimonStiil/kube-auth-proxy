package main

import (
	"fmt"

	"crypto/tls"
	"crypto/x509"
	"net"
	"net/url"

	ldap "github.com/go-ldap/ldap/v3"
)

// Good documentation:
// https://cybernetist.com/2020/05/18/getting-started-with-go-ldap/

type LDAPAuth struct {
	LDAPConfig
	*tls.Config
}

func (auth *LDAPAuth) SetMembershipAtributes(Filter string) {
	// Not implimentet for group usage
	auth.MembershipAtributes = Filter
}

func (auth *LDAPAuth) dialServer() (*ldap.Conn, error) {
	// Handle special situation when using a non standart RootCA
	if len(auth.CACertificate) > 0 && auth.Config == nil {
		cert := []byte(auth.CACertificate)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(cert)
		auth.Config = &tls.Config{
			RootCAs: caCertPool,
		}
	}
	if auth.Config != nil {
		lurl, err := url.Parse(auth.URL)
		if err != nil {
			return nil, err
		}
		host, port, err := net.SplitHostPort(lurl.Host)
		if err != nil {
			// we asume that error is due to missing port
			host = lurl.Host
			port = ""
		}
		if port == "" {
			port = ldap.DefaultLdapsPort
		}
		return ldap.DialTLS("tcp", net.JoinHostPort(host, port), auth.Config)
	} else {
		return ldap.DialURL(auth.URL)
	}
}

func (auth *LDAPAuth) TestLogin(Username string, Password string) (bool, error) {
	// Create server conntction
	conn, err := auth.dialServer()
	if err != nil {
		return false, err
	}
	defer conn.Close()
	// Login with main user for group and user search
	err = conn.Bind(auth.BindDN, auth.BindPassword)
	if err != nil {
		return false, err
	}

	// Lookup group
	groupFilter := fmt.Sprintf(auth.SearchGroupFilter, auth.Group)
	searchReq := ldap.NewSearchRequest(auth.BaseDN, ldap.ScopeWholeSubtree, 0, 0, 0, false, groupFilter, []string{"displayName"}, []ldap.Control{})
	result, err := conn.Search(searchReq)
	if err != nil {
		return false, err
	}
	if len(result.Entries) < 1 {
		return false, fmt.Errorf("group %v not found", auth.Group)
	}
	if len(result.Entries) > 1 {
		return false, fmt.Errorf("group search found %v entries, expected exactly 1", len(result.Entries))
	}

	// Lookup User
	GroupDN := result.Entries[0].DN
	userFilter := fmt.Sprintf(auth.SearchUserFilter, Username, GroupDN)
	searchReq = ldap.NewSearchRequest(auth.BaseDN, ldap.ScopeWholeSubtree, 0, 0, 0, false, userFilter, []string{"displayName"}, []ldap.Control{})
	result, err = conn.Search(searchReq)
	if err != nil {
		return false, err
	}
	if len(result.Entries) < 1 {
		return false, fmt.Errorf("user %v not found", Username)
	}
	if len(result.Entries) > 1 {
		return false, fmt.Errorf("user serarch found %v entries, expected exactly 1", len(result.Entries))
	}
	err = conn.Bind(result.Entries[0].DN, Password)
	if err != nil {
		return false, err
	} else {
		return true, nil
	}
}
