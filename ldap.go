package main

import (
	"fmt"
	"strings"

	"crypto/tls"
	"crypto/x509"

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
		return ldap.DialURL(auth.URL, ldap.DialWithTLSConfig(auth.Config))
	} else {
		return ldap.DialURL(auth.URL)
	}
}

type LDAPUser struct {
	User   string
	Groups []string
}

func (auth *LDAPAuth) LookupGroup(conn *ldap.Conn, group string) (*ldap.Entry, error) {
	groupFilter := fmt.Sprintf(auth.SearchGroupFilter, group)
	searchReq := ldap.NewSearchRequest(auth.BaseDN, ldap.ScopeWholeSubtree, 0, 0, 0, false, groupFilter, []string{"displayName"}, []ldap.Control{})
	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, err
	}
	//fmt.Printf("search for group %v:", groupFilter)
	//result.PrettyPrint(2)
	if len(result.Entries) < 1 {
		return nil, fmt.Errorf("group %v not found", group)
	}
	if len(result.Entries) > 1 {
		return nil, fmt.Errorf("group search found %v entries, expected exactly 1", len(result.Entries))
	}
	return result.Entries[0], nil
}

func (auth *LDAPAuth) findGroupIdentifier(entry *ldap.Entry) string {
	return strings.TrimPrefix(entry.DN, fmt.Sprintf("cn=%s", auth.Group))
}
func (auth *LDAPAuth) ListGroups(groupEntry *ldap.Entry, userEntry *ldap.Entry) []string {
	groupIdentifier := auth.findGroupIdentifier(groupEntry)
	groups := userEntry.GetAttributeValues("memberOf")
	var groupstrings []string
	for _, group := range groups {
		str := strings.TrimSuffix(group, groupIdentifier)
		str = strings.TrimPrefix(str, "cn=")
		str = strings.ReplaceAll(str, " ", "")
		groupstrings = append(groupstrings, str)
	}
	return groupstrings
}

func (auth *LDAPAuth) LookupUser(conn *ldap.Conn, username string, groupDN string) (*ldap.Entry, error) {
	userFilter := fmt.Sprintf(auth.SearchUserFilter, username, groupDN)
	searchReq := ldap.NewSearchRequest(auth.BaseDN, ldap.ScopeWholeSubtree, 0, 0, 0, false, userFilter, []string{"displayName", "memberOf"}, []ldap.Control{})
	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, err
	}
	//log.Printf("search for user %v:", userFilter)
	//result.PrettyPrint(2)
	if len(result.Entries) < 1 {
		fmt.Printf("@E user %v not found", username)
		return nil, nil
	}
	if len(result.Entries) > 1 {
		return nil, fmt.Errorf("user serarch found %v entries, expected exactly 1", len(result.Entries))
	}
	return result.Entries[0], nil
}

func (auth *LDAPAuth) TestLogin(Username string, Password string) (*LDAPUser, error) {
	// Create server conntction
	conn, err := auth.dialServer()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	// Login with main user for group and user search
	err = conn.Bind(auth.BindDN, auth.BindPassword)
	if err != nil {
		return nil, err
	}

	// Lookup group
	groupEntry, err := auth.LookupGroup(conn, auth.Group)
	if err != nil {
		return nil, err
	}

	// Lookup User
	userEntry, err := auth.LookupUser(conn, Username, groupEntry.DN)
	if userEntry == nil && err == nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	err = conn.Bind(userEntry.DN, Password)
	if err != nil {
		if ldap.IsErrorAnyOf(err, 49) {
			return nil, nil
		}
		return nil, err
	} else {
		return &LDAPUser{User: Username, Groups: auth.ListGroups(groupEntry, userEntry)}, nil
	}
}
