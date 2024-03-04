package main

import (
	"errors"
	"fmt"

	"github.com/go-ldap/ldap"
)

// Good documentation:
// https://cybernetist.com/2020/05/18/getting-started-with-go-ldap/

type LDAPAuth struct {
	URL                 string
	Group               string
	BaseDN              string
	AuthUser            string
	AuthPassword        string
	UserFilter          string
	GroupFilter         string
	MembershipAtributes string
}

func (auth *LDAPAuth) Init(URL string, Group string, BaseDN string, User string, Password string) {
	auth.URL = URL
	auth.Group = Group
	auth.BaseDN = BaseDN
	auth.UserFilter = "(&(uid=%s)(memberOf=%s))"
	auth.GroupFilter = "(&(cn=%s)(objectClass=posixGroup))"
	auth.AuthUser = User
	auth.AuthPassword = Password
}

func (auth *LDAPAuth) SetUserFilter(Filter string) {
	auth.UserFilter = Filter
}

func (auth *LDAPAuth) SetGroupFilter(Filter string) {
	auth.GroupFilter = Filter
}

func (auth *LDAPAuth) SetMembershipAtributes(Filter string) {
	auth.MembershipAtributes = Filter
}

func (auth *LDAPAuth) TestLogin(Username string, Password string) (bool, error) {
	conn, err := ldap.DialURL(auth.URL)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	err = conn.Bind(user, password)
	if err != nil {
		return false, err
	}

	// Lookup group
	groupFilter := fmt.Sprintf(auth.GroupFilter, auth.Group)
	searchReq := ldap.NewSearchRequest(auth.BaseDN, ldap.ScopeWholeSubtree, 0, 0, 0, false, groupFilter, []string{"displayName"}, []ldap.Control{})
	result, err := conn.Search(searchReq)
	if err != nil {
		return false, err
	}
	if len(result.Entries) < 1 {
		return false, errors.New(fmt.Sprintf("Group %v not found", auth.Group))
	}
	if len(result.Entries) > 1 {
		return false, errors.New(fmt.Sprintf("Group search found %v entries, expected exactly 1.", len(result.Entries)))
	}

	// Lookup User
	GroupDN := result.Entries[0].DN
	userFilter := fmt.Sprintf(auth.UserFilter, Username, GroupDN)
	searchReq = ldap.NewSearchRequest(auth.BaseDN, ldap.ScopeWholeSubtree, 0, 0, 0, false, userFilter, []string{"displayName"}, []ldap.Control{})
	result, err = conn.Search(searchReq)
	if err != nil {
		return false, err
	}
	if len(result.Entries) < 1 {
		return false, errors.New(fmt.Sprintf("User %v not found", Username))
	}
	if len(result.Entries) > 1 {
		return false, errors.New(fmt.Sprintf("User serarch found %v entries, expected exactly 1.", len(result.Entries)))
	}
	err = conn.Bind(result.Entries[0].DN, Password)
	if err != nil {
		return false, err
	} else {
		return true, nil
	}
}
