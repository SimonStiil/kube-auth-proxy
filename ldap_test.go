package main

import (
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
)

func Test_Ldap(t *testing.T) {
	Config := LoadConfig()
	// Create LDAP Object
	auth := &LDAPAuth{LDAPConfig: Config.LDAP}
	var conn *ldap.Conn
	var err error
	end := false
	t.Run("LDAP Connection", func(t *testing.T) {
		conn, err = auth.dialServer()
		if err != nil {
			t.Errorf("Error: %s", err.Error())
			end = true
		}
	})
	defer conn.Close()
	if end {
		return
	}

	t.Run("LDAP Login", func(t *testing.T) {
		err = conn.Bind(auth.BindDN, auth.BindPassword)
		if err != nil {
			t.Errorf("Error: %s", err.Error())
			end = true
		}
	})
	if end {
		return
	}
	var groupEntry *ldap.Entry
	t.Run("LDAP LookupGroup", func(t *testing.T) {
		groupEntry, err = auth.LookupGroup(conn, auth.Group)
		if err != nil {
			t.Errorf("Error: %s", err.Error())
			return
		}
		if !strings.Contains(groupEntry.DN, auth.Group) {
			t.Errorf("Error: group name not in %s != %s", groupEntry.DN, auth.Group)
		}
	})
	var groupIdentifier string
	t.Run("LDAP findGroupIdentifier", func(t *testing.T) {
		groupIdentifier = auth.findGroupIdentifier(groupEntry)
		t.Log(groupIdentifier)
	})

	var userEntry *ldap.Entry
	Username := "user"
	// Lookup User
	t.Run("LDAP LookupUser", func(t *testing.T) {
		userEntry, err = auth.LookupUser(conn, Username, groupEntry.DN)
		if err != nil {
			t.Errorf("Error: %s", err.Error())
			return
		}
		if !strings.Contains(userEntry.DN, Username) {
			t.Errorf("Error: user name not in %s != %s", userEntry.DN, Username)
		}
		groups := auth.ListGroups(groupEntry, userEntry)
		t.Log(groups)
	})

}
