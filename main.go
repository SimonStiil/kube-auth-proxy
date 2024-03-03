package main

import (
	"fmt"
	"log"

	"github.com/go-ldap/ldap"
)

const (
	user         = "uid=golang-test,cn=users,dc=simon,dc=stiil,dc=dk"
	password     = "gEK7PnVwNTLfuuJoJMYksLx62Vkqa7wt"
	testuser     = "testuser"
	testpassword = "R6nWUmnwNxVJ9Hzv5W4KpGXy3biKpSyk"
)

// Good documentation:
// https://cybernetist.com/2020/05/18/getting-started-with-go-ldap/
// https://dev.to/breda/secret-key-encryption-with-go-using-aes-316d
// https://venilnoronha.io/a-step-by-step-guide-to-mtls-in-go
// https://github.com/davidfstr/nanoproxy/blob/master/nanoproxy.go
// https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/

func main() {
	ldapURL := "ldaps://diskstation.stiil.dk:636"

	conn, err := ldap.DialURL(ldapURL)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	err = conn.Bind(user, password)
	if err != nil {
		log.Fatal(err)
	}
	baseDN := "dc=simon,dc=stiil,dc=dk"
	filter := fmt.Sprintf("(&(uid=%s)(objectClass=person))", testuser)

	// Filters must start and finish with ()!
	searchReq := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, 0, 0, 0, false, filter, []string{"displayName", "memberOf"}, []ldap.Control{})

	result, err := conn.Search(searchReq)
	if err != nil {
		fmt.Println(fmt.Errorf("failed to query LDAP: %w", err))
		return
	}

	log.Println("Got", len(result.Entries), "search results")
	for _, entry := range result.Entries {
		log.Printf("%+v", entry.DN)
		for _, atribute := range entry.Attributes {
			log.Printf("%v : %+v", atribute.Name, atribute.Values)
		}
	}
	userDN := result.Entries[0].DN
	err = conn.Bind(userDN, testpassword)
	if err != nil {
		log.Printf("LDAP authentication failed for user %s, error details: %v", userDN, err)
	} else {
		log.Printf("login success")

	}
}
