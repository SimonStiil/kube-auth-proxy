package main

import (
	"log"
)

const (
	user         = "uid=golang-test,cn=users,dc=simon,dc=stiil,dc=dk"
	password     = "gEK7PnVwNTLfuuJoJMYksLx62Vkqa7wt"
	testuser     = "testuser"
	testpassword = "R6nWUmnwNxVJ9Hzv5W4KpGXy3biKpSyk"
)

// Good documentation:
// https://dev.to/breda/secret-key-encryption-with-go-using-aes-316d
// https://venilnoronha.io/a-step-by-step-guide-to-mtls-in-go
// https://github.com/davidfstr/nanoproxy/blob/master/nanoproxy.go
// https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/

func main() {
	LDAP := new(LDAPAuth)
	LDAP.Init("ldaps://diskstation.stiil.dk:636", "kubeauth", "dc=simon,dc=stiil,dc=dk", user, password)
	ok, err := LDAP.TestLogin(testuser, testpassword)
	if err != nil {
		log.Printf("Error logging in : %+v\n", err)
	}
	if ok {
		log.Println("Login successful")
	}
}
