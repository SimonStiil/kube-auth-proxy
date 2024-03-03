# Authentication proxy for Kubernetes
This has been a project for learning a lot more about Reverse Proxy and Kubernernetes certificate based authentication.  
An Authentication proxy where: 
* A user logs in through Basic Auth. 
* Is authenticated with LDAP
* Creates and Manages mTLS Certificates inside Kubernetes Cluster
* Proxying the request to the cluster and returning the reply

# Download
Docker image can be fetched from [ghcr.io simonstiil/kube-auth-proxy](https://github.com/SimonStiil/kube-auth-proxy/pkgs/container/kube-auth-proxy)  
Can be build with go build .  
Will also be available as a release in releases in the future

## Configuration
Is done in config.yaml following the structure  
Example can be seen in [config.yaml](./config.yaml) 
ldap password is set with LDAP_BIND_PASSWORD


## Configuration Structure
| Option | Description | Default |
| ------ | ----------- | --- |
| Proxy.Host | Host to bind to | |
| Proxy.Port | Port to bind to | 8080 |
| Proxy.TLS.Certificate | Certificate to use for Proxy TLS | |
| Proxy.TLS.Key | Key for Certificate to use for Proxy TLS | |
| LDAP.URL | URL for the LDAP Server | |
| LDAP.Group | Group that allows kubernetes authentication | |
| LDAP.BaseDN | Base DN for searches | |
| LDAP.BindDN | User DN with LDAP Consumer rights | |
| LDAP.SearchUserFilter | Filter for finding users in group | (&(uid=%s)(memberOf=%s)) |
| LDAP.SearchGroupFilter | Filter for finding group DN | (&(cn=%s)(objectClass=posixGroup)) |
| Kubernetes.Kubernetes | Path to kubeconfig file | |
| Kubernetes.Host | host and port to access kubernetes api | kubernetes.default |
| Kubernetes.Namespace | Namespace to use for certificate secrets (Should exist) | kube-auth-proxy |

LDAP password is set in ENV with LDAP_BIND_PASSWORD

## Deplyment Example
See yaml files in [deployment](./deployment) 

## Gotchas
The logged in user will only have the rights that are given to that user. 
Example of a GlobalRole and GlobalRolebinding in [examples](./examples) 