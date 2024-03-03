for cert_name in testcert
do 
  kubectl -n kube-auth-proxy get secret $cert_name -o json | jq -r ".data.\"tls.crt\"" |base64 -d >$cert_name.crt
  kubectl -n kube-auth-proxy get secret $cert_name -o json | jq -r ".data.\"tls.key\"" |base64 -d >$cert_name.key
  kubectl -n kube-auth-proxy get secret $cert_name -o json | jq -r ".data.\"ca.crt\"" |base64 -d >$cert_name.ca
done