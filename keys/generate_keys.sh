#!/bin/bash

openssl req -x509 -newkey rsa:4096 -keyout ca_key.pem -out ca_cert.pem -days 365 -nodes -subj "/CN=Demo CA"

# vSEPP
openssl genpkey -algorithm RSA -out vsepp_key.pem # Generate private key
openssl req -new -key vsepp_key.pem -out vsepp_csr.pem -config openssl_component_vsepp.cnf # Generate CSR
openssl x509 -req -in vsepp_csr.pem -CA ca_cert.pem -CAkey ca_key.pem -CAcreateserial -out vsepp_cert.pem -days 365 -extfile openssl_component_vsepp.cnf -extensions v3_req # sign CSR with CA cert

# vIPX
openssl genpkey -algorithm RSA -out vipx_key.pem
openssl req -new -key vipx_key.pem -out vipx_csr.pem -config openssl_component_vipx.cnf
openssl x509 -req -in vipx_csr.pem -CA ca_cert.pem -CAkey ca_key.pem -CAcreateserial -out vipx_cert.pem -days 365 -extfile openssl_component_vipx.cnf -extensions v3_req


# hIPX
openssl genpkey -algorithm RSA -out hipx_key.pem
openssl req -new -key hipx_key.pem -out hipx_csr.pem -config openssl_component_hipx.cnf
openssl x509 -req -in hipx_csr.pem -CA ca_cert.pem -CAkey ca_key.pem -CAcreateserial -out hipx_cert.pem -days 365 -extfile openssl_component_hipx.cnf -extensions v3_req


# hSEPP
openssl genpkey -algorithm RSA -out hsepp_key.pem
openssl req -new -key hsepp_key.pem -out hsepp_csr.pem -config openssl_component_hsepp.cnf
openssl x509 -req -in hsepp_csr.pem -CA ca_cert.pem -CAkey ca_key.pem -CAcreateserial -out hsepp_cert.pem -days 365 -extfile openssl_component_hsepp.cnf -extensions v3_req
