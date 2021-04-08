#!/usr/bin/env bash

# generate a RSA private key with a length of 4096 bits
openssl genrsa -out example.key 4096

# Following command generates a certificate file.
# -x509: outputs a self signed certificate instead of a certificate request,
# -new: new request,
# -nodes: do not encrypt the output key,
# -key: private key to use for generating this cert,
# -subj: C(CountryName), O(Organization), CN(CommonName)
openssl req \
    -x509 \
    -new -nodes -sha256 -days 10000 \
	-key example.key -subj "/C=VN/O=DaominahTrustServices/CN=*.localhost" \
	-out example.crt

# save public key from the certificate
openssl x509 -pubkey -in example.crt -noout > example.pub
