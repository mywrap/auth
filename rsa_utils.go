package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// ReadRSAPrivatePem parses a RSA private key from a PKCS1 ASN1 PEM file,
// (an example certificate can be generated by `openssl genrsa` in gen_rsa_pair.sh)
func ReadRSAPrivatePem(fileContent []byte) (rsaKey *rsa.PrivateKey, err error) {
	defer func() { // pem.Decode can panic
		if r := recover(); r != nil {
			err = errors.New("invalid PEM input")
		}
	}()
	block0, _ := pem.Decode([]byte(fileContent))
	rsaKey, err = x509.ParsePKCS1PrivateKey(block0.Bytes)
	if err != nil {
		return nil, fmt.Errorf("x509 ParsePKCS1PrivateKey: %v", err)
	}
	return rsaKey, nil
}

// ReadRSAPublicCertPem parses a certificate from the given ASN1 PEM,
// (an example certificate can be generated by `openssl req` in gen_rsa_pair.sh)
func ReadRSAPublicCertPem(fileContent []byte) (rsaKey *rsa.PublicKey, err error) {
	defer func() { // pem.Decode can panic
		if r := recover(); r != nil {
			err = errors.New("invalid PEM input")
		}
	}()
	block1, _ := pem.Decode([]byte(fileContent))
	certificate, err := x509.ParseCertificate(block1.Bytes)
	if err != nil {
		return nil, fmt.Errorf("x509 ParseCertificate: %v", err)
	}
	rsaKey, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate is not a rsa public key")
	}
	return rsaKey, nil
}

// ReadRSAPublicKeyPem parses a RSA public key from a PKIX ASN1 PEM file,
func ReadRSAPublicKeyPem(fileContent []byte) (rsaKey *rsa.PublicKey, err error) {
	defer func() { // pem.Decode can panic
		if r := recover(); r != nil {
			err = errors.New("invalid PEM input")
		}
	}()
	block0, _ := pem.Decode([]byte(fileContent))
	rsaKeyI, err := x509.ParsePKIXPublicKey(block0.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := rsaKeyI.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("file is not a RSA public key")
	}
	return rsaKey, nil
}

func CheckIsRSAPair(private *rsa.PrivateKey, public *rsa.PublicKey) bool {
	if private.N.Cmp(public.N) != 0 {
		return false
	}
	if private.E != public.E {
		return false
	}
	return true
}
