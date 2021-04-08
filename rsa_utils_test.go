package auth

import (
	"io/ioutil"
	"testing"
)

func TestReadRSAPem(t *testing.T) {
	privatePemBytes, err := ioutil.ReadFile("example.key")
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := ReadRSAPrivatePem(privatePemBytes)
	if err != nil {
		t.Fatal(err)
	}
	_ = privateKey

	publicPemBytes2, err := ioutil.ReadFile("example.crt")
	if err != nil {
		t.Fatal(err)
	}
	publicKey2, err := ReadRSAPublicCertPem(publicPemBytes2)
	if err != nil {
		t.Fatal(err)
	}

	if CheckIsRSAPair(privateKey, publicKey2) != true {
		t.Errorf("error CheckIsRSAPair")
	}

	publicPemBytes, err := ioutil.ReadFile("example.pub")
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := ReadRSAPublicKeyPem(publicPemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if CheckIsRSAPair(privateKey, publicKey) != true {
		t.Fatalf("error CheckIsRSAPair")
	}
}
