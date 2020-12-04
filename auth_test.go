package auth

import (
	"io/ioutil"
	"strings"
	"testing"
	"time"
)

func TestRSAFuncs(t *testing.T) {
	const privateFile = "rsa0.key"
	const publicFile = "rsa0.pub"
	err := CreateRSAKeyPairFiles(privateFile, publicFile, 4096)
	if err != nil {
		t.Fatal(err)
	}

	privateBytes, err := ioutil.ReadFile(privateFile)
	if err != nil {
		t.Fatal(err)
	}
	private, err := ReadRSAPrivatePem(privateBytes)
	if private == nil || err != nil {
		t.Fatal(err)
	}
	publicBytes, err := ioutil.ReadFile(publicFile)
	if err != nil {
		t.Fatal(err)
	}
	public, err := ReadRSAPublicKeyPem(publicBytes)
	if public == nil || err != nil {
		t.Fatal(err)
	}

	type AuthInfo struct{ UserId string }
	accessToken := CreateJWTAuthToken(private, 1*time.Second,
		AuthInfo{UserId: "daominah"})
	if accessToken == "" {
		t.Errorf("empty accessToken")
	}
	t.Log(accessToken)

	var read AuthInfo
	err = VerifyJWTAuthToken(public, accessToken, &read)
	if err != nil {
		t.Errorf("error VerifyAuthToken: %v", err)
	}
	if read.UserId != "daominah" {
		t.Errorf("error wrong UserId from token: %v", read.UserId)
	}

	time.Sleep(1100 * time.Millisecond)
	err = VerifyJWTAuthToken(public, accessToken, &read)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("error should be expired token")
	}
}

func TestReadRSAPublicCertPem(t *testing.T) {
	certBytes, err := ioutil.ReadFile("test.crt")
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := ReadRSAPublicCertPem(certBytes)
	if err != nil || publicKey == nil {
		t.Error(err)
	}
}

func TestHashPassword(t *testing.T) {
	password0 := "123qwe"
	hashed := HashPassword(password0)
	if hashed == "" {
		t.Errorf("empty hashed of %v", password0)
	}
	t.Log(hashed)
	isMatched := VerifyHashPassword(hashed, password0)
	if !isMatched {
		t.Errorf("error VerifyHashPassword")
	}
	isMatched2 := VerifyHashPassword("a"+hashed[1:], password0)
	if isMatched2 {
		t.Errorf("error VerifyHashPassword 2")
	}
}

func TestGenRandomPassword(t *testing.T) {
	p := GenRandomPassword(3)
	if len(p) != 4 {
		t.Error("error minimum password len")
	}
	t.Log(p)
	p2 := GenRandomPassword(8)
	if len(p2) != 8 {
		t.Errorf("error password len: %v", len(p2))
	}
	t.Log(p2)
}
