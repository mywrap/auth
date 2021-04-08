package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"
)

func TestRSAFuncs(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	public := &private.PublicKey

	type AuthInfo struct{ UserId string }
	accessToken := CreateJWTAuthToken(private, 1*time.Second,
		AuthInfo{UserId: "daominah"}) // expired duration is at lest 1 second
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
