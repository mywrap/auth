package auth

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// CreateJWTAuthToken creates an accessToken that includes some user info.
// :param authInfo: is a user defined struct, example {UserId: 1, Permission: "ALL"},
// resource servers can read the authInfo from created token with a public key
func CreateJWTAuthToken(signedKey *rsa.PrivateKey, expiredDur time.Duration,
	authInfo interface{}) string {
	claim := myJWTClaim{AuthInfo: authInfo}
	claim.IssuedAt = time.Now().Unix()
	claim.ExpiresAt = claim.IssuedAt + int64(expiredDur.Seconds())
	tokenObj := jwt.NewWithClaims(jwt.SigningMethodRS512, claim)
	accessToken, err := tokenObj.SignedString(signedKey)
	if err != nil {
		return ""
	}
	return accessToken
}

type myJWTClaim struct {
	jwt.StandardClaims
	// user defined struct, example {UserId: 1, Permission: ["ALL"]}
	AuthInfo interface{}
}

// VerifyAuthToken verifies input accessToken (can be created by
// CreateJWTAuthToken func in this file) and read its data to outPointer.
// This func returns an error if the token cannot be parsed with the publicKey
// or the token expired or unexpected outPointer data type
func VerifyJWTAuthToken(verifiedKey *rsa.PublicKey, accessToken string,
	outPointer interface{}) error {
	if v := reflect.ValueOf(outPointer); v.Kind() != reflect.Ptr || v.IsNil() {
		return errors.New("non pointer for user info output")
	}
	var claim myJWTClaim
	fPubKey := func(*jwt.Token) (interface{}, error) { return verifiedKey, nil }
	_, err := jwt.ParseWithClaims(accessToken, &claim, fPubKey)
	if err != nil {
		return fmt.Errorf("parse token: %v", err)
	}
	expire := time.Unix(claim.ExpiresAt, 0)
	if expire.Before(time.Now()) {
		return errors.New("expired token")
	}
	marshalled, err := json.Marshal(claim.AuthInfo)
	if err != nil {
		return err
	}
	err = json.Unmarshal(marshalled, outPointer)
	return err
}
