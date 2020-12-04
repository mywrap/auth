package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	rand2 "math/rand"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

// output files are PEM encoded,
// private key is PKCS1 format, public key is PKIX format
func CreateRSAKeyPairFiles(outPrivate, outPublic string, sizeBits int) error {
	if sizeBits == 0 {
		sizeBits = 4096
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, sizeBits)
	if err != nil {
		return fmt.Errorf("error MarshalPKCS1PrivateKey: %v", err)
	}
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("error MarshalPKIXPublicKey: %v", err)
	}

	outPrivateKeyFileWriter, err := os.OpenFile(
		outPrivate, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("error OpenFile: %v", err)
	}
	err = pem.Encode(outPrivateKeyFileWriter,
		&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateKeyBytes})
	if err != nil {
		return fmt.Errorf("error pem_Encode: %v", err)
	}
	err = outPrivateKeyFileWriter.Close()
	if err != nil {
		return fmt.Errorf("error pem_Encode: %v", err)
	}
	log.Println("done")

	outPublicKeyFileWriter, err := os.OpenFile(
		outPublic, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("error OpenFile: %v", err)
	}
	err = pem.Encode(outPublicKeyFileWriter,
		&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes})
	if err != nil {
		return fmt.Errorf("error pem_Encode: %v", err)
	}
	err = outPublicKeyFileWriter.Close()
	if err != nil {
		return fmt.Errorf("error pem_Encode: %v", err)
	}
	return nil
}

func ReadRSAPrivatePem(fileContent []byte) (rsaKey *rsa.PrivateKey, err error) {
	defer func() { // pem.Decode can panic
		if r := recover(); r != nil {
			err = errors.New("invalid PEM input")
		}
	}()
	block0, _ := pem.Decode([]byte(fileContent))
	rsaKey, err = x509.ParsePKCS1PrivateKey(block0.Bytes)
	if err != nil {
		return nil, err
	}
	return rsaKey, nil
}

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

func ReadRSAPublicCertPem(fileContent []byte) (rsaKey *rsa.PublicKey, err error) {
	defer func() { // pem.Decode can panic
		if r := recover(); r != nil {
			err = errors.New("invalid PEM input")
		}
	}()
	block1, _ := pem.Decode([]byte(fileContent))
	certificate, err := x509.ParseCertificate(block1.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	rsaKey, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		log.Fatal("error not a rsa public key")
	}
	return rsaKey, nil
}

type myJWTClaim struct {
	jwt.StandardClaims
	// user defined struct, example {UserId: 1, Permission: ["ALL"]}
	AuthInfo interface{}
}

// :param authInfo: is a user defined struct, example {UserId: 1, Permission: "ALL"},
// resource servers can read the authInfo from created token with a public key,
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

// VerifyAuthToken verifies input accessToken and read its data to outPointer.
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

// for GenRandomPassword
var (
	lowers   = strings.Split("abcdefghijklmnopqrstuvwxyz", "")
	uppers   = strings.Split("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "")
	digits   = strings.Split("0123456789", "")
	symbols  = strings.Split("_", "")
	allChars []string
)

func init() {
	rand2.Seed(time.Now().UnixNano())
	for _, chars := range [][]string{lowers, uppers, digits, symbols} {
		for _, char := range chars {
			allChars = append(allChars, char)
		}
	}
}

// GenRandomPassword returns a mixture of uppercase, lowercase, number and
// special characters.
func GenRandomPassword(lenPasswd int) string {
	if lenPasswd < 4 {
		lenPasswd = 4
	}
	indices := rand2.Perm(lenPasswd)
	forceIndices := indices[:4]
	password := make([]string, lenPasswd)
	for i := range password {
		password[i] = allChars[rand2.Intn(len(allChars))]
	}
	for i, charType := range [][]string{lowers, uppers, digits, symbols} {
		forceIndex := forceIndices[i]
		password[forceIndex] = charType[rand2.Intn(len(charType))]
	}

	return strings.Join(password, "")
}

// HashPassword is a slow hash func with salt automatically included (
// hashed results in different call can be different).
func HashPassword(plain string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.MinCost)
	if err != nil {
		return ""
	}
	return string(hash)
}

// VerifyHashPassword checks if the hashed was created from the plain
func VerifyHashPassword(hashed string, plain string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(plain))
	if err != nil {
		return false
	}
	return true
}
