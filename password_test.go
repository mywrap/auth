package auth

import "testing"

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
