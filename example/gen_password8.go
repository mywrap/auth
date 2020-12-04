package main

import (
	"fmt"

	"github.com/mywrap/auth"
)

func main() {
	for i := 0; i < 10; i++ {
		passwd := auth.GenRandomPassword(8)
		_, _ = fmt.Println, passwd
		fmt.Println(passwd)
	}
}
