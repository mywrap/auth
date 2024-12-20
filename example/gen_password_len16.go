package main

import (
	"fmt"
	"strings"

	"github.com/mywrap/auth"
)

func main() {
	for i := 0; i < 512; i++ {
		p := auth.GenRandomPassword(16)

		if true { // my personal options
			if strings.Index("abcdefghijklmnopqrstuvwxyz", p[0:1]) == -1 {
				continue
			}
			if p[len(p)-1:] == "_" {
				continue
			}
			isNasty := false
			for _, nastyChar := range []string{
				"1", "j", "i", "I", "l", "L",
				"0", "o", "O",
				"5", "s", "S",
			} {
				if strings.Contains(p, nastyChar) {
					isNasty = true
					break
				}
			}
			if isNasty {
				continue
			}
		}

		fmt.Println(p)
	}
}
