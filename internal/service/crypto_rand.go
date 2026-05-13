package service

import "crypto/rand"

func cryptoRandRead(b []byte) {
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand read failed: " + err.Error())
	}
}
