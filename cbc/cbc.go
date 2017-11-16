package cbc

import (
	"crypto/cipher"

	"github.com/wodadehencou/algomode/padding"
)

func PKCS7Encrypt(block cipher.Block, src []byte, iv []byte) []byte {
	mode := cipher.NewCBCEncrypter(block, iv)
	temp := padding.PKCS7Padding(block, src)
	r := make([]byte, len(temp))
	mode.CryptBlocks(r, temp)
	return r
}

func PKCS7Decrypt(block cipher.Block, src []byte, iv []byte) ([]byte, error) {
	mode := cipher.NewCBCDecrypter(block, iv)
	temp := make([]byte, len(src))
	mode.CryptBlocks(temp, src)
	return padding.PKCS7UnPadding(block, temp)
}
