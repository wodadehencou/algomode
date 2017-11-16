package padding

import (
	"bytes"
	"crypto/cipher"
	"errors"
)

func pkcs7Padding(block cipher.Block, src []byte) []byte {
	padding := block.BlockSize() - len(src)%block.BlockSize()
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func pkcs7UnPadding(block cipher.Block, src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])

	if unpadding > block.BlockSize() || unpadding == 0 {
		return nil, errors.New("Invalid pkcs7 padding (unpadding > algo.BlockSize || unpadding == 0)")
	}

	pad := src[len(src)-unpadding:]
	for i := 0; i < unpadding; i++ {
		if pad[i] != byte(unpadding) {
			return nil, errors.New("Invalid pkcs7 padding (pad[i] != unpadding)")
		}
	}

	return src[:(length - unpadding)], nil
}
