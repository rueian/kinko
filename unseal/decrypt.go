package unseal

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"

	"github.com/rueian/kinko/pb"
)

func Decrypt(detail *pb.SealingDetail, data []byte) (unsealed []byte, err error) {
	if detail.Mode != pb.SealingMode_AES_256_GCM {
		return nil, errors.New("currently only support AES-256-GCM")
	}

	block, err := aes.NewCipher(detail.Dek)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(data) < gcm.NonceSize() {
		return nil, errors.New("nonce missing")
	}

	return gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], nil)
}
