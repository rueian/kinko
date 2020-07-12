package unseal

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"github.com/rueian/kinko/kms"
)

func Decrypt(detail kms.SealingDetail, data []byte) (unsealed []byte, err error) {
	if detail.Mode != "AES-256-GCM" {
		return nil, errors.New("currently only support AES-256-GCM")
	}

	key, err := base64.StdEncoding.DecodeString(detail.DEK)
	if err != nil {
		return nil, err
	}

	iv, err := base64.StdEncoding.DecodeString(detail.IV)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, iv, data, nil)
}
