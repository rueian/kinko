package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"github.com/rueian/kinko/pb"
	"github.com/rueian/kinko/status"
)

func Decrypt(detail *pb.Seal, data []byte) (unsealed []byte, err error) {
	if detail.Mode != pb.Seal_AES_256_GCM {
		return nil, fmt.Errorf("currently only support AES-256-GCM: %w", status.ErrBadData)
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
		return nil, fmt.Errorf("nonce missing: %w", status.ErrBadData)
	}

	return gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], nil)
}

func Encrypt(detail *pb.Seal, data []byte) (unsealed []byte, err error) {
	block, err := aes.NewCipher(detail.Dek)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	encrypted := gcm.Seal(nil, nonce, data, nil)
	encrypted = append(nonce, encrypted...)

	return encrypted, nil
}
