package kms

import (
	"context"
)

type Plugin interface {
	Decrypt(ctx context.Context, params []byte, cipher []byte) ([]byte, error)
	Encrypt(ctx context.Context, params []byte, plain []byte) ([]byte, error)
}

func Providers(ctx context.Context) (map[string]Plugin, error) {
	gcp, err := NewGCP(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]Plugin{
		"GCP": gcp,
	}, nil
}
