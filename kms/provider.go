package kms

import (
	"context"
	"github.com/rueian/kinko/pb"
)

type Provider interface {
	Decrypt(ctx context.Context, params []byte, seal []byte) (*pb.SealingDetail, error)
}

func Providers(ctx context.Context) (map[string]Provider, error) {
	gcp, err := NewGCP(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]Provider{
		"GCP": gcp,
	}, nil
}
