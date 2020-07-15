package kms

import (
	"context"
	"errors"
	"github.com/rueian/kinko/pb"
)

var (
	ErrBadData = errors.New("bad data")
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
