package kms

import "context"

type Provider interface {
	Decrypt(ctx context.Context, params []byte, seal []byte) (SealingDetail, error)
}

type SealingDetail struct {
	Mode string `json:"mode"`
	DEK  string `json:"dek"`
	IV   string `json:"iv"`
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
