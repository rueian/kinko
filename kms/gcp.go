package kms

import (
	gcpkms "cloud.google.com/go/kms/apiv1"
	"context"
	"encoding/json"
	gcpkmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

type GCPParams struct {
	KeyID      string `json:"keyId"`
	Asymmetric bool   `json:"asymmetric"`
}

func NewGCP(ctx context.Context) (*GCP, error) {
	client, err := gcpkms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, err
	}
	return &GCP{client: client}, nil
}

type GCP struct {
	client *gcpkms.KeyManagementClient
}

func (p *GCP) Decrypt(ctx context.Context, params []byte, seal []byte) (detail SealingDetail, err error) {
	ps := GCPParams{}
	if err = json.Unmarshal(params, &ps); err != nil {
		return
	}

	var result []byte
	if ps.Asymmetric {
		res := &gcpkmspb.AsymmetricDecryptResponse{}
		if res, err = p.client.AsymmetricDecrypt(ctx, &gcpkmspb.AsymmetricDecryptRequest{
			Name:       ps.KeyID,
			Ciphertext: seal,
		}); err == nil {
			result = res.Plaintext
		}
	} else {
		res := &gcpkmspb.DecryptResponse{}
		if res, err = p.client.Decrypt(ctx, &gcpkmspb.DecryptRequest{
			Name:       ps.KeyID,
			Ciphertext: seal,
		}); err == nil {
			result = res.Plaintext
		}
	}
	if err == nil {
		err = json.Unmarshal(result, &detail)
	}
	return
}
