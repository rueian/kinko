package kms

import (
	gcpkms "cloud.google.com/go/kms/apiv1"
	"context"
	"encoding/json"
	"fmt"
	"github.com/rueian/kinko/pb"
	gcpkmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
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

func (p *GCP) Decrypt(ctx context.Context, params []byte, seal []byte) (detail *pb.SealingDetail, err error) {
	ps := GCPParams{}
	if err = json.Unmarshal(params, &ps); err != nil {
		return nil, fmt.Errorf("fail to unmarshal GCPParams: %w", ErrBadData)
	}

	var result []byte
	if ps.Asymmetric {
		var res *gcpkmspb.AsymmetricDecryptResponse
		if res, err = p.client.AsymmetricDecrypt(ctx, &gcpkmspb.AsymmetricDecryptRequest{
			Name:       ps.KeyID,
			Ciphertext: seal,
		}); err == nil {
			result = res.Plaintext
		}
	} else {
		var res *gcpkmspb.DecryptResponse
		if res, err = p.client.Decrypt(ctx, &gcpkmspb.DecryptRequest{
			Name:       ps.KeyID,
			Ciphertext: seal,
		}); err == nil {
			result = res.Plaintext
		}
	}
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Code() == codes.InvalidArgument {
			err = fmt.Errorf("%s: %w", err.Error(), ErrBadData)
		}
		return nil, err
	}
	detail = &pb.SealingDetail{}
	if err = proto.Unmarshal(result, detail); err != nil {
		return nil, fmt.Errorf("fail to unmarshal SealingDetail: %w", ErrBadData)
	}
	return
}
