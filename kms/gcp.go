package kms

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"sync"

	gcpkms "cloud.google.com/go/kms/apiv1"
	"github.com/rueian/kinko/pb"
	"github.com/rueian/kinko/status"
	gcpkmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type GCPParams struct {
	KeyID      string `json:"keyId"`
	Asymmetric bool   `json:"asymmetric"`
}

func (p *GCPParams) Validate() error {
	if p.KeyID == "" {
		return errors.New("keyId should not be empty")
	}
	return nil
}

func NewGCP(ctx context.Context) (*GCP, error) {
	client, err := gcpkms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, err
	}
	return &GCP{
		client:      client,
		asymmetrics: map[string]Asymmetric{},
	}, nil
}

type GCP struct {
	client      *gcpkms.KeyManagementClient
	asymmetrics map[string]Asymmetric
	mu          sync.Mutex
}

type Asymmetric struct {
	publicKey *rsa.PublicKey
	algorithm func() hash.Hash
}

func (p *GCP) Encrypt(ctx context.Context, params []byte, detail *pb.SealingDetail) (seal []byte, err error) {
	ps := GCPParams{}
	if err = json.Unmarshal(params, &ps); err != nil {
		return nil, fmt.Errorf("fail to unmarshal GCPParams: %w", status.ErrBadData)
	}

	bs, err := proto.Marshal(detail)
	if err != nil {
		return nil, err
	}

	if ps.Asymmetric {
		p.mu.Lock()
		defer p.mu.Unlock()

		method, ok := p.asymmetrics[ps.KeyID]
		if !ok {
			response, err := p.client.GetPublicKey(ctx, &gcpkmspb.GetPublicKeyRequest{Name: ps.KeyID})
			if err != nil {
				return nil, err
			}
			block, _ := pem.Decode([]byte(response.Pem))
			pk, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			publicKey, ok := pk.(*rsa.PublicKey)
			if !ok {
				return nil, err
			}
			switch response.Algorithm {
			case gcpkmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256,
				gcpkmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA256,
				gcpkmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA256:
				p.asymmetrics[ps.KeyID] = Asymmetric{
					publicKey: publicKey,
					algorithm: sha256.New,
				}
			case gcpkmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA512:
				p.asymmetrics[ps.KeyID] = Asymmetric{
					publicKey: publicKey,
					algorithm: sha512.New,
				}
			default:
				return nil, errors.New("only support RSA_DECRYPT_OAEP_[2048|3072|4096]_SHA[256|512]")
			}
			method = p.asymmetrics[ps.KeyID]
		}
		return rsa.EncryptOAEP(method.algorithm(), rand.Reader, method.publicKey, bs, nil)
	} else {
		res, err := p.client.Encrypt(ctx, &gcpkmspb.EncryptRequest{
			Name:      ps.KeyID,
			Plaintext: bs,
		})
		if err != nil {
			return nil, err
		}
		return res.Ciphertext, nil
	}
}

func (p *GCP) Decrypt(ctx context.Context, params []byte, seal []byte) (detail *pb.SealingDetail, err error) {
	ps := GCPParams{}
	if err = json.Unmarshal(params, &ps); err != nil {
		return nil, fmt.Errorf("fail to unmarshal GCPParams: %w", status.ErrBadData)
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
		if s, ok := grpcstatus.FromError(err); ok && s.Code() == codes.InvalidArgument {
			err = fmt.Errorf("%s: %w", err.Error(), status.ErrBadData)
		}
		return nil, err
	}
	detail = &pb.SealingDetail{}
	if err = proto.Unmarshal(result, detail); err != nil {
		return nil, fmt.Errorf("fail to unmarshal SealingDetail: %w", status.ErrBadData)
	}
	return
}
