/*


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/rueian/kinko/kms"
	"github.com/rueian/kinko/pb"
	"github.com/rueian/kinko/seal"
	"github.com/rueian/kinko/status"
	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// AssetSpec defines the desired state of Asset
type AssetSpec struct {
	// +kubebuilder:validation:Enum=GCP
	SealingPlugin string            `json:"sealingPlugin"`
	SealingParams string            `json:"sealingParams"`
	EncryptedSeal []byte            `json:"encryptedSeal,omitempty"`
	EncryptedData map[string][]byte `json:"encryptedData"`
	Type          corev1.SecretType `json:"type,omitempty"`
}

// AssetStatus defines the observed state of Asset
type AssetStatus struct {
	// +optional
	Conditions status.Conditions `json:"conditions"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// Asset is the Schema for the assets API
// +kubebuilder:printcolumn:name="TYPE",type=string,JSONPath=`.spec.type`
// +kubebuilder:printcolumn:name="PLUGIN",type=string,JSONPath=`.spec.sealingPlugin`
// +kubebuilder:printcolumn:name="SYNCED",type=string,JSONPath=`.status.conditions[?(@.type=="Synced")].status`
// +kubebuilder:printcolumn:name="REASON",type=string,JSONPath=`.status.conditions[?(@.type=="Synced")].reason`
type Asset struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AssetSpec   `json:"spec,omitempty"`
	Status AssetStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AssetList contains a list of Asset
type AssetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Asset `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Asset{}, &AssetList{})
}

func (a *Asset) Unseal(ctx context.Context, providers map[string]kms.Plugin) (map[string][]byte, error) {
	if len(a.Spec.EncryptedData) == 0 {
		return nil, nil
	}

	plugin, ok := providers[a.Spec.SealingPlugin]
	if !ok {
		return nil, fmt.Errorf("%s %w", a.Spec.SealingPlugin, status.ErrNoPlugin)
	}

	if len(a.Spec.SealingParams) == 0 {
		return nil, fmt.Errorf("SealingParams %w", status.ErrNoParams)
	}

	data := make(map[string][]byte, len(a.Spec.EncryptedData))

	if len(a.Spec.EncryptedSeal) != 0 {
		bs, err := plugin.Decrypt(ctx, []byte(a.Spec.SealingParams), a.Spec.EncryptedSeal)
		if err != nil {
			return nil, err
		}

		detail := pb.Seal{}
		if err := proto.Unmarshal(bs, &detail); err != nil {
			return nil, fmt.Errorf("fail to unmarshal EncryptedSeal: %w", status.ErrBadData)
		}

		for k, v := range a.Spec.EncryptedData {
			if data[k], err = seal.Decrypt(&detail, v); err != nil {
				return nil, err
			}
		}
	} else {
		for k, v := range a.Spec.EncryptedData {
			if len(v) < 2 {
				return nil, fmt.Errorf("data '%s' too short: %w", k, status.ErrBadData)
			}
			size := binary.BigEndian.Uint16(v[:2])
			if len(v) < int(2+size) {
				return nil, fmt.Errorf("data '%s' too short: %w", k, status.ErrBadData)
			}
			dekv := v[2 : 2+size]
			encv := v[2+size:]

			bs, err := plugin.Decrypt(ctx, []byte(a.Spec.SealingParams), dekv)
			if err != nil {
				return nil, err
			}

			detail := pb.Seal{}
			if err := proto.Unmarshal(bs, &detail); err != nil {
				return nil, fmt.Errorf("fail to unmarshal EncryptedSeal: %w", status.ErrBadData)
			}

			if data[k], err = seal.Decrypt(&detail, encv); err != nil {
				return nil, err
			}
		}
	}

	return data, nil
}
