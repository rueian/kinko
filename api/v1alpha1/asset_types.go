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
	"fmt"

	"github.com/rueian/kinko/status"
	corev1 "k8s.io/api/core/v1"

	"github.com/rueian/kinko/kms"
	"github.com/rueian/kinko/unseal"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// AssetSpec defines the desired state of Asset
type AssetSpec struct {
	Provider       string            `json:"provider"`
	ProviderParams string            `json:"providerParams"`
	SealingDetail  []byte            `json:"sealingDetail"`
	EncryptedData  map[string][]byte `json:"encryptedData"`
	Type           corev1.SecretType `json:"type,omitempty"`
}

// AssetStatus defines the observed state of Asset
type AssetStatus struct {
	Conditions status.Conditions `json:"conditions"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// Asset is the Schema for the assets API
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

func (a *Asset) Unseal(ctx context.Context, providers map[string]kms.Provider) (map[string][]byte, error) {
	if len(a.Spec.EncryptedData) == 0 {
		return nil, nil
	}

	provider, ok := providers[a.Spec.Provider]
	if !ok {
		return nil, fmt.Errorf("%s %w", a.Spec.Provider, status.ErrNoProvider)
	}

	if len(a.Spec.ProviderParams) == 0 || len(a.Spec.SealingDetail) == 0 {
		return nil, fmt.Errorf("ProviderParams or SealingDetail %w", status.ErrEmptyParam)
	}

	detail, err := provider.Decrypt(ctx, []byte(a.Spec.ProviderParams), a.Spec.SealingDetail)
	if err != nil {
		return nil, err
	}

	data := make(map[string][]byte)
	// unseal the asset
	for k, v := range a.Spec.EncryptedData {
		unsealed, err := unseal.Decrypt(detail, v)
		if err != nil {
			return nil, err
		}
		data[k] = unsealed
	}

	return data, nil
}
