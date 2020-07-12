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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// EncryptedSecretSpec defines the desired state of EncryptedSecret
type EncryptedSecretSpec struct {
	KMSProvider           string `json:"kmsProvider"`
	KMSKeyEncryptionKeyID string `json:"kmsKeyEncryptionKeyId"`
	DataEncryptionDetails string `json:"dataEncryptionDetails"`
	DataEncrypted         string `json:"dataEncrypted"`
}

// EncryptedSecretStatus defines the observed state of EncryptedSecret
type EncryptedSecretStatus struct {
	LastSyncedTimestamp metav1.Time `json:"lastSyncedTimestamp"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// EncryptedSecret is the Schema for the encryptedsecrets API
type EncryptedSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   EncryptedSecretSpec   `json:"spec,omitempty"`
	Status EncryptedSecretStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// EncryptedSecretList contains a list of EncryptedSecret
type EncryptedSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EncryptedSecret `json:"items"`
}

func init() {
	SchemeBuilder.Register(&EncryptedSecret{}, &EncryptedSecretList{})
}
