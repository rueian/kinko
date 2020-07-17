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
	"encoding/json"

	"github.com/rueian/kinko/kms"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

// log is for logging in this package.
var assetlog = logf.Log.WithName("asset-resource")

func (r *Asset) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

// +kubebuilder:webhook:path=/mutate-seals-kinko-dev-v1alpha1-asset,mutating=true,failurePolicy=fail,groups=seals.kinko.dev,resources=assets,verbs=create;update,versions=v1alpha1,name=masset.kb.io

var _ webhook.Defaulter = &Asset{}

// Default implements webhook.Defaulter so a webhook will be registered for the type
func (r *Asset) Default() {
	assetlog.Info("default", "name", r.Name)

	// TODO(user): fill in your defaulting logic.
}

func (r *Asset) Validate() error {
	if r.Spec.SealingPlugin == "GCP" {
		param := kms.GCPParams{}
		if err := json.Unmarshal([]byte(r.Spec.SealingParams), &param); err != nil {
			return err
		}
		return param.Validate()
	}
	return nil
}

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
// +kubebuilder:webhook:verbs=create;update,path=/validate-seals-kinko-dev-v1alpha1-asset,mutating=false,failurePolicy=fail,groups=seals.kinko.dev,resources=assets,versions=v1alpha1,name=vasset.kb.io

var _ webhook.Validator = &Asset{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *Asset) ValidateCreate() error {
	assetlog.Info("validate create", "name", r.Name)
	return r.Validate()
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *Asset) ValidateUpdate(old runtime.Object) error {
	assetlog.Info("validate update", "name", r.Name)
	return r.Validate()
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *Asset) ValidateDelete() error {
	assetlog.Info("validate delete", "name", r.Name)
	// TODO(user): fill in your validation logic upon object deletion.
	return nil
}
