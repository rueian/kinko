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

package controllers

import (
	"context"
	"errors"
	"github.com/go-logr/logr"
	"github.com/rueian/kinko/kms"
	"github.com/rueian/kinko/status"
	"github.com/rueian/kinko/unseal"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sealsv1alpha1 "github.com/rueian/kinko/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
)

var (
	assetVersionAnnotation = "seals.kinko.dev/asset-version"
)

// AssetReconciler reconciles a Asset object
type AssetReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme

	Providers map[string]kms.Provider
}

// +kubebuilder:rbac:groups=seals.kinko.dev,resources=assets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=seals.kinko.dev,resources=assets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=,resources=secrets,verbs=get;list;watch;create;update;patch;delete

func (r *AssetReconciler) Reconcile(req ctrl.Request) (res ctrl.Result, err error) {
	ctx := context.Background()
	log := r.Log.WithValues("asset", req.NamespacedName)
	// get the asset
	asset := &sealsv1alpha1.Asset{}
	if err := r.Get(ctx, req.NamespacedName, asset); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	condition := status.Condition{
		Type:   "Synced",
		Status: corev1.ConditionTrue,
	}
	defer func() {
		asset.Status.Conditions.SetCondition(condition)
		err = r.Status().Update(ctx, asset)
	}()

	// get the corresponding secret, should be 1 to 1 matching by the NamespacedName
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name:      asset.Name,
		Namespace: asset.Namespace,
	}}
	if _, err = ctrl.CreateOrUpdate(ctx, r, secret, func() (err error) {
		if len(secret.Annotations) > 0 {
			if assetVersion, ok := secret.Annotations[assetVersionAnnotation]; ok && assetVersion == asset.ResourceVersion {
				log.Info("the target secret is latest version, skip.")
				return nil
			}
		}

		if err := ctrl.SetControllerReference(asset, secret, r.Scheme); err != nil {
			return err
		}

		secret.ObjectMeta.Annotations = map[string]string{
			assetVersionAnnotation: asset.ResourceVersion,
		}
		secret.Type = "Opaque"
		secret.Data, err = asset.Unseal(ctx, r.Providers)
		return err
	}); err != nil {
		if errors.Is(err, sealsv1alpha1.ErrEmptyParam) ||
			errors.Is(err, sealsv1alpha1.ErrNoProvider) ||
			errors.Is(err, unseal.ErrBadData) ||
			errors.Is(err, kms.ErrBadData) {
			condition.Status = corev1.ConditionFalse
			condition.Message = err.Error()
			condition.Reason = "BadData"
			err = nil
		}
	}
	return
}

func (r *AssetReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sealsv1alpha1.Asset{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}
