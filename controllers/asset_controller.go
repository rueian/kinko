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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/go-logr/logr"
	"github.com/rueian/kinko/kms"
	"github.com/rueian/kinko/unseal"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"time"

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

func (r *AssetReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("asset", req.NamespacedName)
	// get the asset
	asset := &sealsv1alpha1.Asset{}
	if err := r.Get(ctx, req.NamespacedName, asset); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	provider, ok := r.Providers[asset.Spec.Provider]
	if !ok {
		return ctrl.Result{Requeue: false}, fmt.Errorf("not supported provider: %s", asset.Spec.Provider)
	}
	seal, err := base64.StdEncoding.DecodeString(asset.Spec.SealingDetail)
	if err != nil {
		return ctrl.Result{Requeue: false}, fmt.Errorf("bad sealing detail: %w", err)
	}
	data, err := base64.StdEncoding.DecodeString(asset.Spec.SealedData)
	if err != nil {
		return ctrl.Result{Requeue: false}, fmt.Errorf("bad sealed data: %w", err)
	}

	// get the corresponding secret, should be 1 to 1 matching by the NamespacedName
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name:      asset.Name,
		Namespace: asset.Namespace,
	}}
	if _, err := ctrl.CreateOrUpdate(ctx, r, secret, func() error {
		if len(secret.Annotations) > 0 {
			if assetVersion, ok := secret.Annotations[assetVersionAnnotation]; ok && assetVersion == asset.ResourceVersion {
				log.Info("the target secret is latest version, skip.")
				return nil
			}
		}

		detail, err := provider.Decrypt(ctx, []byte(asset.Spec.ProviderParams), seal)
		if err != nil {
			return err
		}

		// unseal the asset
		unsealed, err := unseal.Decrypt(detail, data)
		if err != nil {
			return err
		}

		stringData := map[string]string{}
		if err := json.Unmarshal(unsealed, &stringData); err != nil {
			return err
		}

		secret.ObjectMeta.Annotations = map[string]string{
			assetVersionAnnotation: asset.ResourceVersion,
		}
		secret.Data = make(map[string][]byte)
		secret.Type = "Opaque"
		if err := ctrl.SetControllerReference(asset, secret, r.Scheme); err != nil {
			return err
		}
		for k, v := range stringData {
			if bs, err := base64.StdEncoding.DecodeString(v); err == nil {
				secret.Data[k] = bs
			}
		}
		return nil
	}); err != nil {
		return ctrl.Result{RequeueAfter: time.Second}, err
	}

	return ctrl.Result{}, nil
}

func (r *AssetReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sealsv1alpha1.Asset{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}
