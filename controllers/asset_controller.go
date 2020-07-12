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
	"errors"
	"fmt"
	"github.com/go-logr/logr"
	"github.com/rueian/kinko/kms"
	"github.com/rueian/kinko/unseal"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sealsv1alpha1 "github.com/rueian/kinko/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
	log.V(1).Info("reconcile")
	// get the asset
	asset := &sealsv1alpha1.Asset{}
	if err := r.Get(ctx, req.NamespacedName, asset); err != nil {
		log.Error(err, "r.Get Err")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	provider, ok := r.Providers[asset.Spec.Provider]
	if !ok {
		log.Error(errors.New("not supported provider"), "r.Get Err")
		return ctrl.Result{Requeue: false}, fmt.Errorf("not supported provider: %s", asset.Spec.Provider)
	}

	params, err := base64.StdEncoding.DecodeString(asset.Spec.ProviderParams)
	if err != nil {
		log.Error(err, "r.Get Err")
		return ctrl.Result{Requeue: false}, fmt.Errorf("bad provider pararms: %w", err)
	}
	seal, err := base64.StdEncoding.DecodeString(asset.Spec.SealingDetail)
	if err != nil {
		log.Error(err, "bad sealing detail")
		return ctrl.Result{Requeue: false}, fmt.Errorf("bad sealing detail: %w", err)
	}
	data, err := base64.StdEncoding.DecodeString(asset.Spec.SealedData)
	if err != nil {
		log.Error(err, "bad sealed data")
		return ctrl.Result{Requeue: false}, fmt.Errorf("bad sealed data: %w", err)
	}
	detail, err := provider.Decrypt(ctx, params, seal)
	if err != nil {
		log.Error(err, "corrupted sealing detail")
		return ctrl.Result{Requeue: false}, fmt.Errorf("corrupted sealing detail: %w", err)
	}

	// unseal the asset
	unsealed, err := unseal.Decrypt(detail, data)
	if err != nil {
		log.Error(err, "corrupted sealed data")
		return ctrl.Result{Requeue: false}, fmt.Errorf("corrupted sealed data: %w", err)
	}

	stringData := map[string]string{}
	if err := json.Unmarshal(unsealed, &stringData); err != nil {
		return ctrl.Result{Requeue: false}, fmt.Errorf("bad sealed data: %w", err)
	}

	// get the corresponding secret, should be 1 to 1 matching by the NamespacedName
	secret, err := r.makeSecret(asset, stringData)
	if err != nil {
		return ctrl.Result{}, err
	}
	if err := r.Get(ctx, req.NamespacedName, &corev1.Secret{}); err != nil {
		if apierrors.IsNotFound(err) {
			if err := r.Create(ctx, secret); err != nil {
				return ctrl.Result{}, err
			}
		}
	} else {
		if err := r.Update(ctx, secret); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, nil
}

func (r *AssetReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sealsv1alpha1.Asset{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}

func (r *AssetReconciler) makeSecret(asset *sealsv1alpha1.Asset, data map[string]string) (*corev1.Secret, error) {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      asset.Name,
			Namespace: asset.Namespace,
		},
		Data: make(map[string][]byte),
		Type: "Opaque",
	}

	if err := ctrl.SetControllerReference(asset, s, r.Scheme); err != nil {
		return nil, err
	}

	for k, v := range data {
		if bs, err := base64.StdEncoding.DecodeString(v); err == nil {
			s.Data[k] = bs
		}
	}

	return s, nil
}
