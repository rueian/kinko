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
	"bytes"
	"context"
	"errors"
	"fmt"
	"hash/crc32"
	"sort"
	"strconv"

	"github.com/go-logr/logr"
	sealsv1alpha1 "github.com/rueian/kinko/api/v1alpha1"
	"github.com/rueian/kinko/kms"
	"github.com/rueian/kinko/status"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	assetVersionAnnotation = "seals.kinko.dev/asset-version"
	dataChecksumAnnotation = "seals.kinko.dev/data-checksum"
)

// AssetReconciler reconciles a Asset object
type AssetReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme

	Plugins map[string]kms.Plugin
}

// +kubebuilder:rbac:groups=seals.kinko.dev,resources=assets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=seals.kinko.dev,resources=assets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete

func (r *AssetReconciler) Reconcile(req ctrl.Request) (res ctrl.Result, err error) {
	ctx := context.Background()
	log := r.Log.WithValues("asset", req.NamespacedName)
	// get the asset
	asset := &sealsv1alpha1.Asset{}
	if err := r.Get(ctx, req.NamespacedName, asset); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	assetVersion := checksum(asset.Spec.EncryptedData)

	// get the corresponding secret, should be 1 to 1 matching by the NamespacedName
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name:      asset.Name,
		Namespace: asset.Namespace,
	}}
	_, err = ctrl.CreateOrUpdate(ctx, r, secret, func() (err error) {
		if secret.Annotations == nil {
			secret.Annotations = make(map[string]string)
		}
		if secret.Annotations[assetVersionAnnotation] == assetVersion &&
			secret.Annotations[dataChecksumAnnotation] == checksum(secret.Data) {
			log.Info("the target secret is latest version, skip.")
			return nil
		}
		if err := ctrl.SetControllerReference(asset, secret, r.Scheme); err != nil {
			return err
		}

		data, err := asset.Unseal(ctx, r.Plugins)
		if err != nil {
			return err
		}
		// migration mode, protect existing value
		if secret.Annotations[assetVersionAnnotation] == "" ||
			secret.Annotations[dataChecksumAnnotation] == "" {
			for k, n := range data {
				if o, ok := secret.Data[k]; ok && !bytes.Equal(n, o) {
					return fmt.Errorf("migration failed: '%s' mismatch with the existing value: %w", k, status.ErrMigrate)
				}
			}
		}

		secret.Data = data
		secret.Type = asset.Spec.Type
		secret.Annotations[assetVersionAnnotation] = assetVersion
		secret.Annotations[dataChecksumAnnotation] = checksum(secret.Data)
		return nil
	})

	// erase secrets in memory
	for k, v := range secret.Data {
		for i := range v {
			v[i] = 0
		}
		delete(secret.Data, k)
	}

	setSyncedCondition(asset, err)
	if err := r.Status().Update(ctx, asset); err != nil {
		log.Error(err, "fail to update status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, shouldRequeue(err)
}

func (r *AssetReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sealsv1alpha1.Asset{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}

func setSyncedCondition(a *sealsv1alpha1.Asset, err error) {
	sc := status.Condition{
		Type:               "Synced",
		LastTransitionTime: metav1.Now(),
	}
	defer a.Status.Conditions.SetCondition(sc)

	if err == nil {
		sc.Status = corev1.ConditionTrue
		sc.Reason = status.ReasonSyncSuccess
		return
	}

	sc.Status = corev1.ConditionFalse
	sc.Reason = status.ReasonUnknown
	sc.Message = err.Error()
	switch {
	case errors.Is(err, status.ErrNoPlugin):
		sc.Reason = status.ReasonNoPlugin
	case errors.Is(err, status.ErrMigrate):
		sc.Reason = status.ReasonMigrationFailed
	case errors.Is(err, status.ErrBadData):
		sc.Reason = status.ReasonBadData
	case errors.Is(err, status.ErrNoParams):
		sc.Reason = status.ReasonNoParams
	}
}

func shouldRequeue(err error) error {
	switch {
	case errors.Is(err, status.ErrNoPlugin),
		errors.Is(err, status.ErrMigrate),
		errors.Is(err, status.ErrBadData),
		errors.Is(err, status.ErrNoParams):
		return nil
	default:
		return err
	}
}

func checksum(secrets map[string][]byte) string {
	keys := make([]string, 0, len(secrets))
	for k := range secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	checksum := crc32.NewIEEE()
	for _, k := range keys {
		checksum.Write(secrets[k])
	}
	return strconv.FormatUint(uint64(checksum.Sum32()), 10)
}
