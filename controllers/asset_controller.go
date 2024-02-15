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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
	log    logr.Logger
	scheme *runtime.Scheme

	plugins map[string]kms.Plugin
}

func NewAssetReconciler(client client.Client, log logr.Logger, scheme *runtime.Scheme, plugins map[string]kms.Plugin) *AssetReconciler {
	return &AssetReconciler{
		Client:  client,
		log:     log,
		scheme:  scheme,
		plugins: plugins,
	}
}

func (r *AssetReconciler) Scheme() *runtime.Scheme {
	return r.scheme
}

// +kubebuilder:rbac:groups=seals.kinko.dev,resources=assets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=seals.kinko.dev,resources=assets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete

func (r *AssetReconciler) Reconcile(ctx context.Context, req ctrl.Request) (res ctrl.Result, err error) {
	log := r.log.WithValues("asset", req.NamespacedName)
	// get the asset
	asset := &sealsv1alpha1.Asset{}
	if err := r.Get(ctx, req.NamespacedName, asset); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	assetVersion := checksum(mergeMap(
		stringMapToByteMap(asset.Annotations),
		stringMapToByteMap(asset.Labels),
		map[string][]byte{"type": []byte(asset.Spec.Type)},
		asset.Spec.EncryptedData,
	))

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
		if err := ctrl.SetControllerReference(asset, secret, r.Scheme()); err != nil {
			return err
		}

		data, err := asset.Unseal(ctx, r.plugins)
		if err != nil {
			return err
		}
		// migration mode, protect existing value
		if secret.Annotations[assetVersionAnnotation] == "" ||
			secret.Annotations[dataChecksumAnnotation] == "" {
			if secret.Type != "" && secret.Type != asset.Spec.Type {
				return fmt.Errorf("migration failed: spec.type mismatch with the existing value: %w", status.ErrMigrate)
			}

			for k, n := range data {
				if o, ok := secret.Data[k]; ok && !bytes.Equal(n, o) {
					return fmt.Errorf("migration failed: '%s' mismatch with the existing value: %w", k, status.ErrMigrate)
				}
			}
		}

		if asset.Spec.Type == "" {
			asset.Spec.Type = corev1.SecretTypeOpaque
		}

		if secret.Type != "" && secret.Type != asset.Spec.Type {
			log.Info("trying to update immutable field", "field", "type", "old", secret.Type, "new", asset.Spec.Type)
			return fmt.Errorf("%w: type", status.ErrImmutable)
		}

		secret.Data = data
		secret.Type = asset.Spec.Type
		secret.Annotations = asset.Annotations
		secret.Annotations[assetVersionAnnotation] = assetVersion
		secret.Annotations[dataChecksumAnnotation] = checksum(secret.Data)
		secret.Labels = asset.Labels
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
		if apierrors.IsConflict(err) {
			statusErr := &apierrors.StatusError{}
			if ok := errors.As(err, &statusErr); ok {
				log.Info(statusErr.ErrStatus.Message + ", retry")
				return ctrl.Result{}, err
			}
		}

		log.Error(err, "fail to update status")
		return ctrl.Result{}, err
	}

	if errors.Is(err, status.ErrImmutable) {
		log.Info("immutable field changed, delete secret for re-sync")

		if err := r.Delete(ctx, secret); err != nil {
			log.Error(err, "fail to delete secret for re-sync")
			return ctrl.Result{}, nil
		}

		return ctrl.Result{Requeue: true}, nil
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
		Status:             corev1.ConditionTrue,
		Reason:             status.ReasonSyncSuccess,
		LastTransitionTime: metav1.Now(),
	}
	if err != nil {
		sc.Status = corev1.ConditionFalse
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
		case errors.Is(err, status.ErrImmutable):
			sc.Reason = status.ReasonImmutable
		default:
			sc.Reason = status.ReasonUnknown
		}
	}
	a.Status.Conditions.SetCondition(sc)
}

func shouldRequeue(err error) error {
	switch {
	case errors.Is(err, status.ErrNoPlugin),
		errors.Is(err, status.ErrMigrate),
		errors.Is(err, status.ErrBadData),
		errors.Is(err, status.ErrNoParams),
		errors.Is(err, status.ErrImmutable):
		return nil
	default:
		return err
	}
}

func stringMapToByteMap(m map[string]string) map[string][]byte {
	res := make(map[string][]byte)
	for k, v := range m {
		res[k] = []byte(v)
	}
	return res
}

func mergeMap(maps ...map[string][]byte) map[string][]byte {
	res := make(map[string][]byte)
	for _, m := range maps {
		for k, v := range m {
			res[k] = v
		}

	}
	return res
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
