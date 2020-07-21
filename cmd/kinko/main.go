package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"github.com/rueian/kinko/status"
	"google.golang.org/protobuf/proto"
	"io"
	"io/ioutil"
	"os"
	"strings"

	sealsv1alpha1 "github.com/rueian/kinko/api/v1alpha1"
	"github.com/rueian/kinko/kms"
	"github.com/rueian/kinko/pb"
	"github.com/rueian/kinko/seal"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
)

var (
	rootCmd = &cobra.Command{
		Use:   "kinko",
		Short: "A generator for kinko sealed assets",
	}
	sealCmd = &cobra.Command{
		Use:   "seal",
		Short: "seal k8s secrets yaml from stdin to kinko sealed assets yaml",
		RunE:  Seal,
	}
	unsealCmd = &cobra.Command{
		Use:   "unseal",
		Short: "unseal kinko yaml sealed assets from stdin to k8s secrets yaml",
		RunE:  Unseal,
	}
	newCmd = &cobra.Command{
		Use:   "new",
		Short: "create kinko sealed assets yaml from CLI flags",
		RunE:  Create,
	}
	patchCmd = &cobra.Command{
		Use:   "patch",
		Short: "patch kinko sealed assets yaml from CLI flags",
		RunE:  Patch,
	}

	KeyID         string
	StringSecrets []string
	Base64Secrets []string

	scheme  = runtime.NewScheme()
	codec   serializer.CodecFactory
	decoder runtime.Decoder
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(sealsv1alpha1.AddToScheme(scheme))
	codec = serializer.NewCodecFactory(scheme)
	decoder = codec.UniversalDeserializer()

	rootCmd.AddCommand(sealCmd)
	rootCmd.AddCommand(unsealCmd)
	rootCmd.AddCommand(newCmd)
	rootCmd.AddCommand(patchCmd)
	rootCmd.PersistentFlags().StringVarP(&KeyID, "key", "k", "", "the asymmetric key id of kms")
	rootCmd.MarkFlagRequired("key")
	patchCmd.Flags().StringArrayVarP(&StringSecrets, "string", "s", nil, "string values to seal: --string key=value")
	patchCmd.Flags().StringArrayVarP(&Base64Secrets, "base64", "b", nil, "base64 values to seal: --base64 key=dmFsdWU=")
	newCmd.Flags().StringArrayVarP(&StringSecrets, "string", "s", nil, "string values to seal: --string key=value")
	newCmd.Flags().StringArrayVarP(&Base64Secrets, "base64", "b", nil, "base64 values to seal: --base64 key=dmFsdWU=")
	newCmd.Args = cobra.MinimumNArgs(1)
}

func Seal(cmd *cobra.Command, args []string) error {
	writer := bufio.NewWriter(os.Stdout)
	defer writer.Flush()

	yamls, err := readYAMLs(os.Stdin)
	if err != nil {
		return err
	}

	provider, err := kms.NewGCP(context.Background())
	if err != nil {
		return err
	}

	params, _ := json.Marshal(kms.GCPParams{
		KeyID:      KeyID,
		Asymmetric: true,
	})

	info, _ := runtime.SerializerInfoForMediaType(codec.SupportedMediaTypes(), runtime.ContentTypeYAML)
	encoder := codec.EncoderForVersion(info.Serializer, sealsv1alpha1.GroupVersion)

	for _, doc := range yamls {
		obj, _, err := decoder.Decode(doc, nil, nil)
		if err != nil {
			continue
		}
		secret := &corev1.Secret{}
		if err := scheme.Convert(obj, secret, corev1.SchemeGroupVersion); err != nil {
			continue
		}

		asset := &sealsv1alpha1.Asset{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secret.Name,
				Namespace: secret.Namespace,
			},
			Spec: sealsv1alpha1.AssetSpec{
				Type:          secret.Type,
				SealingPlugin: "GCP",
				SealingParams: string(params),
				EncryptedData: make(map[string][]byte),
			},
		}

		asset.Spec.EncryptedData, err = encrypt(provider, params, secret.Data)
		if err != nil {
			return err
		}

		if err := writeYAML(writer, encoder, asset); err != nil {
			return err
		}
	}
	return nil
}

func Unseal(cmd *cobra.Command, args []string) error {
	writer := bufio.NewWriter(os.Stdout)
	defer writer.Flush()

	yamls, err := readYAMLs(os.Stdin)
	if err != nil {
		return err
	}

	providers, err := kms.Providers(context.Background())
	if err != nil {
		return err
	}

	info, _ := runtime.SerializerInfoForMediaType(codec.SupportedMediaTypes(), runtime.ContentTypeYAML)
	encoder := codec.EncoderForVersion(info.Serializer, corev1.SchemeGroupVersion)

	for _, doc := range yamls {
		obj, _, err := decoder.Decode(doc, nil, nil)
		if err != nil {
			continue
		}
		asset := &sealsv1alpha1.Asset{}
		if err := scheme.Convert(obj, asset, sealsv1alpha1.GroupVersion); err != nil {
			continue
		}

		data, err := asset.Unseal(context.Background(), providers)
		if err != nil {
			return err
		}

		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      asset.Name,
				Namespace: asset.Namespace,
			},
			Data: data,
		}

		if err := writeYAML(writer, encoder, secret); err != nil {
			return err
		}
	}
	return nil
}

func Create(cmd *cobra.Command, args []string) error {
	writer := bufio.NewWriter(os.Stdout)
	defer writer.Flush()

	info, _ := runtime.SerializerInfoForMediaType(codec.SupportedMediaTypes(), runtime.ContentTypeYAML)
	encoder := codec.EncoderForVersion(info.Serializer, sealsv1alpha1.GroupVersion)

	var name, namespace string

	parts := strings.SplitN(args[0], "/", 2)
	if len(parts) == 1 {
		name = parts[0]
	} else if len(parts) > 1 {
		namespace = parts[0]
		name = parts[1]
	}

	params, _ := json.Marshal(kms.GCPParams{
		KeyID:      KeyID,
		Asymmetric: true,
	})

	asset := &sealsv1alpha1.Asset{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: sealsv1alpha1.AssetSpec{
			SealingPlugin: "GCP",
			SealingParams: string(params),
			EncryptedData: make(map[string][]byte),
		},
	}

	secrets, err := secretsFromCLIFlags()
	if err != nil {
		return err
	}

	if len(secrets) > 0 {
		provider, err := kms.NewGCP(context.Background())
		if err != nil {
			return err
		}
		asset.Spec.EncryptedData, err = encrypt(provider, params, secrets)
		if err != nil {
			return err
		}
	}

	return writeYAML(writer, encoder, asset)
}

func Patch(cmd *cobra.Command, args []string) error {
	secrets, err := secretsFromCLIFlags()
	if err != nil {
		return err
	}

	if len(secrets) == 0 {
		return nil
	}

	writer := bufio.NewWriter(os.Stdout)
	defer writer.Flush()

	yamls, err := readYAMLs(os.Stdin)
	if err != nil {
		return err
	}

	if len(yamls) != 1 {
		return errors.New("there should be exact 1 kinko asset crd from stdin")
	}

	providers, err := kms.Providers(context.Background())
	if err != nil {
		return err
	}

	info, _ := runtime.SerializerInfoForMediaType(codec.SupportedMediaTypes(), runtime.ContentTypeYAML)
	encoder := codec.EncoderForVersion(info.Serializer, sealsv1alpha1.GroupVersion)

	doc := yamls[0]

	obj, _, err := decoder.Decode(doc, nil, nil)
	if err != nil {
		return err
	}
	asset := &sealsv1alpha1.Asset{}
	if err := scheme.Convert(obj, asset, sealsv1alpha1.GroupVersion); err != nil {
		return err
	}

	provider, ok := providers[asset.Spec.SealingPlugin]
	if !ok {
		return status.ErrNoPlugin
	}

	encrypted, err := encrypt(provider, []byte(asset.Spec.SealingParams), secrets)
	if err != nil {
		return err
	}

	for k := range secrets {
		if v, ok := encrypted[k]; ok {
			asset.Spec.EncryptedData[k] = v
		} else {
			delete(asset.Spec.EncryptedData, k)
		}
	}

	return writeYAML(writer, encoder, asset)
}

func writeYAML(writer io.Writer, encoder runtime.Encoder, obj runtime.Object) (err error) {
	if _, err = writer.Write([]byte("---\n")); err == nil {
		if err = encoder.Encode(obj, writer); err == nil {
			_, err = writer.Write([]byte("\n"))
		}
	}
	return nil
}

func readYAMLs(reader io.Reader) ([][]byte, error) {
	bs, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	return bytes.Split(bs, []byte("\n---")), nil
}

func secretsFromCLIFlags() (map[string][]byte, error) {
	secrets := make(map[string][]byte)

	for _, v := range StringSecrets {
		parts := strings.SplitN(v, "=", 2)
		if len(parts) == 2 {
			secrets[parts[0]] = []byte(parts[1])
		}
	}

	for _, v := range Base64Secrets {
		parts := strings.SplitN(v, "=", 2)
		if len(parts) == 2 {
			v, err := base64.StdEncoding.DecodeString(parts[1])
			if err != nil {
				return nil, err
			}
			secrets[parts[0]] = v
		}
	}
	return secrets, nil
}

func encrypt(provider kms.Plugin, params []byte, secrets map[string][]byte) (map[string][]byte, error) {
	encrypted := make(map[string][]byte, len(secrets))

	detail := &pb.Seal{
		Mode: pb.Seal_AES_256_GCM,
		Dek:  make([]byte, 32),
	}

	for k, v := range secrets {
		if len(v) == 0 {
			continue
		}

		rand.Read(detail.Dek)

		bs, _ := proto.Marshal(detail)
		dekv, err := provider.Encrypt(context.Background(), params, bs)
		if err != nil {
			return nil, err
		}

		encv, err := seal.Encrypt(detail, v)
		if err != nil {
			return nil, err
		}

		if len(dekv) > 65535 {
			panic("the length of encrypted seal exceed the max uint16 (65535)")
		}

		result := make([]byte, 2+len(dekv)+len(encv))
		binary.BigEndian.PutUint16(result[:2], uint16(len(dekv)))
		copy(result[2:2+len(dekv)], dekv)
		copy(result[2+len(dekv):], encv)
		encrypted[k] = result
	}
	return encrypted, nil
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		panic(err)
		//os.Exit(1)
	}
}
