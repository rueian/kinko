package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"strings"

	sealsv1alpha1 "github.com/rueian/kinko/api/v1alpha1"
	"github.com/rueian/kinko/kms"
	"github.com/rueian/kinko/pb"
	"github.com/rueian/kinko/unseal"
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
		Short: "A generator for kinko sealed secrets",
	}
	sealCmd = &cobra.Command{
		Use:   "seal",
		Short: "seal k8s secrets yaml to kinko sealed secrets yaml",
		RunE:  Seal,
	}
	unsealCmd = &cobra.Command{
		Use:   "unseal",
		Short: "unseal to kinko yaml sealed secrets k8s secrets yaml",
		RunE:  Unseal,
	}
	newCmd = &cobra.Command{
		Use:   "new",
		Short: "create kinko sealed secret yaml",
		RunE:  Create,
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
	rootCmd.PersistentFlags().StringVarP(&KeyID, "key", "k", "", "the asymmetric key id of kms")
	rootCmd.MarkFlagRequired("key")
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
				Type:           secret.Type,
				Provider:       "GCP",
				ProviderParams: string(params),
				EncryptedData:  make(map[string][]byte),
			},
		}

		detail := &pb.SealingDetail{
			Mode: pb.SealingMode_AES_256_GCM,
			Dek:  make([]byte, 32),
		}
		rand.Read(detail.Dek)

		for k, v := range secret.Data {
			encrypted, err := unseal.Encrypt(detail, v)
			if err != nil {
				return err
			}
			asset.Spec.EncryptedData[k] = encrypted
		}

		sealed, err := provider.Encrypt(context.Background(), params, detail)
		if err != nil {
			return err
		}
		asset.Spec.SealingDetail = sealed

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
			Provider:       "GCP",
			ProviderParams: string(params),
			EncryptedData:  make(map[string][]byte),
		},
	}

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
				return err
			}
			secrets[parts[0]] = v
		}
	}

	if len(secrets) > 0 {
		detail := &pb.SealingDetail{
			Mode: pb.SealingMode_AES_256_GCM,
			Dek:  make([]byte, 32),
		}
		rand.Read(detail.Dek)

		for k, v := range secrets {
			encrypted, err := unseal.Encrypt(detail, v)
			if err != nil {
				return err
			}
			asset.Spec.EncryptedData[k] = encrypted
		}

		provider, err := kms.NewGCP(context.Background())
		if err != nil {
			return err
		}

		sealed, err := provider.Encrypt(context.Background(), params, detail)
		if err != nil {
			return err
		}
		asset.Spec.SealingDetail = sealed
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

func main() {
	if err := rootCmd.Execute(); err != nil {
		panic(err)
		//os.Exit(1)
	}
}
