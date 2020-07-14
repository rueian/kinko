# Kinko for kubernetes

Kinko is a Kubernetes CRD controller that does the same thing as the [bitnami-labs/sealed-secrets](https://github.com/bitnami-labs/sealed-secrets), but in a much simpler way with the help of the external KMS provider.

# Comparison to the bitnami-labs/sealed-secrets
The Same:
* `kinko` CLI to create sealed CRDs that can be saved into a VCS.
* `kinko` CRD controller that unseals the sealed CRDs into normal k8s secrets.

The Different:
* There is no RSA key pair maintained by `kinko`. Instead, the Data Encryption Key (DEK) is encrypted by the external KMS provider. 
* The `kinko` CRD controller should have the decryption permission on the external KMS provider to decrypt the DEK.
* Anyone having the decryption permission can decrypt the DEK as well. It is not forced that the CRD controller be the only one who can unseal the secret.
* Currently, only support Google Cloud KMS.