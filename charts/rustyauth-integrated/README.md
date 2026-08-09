# rustyauth-integrated

Installs one self-contained RustyAuth realm: the Dioxus WebAssembly dashboard gateway, one Rust API writer and
one persistent SableDB instance. Only the dashboard Service is an ingress target; the API and datastore remain
cluster-private.

```sh
kubectl create namespace rustyauth
kubectl -n rustyauth create secret generic auth-rustyauth-integrated-secrets \
  --from-literal=AUTH_MASTER_KEY_HEX="$(openssl rand -hex 32)" \
  --from-literal=BOOTSTRAP_TOKEN="$(openssl rand -base64 48)" \
  --from-literal=AUTH_EVENT_RPC_TOKEN="$(openssl rand -base64 48)" \
  --from-literal=AUTH_IDENTITY_RPC_TOKEN="$(openssl rand -base64 48)"
helm upgrade --install auth ./charts/rustyauth-integrated \
  --namespace rustyauth --values my-values.yaml --wait
```

The release name determines the default Secret name. Set `secrets.existingSecret` when using another name or
an external secret controller. Do not pass credentials with `--set`: Helm stores release values.

The default PVC carries `helm.sh/resource-policy: keep`, so uninstalling the release does not delete identity
state. Delete that PVC only as an explicit destructive operation. See [`docs/KUBERNETES.md`](../../docs/KUBERNETES.md).
