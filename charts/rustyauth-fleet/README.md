# rustyauth-fleet

Installs the central Fleet boundary: Dioxus WebAssembly dashboard gateway, one control-plane writer and one
persistent Fleet SableDB. It does not install managed realms; deploy each project/environment with the
`rustyauth-realm` chart and its own Secret, namespace, volume and recovery policy.

Create the expected Secret out-of-band, then install with a reviewed values file:

```sh
kubectl create namespace rustyauth-fleet
kubectl -n rustyauth-fleet create secret generic fleet-rustyauth-fleet-secrets \
  --from-literal=AUTH_MASTER_KEY_HEX="$(openssl rand -hex 32)" \
  --from-literal=BOOTSTRAP_TOKEN="$(openssl rand -base64 48)"
helm upgrade --install fleet ./charts/rustyauth-fleet \
  --namespace rustyauth-fleet --values fleet-values.yaml --wait
```

See [`docs/KUBERNETES.md`](../../docs/KUBERNETES.md) for the full Civo/K3s topology and operational notes.
