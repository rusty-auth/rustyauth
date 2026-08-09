# rustyauth-realm

Installs a lightweight Realm boundary for one project environment: one Rust API writer and one persistent
SableDB. It intentionally omits the dashboard. Deploy the dashboard once with `rustyauth-fleet`, then keep
every realm's identities, sessions, keys, Secret, volume and backups isolated.

```sh
kubectl create namespace project-production
kubectl -n project-production create secret generic realm-rustyauth-realm-secrets \
  --from-literal=AUTH_MASTER_KEY_HEX="$(openssl rand -hex 32)" \
  --from-literal=BOOTSTRAP_TOKEN="$(openssl rand -base64 48)" \
  --from-literal=AUTH_EVENT_RPC_TOKEN="$(openssl rand -base64 48)" \
  --from-literal=AUTH_IDENTITY_RPC_TOKEN="$(openssl rand -base64 48)"
helm upgrade --install realm ./charts/rustyauth-realm \
  --namespace project-production --values realm-values.yaml --wait
```

See [`docs/KUBERNETES.md`](../../docs/KUBERNETES.md) for ingress, Fleet pairing and upgrades.
