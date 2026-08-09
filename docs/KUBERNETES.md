# Kubernetes and Civo K3s deployment

RustyAuth provides three versioned Helm charts. Choose a chart per trust and recovery boundary rather than
installing one oversized cluster-wide release.

| Chart | Public entry point | Private services | Intended boundary |
| --- | --- | --- | --- |
| `rustyauth-integrated` | Dashboard gateway | Realm API and Realm SableDB | One standalone application environment |
| `rustyauth-fleet` | Fleet dashboard gateway | Fleet control plane and Fleet SableDB | One central management plane |
| `rustyauth-realm` | Realm API | Realm SableDB | One lightweight Fleet-managed project environment |

The Dioxus web application in the dashboard image is compiled to WebAssembly. Its same-origin Caddy gateway,
the Rust/Axum API and SableDB are native Linux binaries in scratch containers. WebAssembly is therefore the
browser delivery format, not the server runtime. Current release images are `linux/amd64`; schedule them only
on compatible nodes until multi-architecture images are qualified.

RustyAuth remains `0.1.0` pre-release software. The charts are suitable for evaluation and integration work;
they do not remove the production qualification gates in [Release readiness](RELEASE_READINESS.md).

## Civo/K3s prerequisites

Civo Kubernetes uses K3s and supplies standard Kubernetes and Helm APIs. Its default application set includes
Traefik, which matches the charts' default `ingress.className`. Confirm the active classes rather than assuming
the cluster was created with defaults:

```sh
kubectl get nodes
kubectl get ingressclass
kubectl get storageclass
```

The charts leave `sabledb.persistence.storageClass` empty so the cluster default is selected. On a default Civo
cluster this is normally `civo-volume`. Civo's StorageClass uses a `Delete` reclaim policy, so each chart marks
the SableDB PVC with `helm.sh/resource-policy: keep` by default. An uninstall therefore leaves identity state
behind for explicit recovery or deletion.

TLS is still required for production WebAuthn origins. Configure a certificate controller or a pre-created TLS
Secret and add it under `ingress.tls`; Traefik does not create a publicly trusted certificate by itself.

## Install an integrated realm

Create `integrated-values.yaml` and replace every example origin:

```yaml
config:
  tenantId: acme
  realmId: production
  publicIssuer: https://auth.acme.example
  relyingParty:
    id: auth.acme.example
    origin: https://auth.acme.example
    name: Acme Account
  tokens:
    audience: acme-api
    accessTtl: 5m
  operators:
    bootstrapEmails:
      - owner@acme.example

ingress:
  enabled: true
  className: traefik
  hosts:
    - host: auth.acme.example
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: auth-acme-tls
      hosts:
        - auth.acme.example
```

Create credentials out-of-band. The default Secret name combines the release and chart names:

```sh
kubectl create namespace rustyauth
kubectl -n rustyauth create secret generic auth-rustyauth-integrated-secrets \
  --from-literal=AUTH_MASTER_KEY_HEX="$(openssl rand -hex 32)" \
  --from-literal=BOOTSTRAP_TOKEN="$(openssl rand -base64 48)" \
  --from-literal=AUTH_EVENT_RPC_TOKEN="$(openssl rand -base64 48)" \
  --from-literal=AUTH_IDENTITY_RPC_TOKEN="$(openssl rand -base64 48)"
```

Install from a checked-out repository while developing:

```sh
helm upgrade --install auth ./charts/rustyauth-integrated \
  --namespace rustyauth \
  --values integrated-values.yaml \
  --wait --atomic
```

Tagged releases attach version-matched chart archives. After a release is published, the equivalent pinned
install is:

```sh
VERSION=0.1.0
CHART=https://github.com/rusty-auth/rustyauth/releases/download/v$VERSION/rustyauth-integrated-$VERSION.tgz
helm upgrade --install auth "$CHART" \
  --namespace rustyauth \
  --values integrated-values.yaml \
  --wait --atomic
```

Do not pass credentials with Helm `--set`: Helm stores release values. Use a pre-created Secret, a sealed-secret
workflow or an external secret controller and set `secrets.existingSecret` when its name differs from the
chart default.

## Install Fleet and lightweight realms

Fleet is one central deployment. Every managed environment is a separate realm release and should normally
have its own namespace:

```text
rustyauth-fleet namespace
  Fleet WASM dashboard gateway -> Fleet control plane -> Fleet SableDB PVC

acme-production namespace
  Realm API -> Realm SableDB PVC

acme-staging namespace
  Realm API -> Realm SableDB PVC
```

For Fleet, create a values file with the Fleet dashboard origin and then install the central chart:

```sh
kubectl create namespace rustyauth-fleet
kubectl -n rustyauth-fleet create secret generic fleet-rustyauth-fleet-secrets \
  --from-literal=AUTH_MASTER_KEY_HEX="$(openssl rand -hex 32)" \
  --from-literal=BOOTSTRAP_TOKEN="$(openssl rand -base64 48)"
helm upgrade --install fleet ./charts/rustyauth-fleet \
  --namespace rustyauth-fleet \
  --values fleet-values.yaml \
  --wait --atomic
```

For each realm, use distinct credentials and values. The relying-party origin is the application using
passkeys; the public issuer is the exposed Realm API:

```yaml
config:
  tenantId: acme
  realmId: payments-production
  publicIssuer: https://payments-auth.acme.example
  relyingParty:
    id: payments.acme.example
    origin: https://payments.acme.example
    name: Acme Payments
  tokens:
    audience: payments-api
    accessTtl: 5m

ingress:
  enabled: true
  hosts:
    - host: payments-auth.acme.example
      paths:
        - path: /
          pathType: Prefix
```

```sh
kubectl create namespace acme-payments-production
kubectl -n acme-payments-production create secret generic realm-rustyauth-realm-secrets \
  --from-literal=AUTH_MASTER_KEY_HEX="$(openssl rand -hex 32)" \
  --from-literal=BOOTSTRAP_TOKEN="$(openssl rand -base64 48)" \
  --from-literal=AUTH_EVENT_RPC_TOKEN="$(openssl rand -base64 48)" \
  --from-literal=AUTH_IDENTITY_RPC_TOKEN="$(openssl rand -base64 48)"
helm upgrade --install realm ./charts/rustyauth-realm \
  --namespace acme-payments-production \
  --values realm-values.yaml \
  --wait --atomic
```

Pair that public Realm management endpoint through the normal [Fleet pairing workflow](FLEET_CONTROL_PLANE.md).
Fleet never receives the realm's database URL, volume or encryption keys.

## Configuration, secrets and backups

The chart-generated ConfigMap covers the safe baseline configuration and disables backups and Fleet analytics.
For the full configuration contract—backups, webhooks or Analytics—create a ConfigMap from a reviewed YAML
document and select it with `config.existingConfigMap` and `config.existingConfigMapKey`:

```sh
kubectl -n rustyauth create configmap auth-policy \
  --from-file=config.yaml=rustyauth.production.yaml
helm upgrade auth ./charts/rustyauth-integrated \
  --namespace rustyauth \
  --set config.existingConfigMap=auth-policy \
  --set config.existingConfigMapKey=config.yaml \
  --reuse-values --wait
```

An external production document must use the chart's fully qualified private datastore endpoint, for example
`redis://auth-rustyauth-integrated-sabledb.rustyauth.svc.cluster.local:6379`. Short Service names are rejected
in production. Keep backup bucket credentials and encryption keys in the selected Secret, never the ConfigMap.

Changing a chart-generated ConfigMap rolls the writer. Kubernetes cannot detect the contents of an externally
managed ConfigMap or Secret through Helm, so restart the affected writer after rotating either one:

```sh
kubectl -n rustyauth rollout restart deployment/auth-rustyauth-integrated-api
kubectl -n rustyauth rollout status deployment/auth-rustyauth-integrated-api
```

## Upgrades and removal

Version `0.1` supports one writer. The schema rejects a second API/control-plane replica, and writer Deployments
use `Recreate` so an upgrade does not intentionally overlap two pods. Expect a short authentication outage and
allow for the existing writer lease to expire if a node failed without a clean shutdown.

Before upgrading, create and verify a logical backup, pin image digests where possible, render the change and
then apply it:

```sh
helm template auth ./charts/rustyauth-integrated \
  --namespace rustyauth --values integrated-values.yaml > rendered.yaml
helm upgrade auth ./charts/rustyauth-integrated \
  --namespace rustyauth --values integrated-values.yaml --wait --atomic
```

`helm uninstall` removes workloads but retains the default PVC. Confirm the exact claim before deleting it;
PVC deletion is the operation that can trigger Civo's underlying volume deletion:

```sh
kubectl -n rustyauth get pvc
```

## Chart validation

CI lints and renders every chart with Helm 4, checks the private datastore DNS and hardening controls, and
proves that a second writer is rejected:

```sh
scripts/check-helm.sh
```
