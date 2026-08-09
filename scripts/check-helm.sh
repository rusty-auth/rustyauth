#!/usr/bin/env bash
set -euo pipefail

if ! command -v helm >/dev/null 2>&1; then
  echo "helm is required to validate charts" >&2
  exit 1
fi

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
render_dir="$(mktemp -d)"
trap 'rm -rf "${render_dir}"' EXIT

charts=(rustyauth-integrated rustyauth-fleet rustyauth-realm)
for chart_name in "${charts[@]}"; do
  chart_path="${repository_root}/charts/${chart_name}"
  rendered_path="${render_dir}/${chart_name}.yaml"
  secret_rendered_path="${render_dir}/${chart_name}-with-secret.yaml"

  helm lint "${chart_path}"
  helm template smoke "${chart_path}" \
    --namespace rustyauth-smoke \
    --set ingress.enabled=true > "${rendered_path}"

  rg --quiet '^kind: NetworkPolicy$' "${rendered_path}"
  rg --quiet '^kind: PersistentVolumeClaim$' "${rendered_path}"
  rg --quiet 'helm.sh/resource-policy: keep' "${rendered_path}"
  rg --quiet 'readOnlyRootFilesystem: true' "${rendered_path}"
  rg --quiet 'runAsNonRoot: true' "${rendered_path}"
  rg --quiet '^kind: Ingress$' "${rendered_path}"
  rg --quiet "redis://smoke-${chart_name}-sabledb.rustyauth-smoke.svc.cluster.local:6379" "${rendered_path}"

  if rg --quiet '^kind: Secret$' "${rendered_path}"; then
    echo "${chart_name} rendered a Secret with the secure defaults" >&2
    exit 1
  fi

  secret_args=(
    --set secrets.create=true
    --set secrets.values.masterKeyHex=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
    --set secrets.values.bootstrapToken=bootstrap-token-longer-than-thirty-two-characters
  )
  if [[ "${chart_name}" != "rustyauth-fleet" ]]; then
    secret_args+=(
      --set secrets.values.eventRpcToken=event-token-longer-than-thirty-two-characters
      --set secrets.values.identityRpcToken=identity-token-longer-than-thirty-two-characters
    )
  fi
  helm template smoke "${chart_path}" --namespace rustyauth-smoke \
    "${secret_args[@]}" > "${secret_rendered_path}"
  rg --quiet '^kind: Secret$' "${secret_rendered_path}"
  rg --quiet 'AUTH_MASTER_KEY_HEX:' "${secret_rendered_path}"
  rg --quiet 'BOOTSTRAP_TOKEN:' "${secret_rendered_path}"
done

for chart_name in rustyauth-integrated rustyauth-realm; do
  rendered_path="${render_dir}/${chart_name}.yaml"
  rg --quiet 'AUTH_EVENT_RPC_TOKEN:' "${render_dir}/${chart_name}-with-secret.yaml"
  rg --quiet 'AUTH_IDENTITY_RPC_TOKEN:' "${render_dir}/${chart_name}-with-secret.yaml"
  rg --quiet 'type: Recreate' "${rendered_path}"
done

rg --quiet 'type: Recreate' "${render_dir}/rustyauth-fleet.yaml"
rg --quiet 'app.kubernetes.io/component: control-plane' "${render_dir}/rustyauth-fleet.yaml"

if helm template invalid "${repository_root}/charts/rustyauth-integrated" \
  --set api.replicaCount=2 >/dev/null 2>&1; then
  echo "rustyauth-integrated accepted an unsupported second writer" >&2
  exit 1
fi
if helm template invalid "${repository_root}/charts/rustyauth-fleet" \
  --set controlPlane.replicaCount=2 >/dev/null 2>&1; then
  echo "rustyauth-fleet accepted an unsupported second writer" >&2
  exit 1
fi
if helm template invalid "${repository_root}/charts/rustyauth-realm" \
  --set api.replicaCount=2 >/dev/null 2>&1; then
  echo "rustyauth-realm accepted an unsupported second writer" >&2
  exit 1
fi

echo "validated ${#charts[@]} RustyAuth Helm charts"
