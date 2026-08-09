{{- define "rustyauth-fleet.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- define "rustyauth-fleet.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 48 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}{{ .Release.Name | trunc 48 | trimSuffix "-" }}{{- else -}}{{ printf "%s-%s" .Release.Name $name | trunc 48 | trimSuffix "-" }}{{- end -}}
{{- end -}}
{{- end -}}
{{- define "rustyauth-fleet.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | quote }}
app.kubernetes.io/name: {{ include "rustyauth-fleet.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: rustyauth
{{- end -}}
{{- define "rustyauth-fleet.image" -}}
{{- if .digest }}{{ printf "%s@%s" .repository .digest }}{{- else }}{{ printf "%s:%s" .repository .tag }}{{- end }}
{{- end -}}
{{- define "rustyauth-fleet.secretName" -}}
{{- default (printf "%s-secrets" (include "rustyauth-fleet.fullname" .)) .Values.secrets.existingSecret -}}
{{- end -}}
{{- define "rustyauth-fleet.configMapName" -}}
{{- default (printf "%s-config" (include "rustyauth-fleet.fullname" .)) .Values.config.existingConfigMap -}}
{{- end -}}
{{- define "rustyauth-fleet.config" -}}
apiVersion: rustyauth.dev/v1alpha1
kind: FleetControlPlane
metadata:
  tenantId: {{ .Values.config.tenantId | quote }}
spec:
  environment: {{ .Values.config.environment | quote }}
  server:
    bind: 0.0.0.0
    port: 8080
    publicIssuer: {{ .Values.config.publicIssuer | quote }}
    trustedProxyHops: {{ .Values.config.trustedProxyHops }}
  datastore:
    endpoint: {{ printf "redis://%s-sabledb.%s.svc.%s:6379" (include "rustyauth-fleet.fullname" .) .Release.Namespace .Values.clusterDomain | quote }}
  relyingParty:
    id: {{ .Values.config.relyingParty.id | quote }}
    origin: {{ .Values.config.relyingParty.origin | quote }}
    name: {{ .Values.config.relyingParty.name | quote }}
  tokens:
    accessTtl: {{ .Values.config.tokens.accessTtl | quote }}
  sessions:
    idleTimeout: {{ .Values.config.sessions.idleTimeout | quote }}
    absoluteTimeout: {{ .Values.config.sessions.absoluteTimeout | quote }}
  events:
    retention: {{ .Values.config.events.retention | quote }}
  signingKeys:
    rotateEvery: {{ .Values.config.signingKeys.rotateEvery | quote }}
    prepublishFor: {{ .Values.config.signingKeys.prepublishFor | quote }}
    overlapFor: {{ .Values.config.signingKeys.overlapFor | quote }}
    maintenanceInterval: {{ .Values.config.signingKeys.maintenanceInterval | quote }}
  operators:
{{- if .Values.config.operators.bootstrapEmails }}
    bootstrapEmails:
{{- range .Values.config.operators.bootstrapEmails }}
      - {{ . | quote }}
{{- end }}
{{- else }}
    bootstrapEmails: []
{{- end }}
  backups:
    enabled: false
  analytics:
    enabled: false
{{- end -}}
