{{/*
Chart name, overridable.
*/}}
{{- define "netops.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully qualified app name.
*/}}
{{- define "netops.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Common labels.
*/}}
{{- define "netops.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "netops.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: netops
{{- end -}}

{{/*
Selector labels.
*/}}
{{- define "netops.selectorLabels" -}}
app.kubernetes.io/name: {{ include "netops.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
ServiceAccount name.
*/}}
{{- define "netops.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "netops.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Fully-qualified image reference. Tag falls back to the chart appVersion so a
release always pins something explicit rather than floating on :latest.
*/}}
{{- define "netops.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{/*
Namespace the kagent Agent / RemoteMCPServer objects land in. These must live in
a namespace the kagent controller watches (the homelab runs kagent in `ai`),
which is NOT necessarily the namespace the node DaemonSet is released into.
*/}}
{{- define "netops.agentNamespace" -}}
{{- default .Release.Namespace .Values.agent.namespace -}}
{{- end -}}
