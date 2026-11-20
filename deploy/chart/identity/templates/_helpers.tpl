{{- define "identity.namespace" -}}zeabur-identity{{- end }}

{{- define "identity.labels" -}}
app.kubernetes.io/name: zeabur-identity
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end }}

{{- define "identity.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.Version }}
{{- end -}}
{{- end }}

{{/* The domain: global.domain, else <ip>.sslip.io from the first node's address. */}}
{{- define "identity.domain" -}}
{{- if .Values.global.domain -}}
{{ .Values.global.domain }}
{{- else -}}
{{- $ip := "" -}}
{{- range $node := (lookup "v1" "Node" "" "").items | default list -}}
{{- if not $ip -}}
{{- range $node.status.addresses -}}{{- if and (eq .type "ExternalIP") (not $ip) -}}{{- $ip = .address -}}{{- end -}}{{- end -}}
{{- range $node.status.addresses -}}{{- if and (eq .type "InternalIP") (not $ip) -}}{{- $ip = .address -}}{{- end -}}{{- end -}}
{{- end -}}
{{- end -}}
{{- required "global.domain is required when the chart cannot read the cluster's nodes (helm template)" $ip -}}.sslip.io
{{- end -}}
{{- end }}

{{- define "identity.issuer" -}}
{{- $issuer := .Values.issuer -}}
{{- if not $issuer -}}
{{- $issuer = printf "https://identity.%s" (include "identity.domain" .) -}}
{{- end -}}
{{- if not (regexMatch "^https://[^/]+$" $issuer) -}}
{{- fail (printf "issuer must be https:// and a host with no path, not %q" $issuer) -}}
{{- end -}}
{{ $issuer }}
{{- end }}

{{- define "identity.host" -}}
{{ include "identity.issuer" . | trimPrefix "https://" }}
{{- end }}

{{/* The setup token, made once per render and shared by the hook Job and NOTES. */}}
{{- define "identity.setupToken" -}}
{{- if not (hasKey .Values "_setupToken") -}}
{{- $_ := set .Values "_setupToken" (randAlphaNum 43) -}}
{{- end -}}
{{ .Values._setupToken }}
{{- end }}
