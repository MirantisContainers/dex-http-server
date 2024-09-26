{{- define "dex-http-server.params" -}}
{{- if .Values.grpc.server -}}
- --grpc-server={{.Values.grpc.server | trim }}
{{- end }}
{{- end -}}
