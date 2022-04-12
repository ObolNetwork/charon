# {{.Tag}} - {{.Date}}

This release introduces general fixes and improvements including progress on great new features.

**Full Changelog**: [{{.RangeText}}]({{.RangeLink}})
{{range .Categories}}
## {{.Label}}
  {{- range .Issues}}
- {{.Title}} {{.Label}} ({{range $i, $v := .PRs}}{{if $i}},{{end}}{{$v.Label}}{{end}})
  {{- end}}
{{end}}
