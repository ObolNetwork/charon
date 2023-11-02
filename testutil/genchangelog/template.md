# {{.Tag}} - {{.Date}}

![Obol Logo](https://obol.tech/obolnetwork.png)

This release introduces general fixes and improvements including progress on great new features.

**Full Changelog**: [{{.RangeText}}]({{.RangeLink}})
{{range .Categories}}
## {{.Label}}
  {{- range .Issues}}
- {{.Title}} {{.Label}} ({{range $i, $v := .PRs}}{{if $i}},{{end}}{{$v.Label}}{{end}})
  {{- end}}
{{end}}

## What's Changed
{{range .ExtraPRs}}
- [{{.Title}}](https://github.com/ObolNetwork/charon/pull/{{.Number}})
{{end}}
