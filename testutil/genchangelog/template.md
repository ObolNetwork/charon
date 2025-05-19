# {{.Tag}} - {{.Date}}

![Obol Logo](https://obol.tech/obolnetwork.png)

<!-- TODO: Add resume of the release in free text -->

Read the rest of the release notes for more:

**Full Changelog**: [{{.RangeText}}]({{.RangeLink}})
{{range .Categories}}
## {{.Label}}
  {{- range .Issues}}
- {{.Title}} {{.Label}} ({{range $i, $v := .PRs}}{{if $i}},{{end}}{{$v.Label}}{{end}})
  {{- end}}
{{end}}
## Compatibility Matrix

<!-- TODO: Update versions with which this version is compatible -->
This release of Charon is backwards compatible with Charon v1.0, v1.1, v1.2.

The below matrix details a combination of beacon node (consensus layer) + validator clients and their corresponding versions the DV Labs team have tested with this Charon release. More validator and consensus client will be added to this list as they are supported in our automated testing framework.

**Legend**
- ✅: All duties succeed in testing
- 🟡: All duties succeed in testing, except non-penalised aggregation duties
- 🟠: Duties may fail for this combination
- 🔴: One or more duties fails consistently

<!-- TODO: Update clients versions, results and remarks -->
| Validator 👉 Consensus 👇 | Teku v25.3.0 | Lighthouse v7.0.0 | Lodestar v1.28.1 | Nimbus v25.3.1 | Prysm v5.3.1 | Vouch v1.10.2 | Remarks |
|---------------------------|--------------|-------------------|------------------|----------------|--------------|---------------|---------|
| Teku v25.3.0              |       ✅     |         ✅        |        ✅        |       ✅       |       ✅     |       ✅      |         |
| Lighthouse v7.0.0         |       ✅     |         ✅        |        ✅        |       ✅       |       ✅     |       ✅      |         |
| Lodestar v1.28.1          |       ✅     |         ✅        |        ✅        |       ✅       |       ✅     |       ✅      |         |
| Nimbus v25.3.1            |       ✅     |         ✅        |        ✅        |       ✅       |       ✅     |       ✅      |         |
| Prysm v5.3.1              |       ✅     |         ✅        |        ✅        |       ✅       |       ✅     |       ✅      |         |
| Grandine v1.1.0           |       ✅     |         ✅        |        ✅        |       ✅       |       ✅     |       ✅      |         |

## What's Changed
{{range .ExtraPRs}}
- [{{.Title}}](https://github.com/ObolNetwork/charon/pull/{{.Number}})
{{end}}
