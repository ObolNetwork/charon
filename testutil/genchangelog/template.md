# {{.Tag}} - {{.Date}}

![Obol Logo](https://obol.tech/obolnetwork.png)

<!-- TODO: Add a summary of the release in free text -->

Read the rest of the release notes for more:

**Full Changelog**: [{{.RangeText}}]({{.RangeLink}})
{{range .Categories}}
## {{.Label}}
  {{- range .Issues}}
- {{.Title}} {{.Label}} ({{range $i, $v := .PRs}}{{if $i}},{{end}}{{$v.Label}}{{end}})
  {{- end}}
{{end}}
## Compatibility Matrix

This release of Charon is backwards compatible with Charon >= v1.0., though *only v1.7.* and newer are Fulu-ready.

The below matrix details a combination of beacon node (consensus layer) + validator clients and their corresponding versions the DV Labs team have tested with this Charon release. More validator and consensus clients will be added to this list as they are supported in our automated testing framework.

**Legend**
- ✅: All duties succeed in testing
- 🟡: All duties succeed in testing, except non-penalised aggregation duties
- 🟠: Duties may fail for this combination
- 🔴: One or more duties fail consistently

| Validator 👉 Consensus 👇 | Teku {{.Clients.Teku}} | Lighthouse {{.Clients.Lighthouse}} | Lodestar {{.Clients.Lodestar}} | Nimbus {{.Clients.Nimbus}} | Prysm {{.Clients.Prysm}} | Vouch {{.Clients.Vouch}} [❗](## "Vouch VC aggregations and sync contributions are not yet supported by Attestant team.") |
|---------------------------|--------------|-------------------|------------------|----------------|--------------|---------------|
| Teku {{.Clients.Teku}} [❗](## "Teku BN needs the `--validators-graffiti-client-append-format=DISABLED` flag in order to produce blocks properly.") |       ✅     |         ✅        |        ✅        |       ✅       |       ✅     |       🟡      |
| Lighthouse {{.Clients.Lighthouse}}         |       ✅     |         ✅        |        ✅        |       ✅       |       ✅     |       🟡      |
| Lodestar {{.Clients.Lodestar}}          |       ✅     |         ✅        |        ✅        |       ✅       |       ✅     |       🟡      |
| Nimbus {{.Clients.Nimbus}}            |       ✅     |         ✅        |        ✅        |       ✅       |       ✅     |       🟡      |
| Prysm {{.Clients.Prysm}}              |       ✅     |         ✅        |        ✅        |       ✅       |       ✅     |       🟡      |
| Grandine {{.Clients.Grandine}}           |       ✅     |         ✅        |        ✅        |       ✅       |       ✅     |       🟡      |

## What's Changed
{{range .ExtraPRs}}
- [{{.Title}}](https://github.com/ObolNetwork/charon/pull/{{.Number}})
{{end}}
