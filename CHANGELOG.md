# v0.0.0 - 2022-03-29

This release introduces general fixes and improvements including progress on great new features.

**Full Changelog**: [v0.1.1..HEAD](https://github.com/obolnetwork/charon/compare/v0.1.1..HEAD)

## Feature
- Implement SigEx v1 #167 (#194)
- app: integrate life cycle #162 (#162)
- Support configuring log format and level #296 (#297)
- Load private shares when running simnet #216 (#232)
- Implement SigAgg component #184 (#192)
- Implement ParSigDB #166 (#183)
- Create fetcher v1 for attester data #156 (#175)
- Improve gen-simnet run_cluster output #154 (#231)
- Implement validatorapi component #179 (#180)
- app/life: implement life cycle manager #161 (#161)

## Bug
- Ping logger concurrent map write #197 (#199)

## Refactor
- Simplify p2p flag names #151 (#152)
- Follow up on kryptology issues #168 (#188)
- Refactor core workflow types #163 (#174)
- Create scheduler v1  #145 (#149,#137,#144,#136)
- Introduce explicit core.Signature type #289 (#294)
- Integrate the simnet core workflow #203 (#206,#202,#205)
- Implement dutyDB v1 #165 (#182,#178)

## Docs
- Implement AggSigDB #220 (#249,#238)
- Add project structure docs #146 (#171,#155)

## Test
- Add integration unit test using one teku validator client #268 (#271)
- app: add teku simnet integration test #271 (#273)

## Misc
- Support lighthouse validator-client in a simnet cluster #251 (#265,#264,#263,#260,#259,#258,#252)
- Add and verify PR templates #239 (#241,#240)
