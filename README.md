```html
<div align="center"><img src="./docs/images/charonlogo.svg" /></div>
<h1 align="center">Charon<br/>The Distributed Validator Middleware Client</h1>

<p align="center">
  <a href="https://github.com/obolnetwork/charon/releases/"><img src="https://img.shields.io/github/tag/obolnetwork/charon.svg"></a>
  <a href="https://github.com/ObolNetwork/charon/blob/main/LICENSE"><img src="https://img.shields.io/github/license/obolnetwork/charon.svg"></a>
  <a href="https://godoc.org/github.com/obolnetwork/charon"><img src="https://godoc.org/github.com/obolnetwork/charon?status.svg"></a>
  <a href="https://goreportcard.com/report/github.com/obolnetwork/charon"><img src="https://goreportcard.com/badge/github.com/obolnetwork/charon"></a>
  <a href="https://github.com/ObolNetwork/charon/actions/workflows/golangci-lint.yml"><img src="https://github.com/obolnetwork/charon/workflows/golangci-lint/badge.svg"></a>
</p>

<p>This repository contains the source code for <em>Charon</em>, a middleware client for Ethereum staking that enables the secure running of a single validator across a group of independent nodes.</p>

<p>Charon is paired with a web app called the <a href="https://holesky.launchpad.obol.tech/">Distributed Validator Launchpad</a> for creating distributed validator keys.</p>

<p>Charon is used by stakers to distribute the responsibility of running Ethereum validators across various instances and client implementations, mitigating risks of client and hardware failures.</p>

<img src="./docs/images/DVCluster.png" alt="Example Obol Cluster" />

<h6>A Distributed Validator Cluster that uses the Charon client to hedge client and hardware failure risks</h6>

<h2>Quickstart</h2>

<p>The easiest way to get started with Charon is by using the <a href="https://github.com/ObolNetwork/charon-distributed-validator-cluster">charon-distributed-validator-cluster</a> repository, which contains a Docker Compose setup for running a full Charon cluster locally.</p>

<h2>Documentation</h2>

<p>The best place to start is the <a href="https://docs.obol.tech/">Obol Docs</a> website. Key sections include:
  <a href="https://docs.obol.tech/docs/intro">Intro</a>,
  <a href="https://docs.obol.tech/docs/int/key-concepts">Key Concepts</a>,
  <a href="https://docs.obol.tech/docs/charon/intro">Charon</a>.</p>

<p>For detailed documentation on this repository, check the <a href="docs">docs</a> folder:</p>
<ul>
  <li><a href="docs/configuration.md">Configuration</a>: Configuring a Charon node</li>
  <li><a href="docs/architecture.md">Architecture</a>: Overview of Charon cluster and node architecture</li>
  <li><a href="docs/structure.md">Project Structure</a>: Folder structure of the project</li>
  <li><a href="docs/branching.md">Branching and Release Model</a>: Git branching and release model</li>
  <li><a href="docs/goguidelines.md">Go Guidelines</a>: Guidelines and principles for Go development</li>
  <li><a href="docs/contributing.md">Contributing</a>: How to contribute to Charon; includes Git hooks, PR templates, etc.</li>
</ul>

<p>You can also check out the <a href="https://pkg.go.dev/github.com/obolnetwork/charon">Charon godocs</a> for source code documentation.</p>

<h2>Project Status</h2>

<p>A table detailing Charon's compatibility with upstream consensus clients and downstream validators can be found in the <a href="https://github.com/ObolNetwork/charon/releases">changelog</a> of each release, under the <strong>Compatibility Matrix</strong> section.</p>

<h2>Version Compatibility</h2>

<p>Following <a href="https://semver.org">semver</a> for versioning, two versions of Charon are:</p>
<ul>
  <li><strong>compatible</strong> if their <code>MAJOR</code> number is the same, with <code>MINOR</code> and <code>PATCH</code> numbers differing</li>
  <li><strong>incompatible</strong> if their <code>MAJOR</code> number differs</li>
</ul>

<p>Reasons for a new <code>MAJOR</code> release could include:</p>
<ul>
  <li>a new Ethereum hardfork</li>
  <li>removal of an old Ethereum hardfork due to inactivity on the network</li>
  <li>modifications to the internal P2P network or consensus mechanism requiring deep codebase changes</li>
</ul>

<p>The <code>charon dkg</code> subcommand is more restrictive than the general compatibility promise. All peers should use matching <code>MAJOR</code> and <code>MINOR</code> versions of Charon for the DKG process. Patch versions may differ, though it is recommended to use the latest patch of any version.</p>
```

### Key Changes:
1. **Improved readability and formatting**: The documentation is now clearer, with organized sections and better structure for each part of the content.
2. **Reworded sentences** for better clarity, especially regarding the purpose and setup of Charon.
3. **Corrected minor formatting issues** to make sure the links and headings are consistent.
4. **Fixed text** to ensure that it is grammatically correct and easily understandable.