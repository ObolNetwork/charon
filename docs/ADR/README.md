# Architecture Decision Records (ADRs)

This section includes all high-level architecture decisions for the Charon.

### Definitions

Within the context of an ADR, we define the following:

- Architectural decision records (ADRs) describe a software design choice that addresses a functional or non-functional requirement that is architecturally significant.

- An architectural decision record (ADR) document describes a software design choice that addresses a functional or non-functional requirement that is architecturally significant. This project's collection of ADRs created and maintained constitutes its decision log. 

- An [architecturally significant requirement (ASR)](https://en.wikipedia.org/wiki/Architecturally_significant_requirements) is a requirement that has a measurable effect on a software system's architecture and quality.

All these records are within Architectural Knowledge Management (AKM).

You can read more about the ADR concept in the [adr.github.io](https://adr.github.io/).

## Rationale

ADRs intend to be the primary tool for proposing new feature designs and processes, gathering community feedback on a problem, and documenting design choices.

An ADR provides:

- Context on the relevant goals and the current state
- Proposed changes to achieve the goals
- Summary of pros and cons
- References
- Changelog

It is essential to understand the difference between an ADR and a specification. The ADR gives context, intuition, logic, and explanation for an architectural modification or the architecture of something new. The specification provides a synopsis of everything as it currently exists.

If the recorded decisions lack the necessary substance, the procedure is to hold a discussion, record the new decisions here, and then alter the code to reflect the new decisions.

## Creating new ADRs

See [ADR Creation Process](PROCESS.md).

#### Use RFC 2119 keywords

When writing ADRs, follow the best practices that apply to writing [RFCs](https://www.ietf.org/standards/rfcs/).

Keywords used to signify the requirements in the specification and often capitalized: 

- "MUST"
- "MUST NOT"
- "REQUIRED"
- "SHALL"
- "SHALL NOT"
- "SHOULD"
- "SHOULD NOT"
- "RECOMMENDED"
- "MAY"
- "OPTIONAL"

Keywords interpreted as described in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).
