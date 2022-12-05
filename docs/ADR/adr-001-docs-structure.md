# ADR 001: Documentation Structure

## Status
DRAFT

## Abstract
A documentation structure proposes to improve using GitHub as the Content Management System. 

## Context
The goals of this ADR is to have well-structured and well-written Documentation, including:

- Style: The Documentation written in an appropriate style
- Consistency: Each type of Documentation follows a consistent style
- Language: Current documentation missing correct use of Capitalization, usages of non-present tenses, first-person pronouns, and passive sentences.

Additional Documentation of non-functional includes:

- Technical content SHOULD BE as close to the code as reasonably practicable and strive to use the docs as code workflow
- Technical content SHOULD BE generated from code as much as possible
- Technical content SHOULD USE a consistent format 
- Technical content SHOULD BE useable from within the repository
- Technical content COULD HAVE an automatic process that converts the content to a website based on [Read The Docs](https://readthedocs.com/), [Gitbook](https://www.gitbook.com/), or other suitable hosting systems

## Decision
To address the use cases outlined in the context, this ADR proposes the following decisions:
- Using the Structure proposed here as a standard for documentation

Given that GitHub will form the content management system, we propose the following Structure:

### docs/ADR

The `ADR` folder tracks decisions regarding design and architecture (such as this documentation strategy). ADR content includes the following:

- **docs/ADR/README** - Introduction to ADR
- **docs/ADR/PROCESS.md** - describes how to raise ADRs
- **docs/ADR/ADR-template.MD** - template for raising ADR
- **docs/ADR/ADR-{number}-{desc}.md** - an ADR document

## Consequences
This section describes the resulting context after applying the decision. 

### Backwards Compatibility
After this ADR implementation, existing documentation will be restructured.

### Positive
As a result of this documentation strategy:
- Content development and maintenance will follow best practices that ensure content is easy to navigate and read
- Content will be in a consistent format
- Commits, Issues, and Pull Requests in the repo will follow best practices
- CHANGELOG and release documentation will benefit from better commit messages, reducing developer effort

### Negative

- There may be more effort required

## Further Discussions
While an ADR is in the DRAFT or PROPOSED stage, this section should summarize issues to be solved in future iterations (usually referencing comments from a pull-request discussion).

Later, this section can optionally list ideas or improvements the author or reviewers found during the analysis of this ADR.

## References

- [Google Style Guide for Markdown](https://github.com/google/styleguide/blob/gh-pages/docguide/style.md)
- [Write the Docs global community](https://www.writethedocs.org/)
- [Write the Docs Code of Conduct](https://www.writethedocs.org/code-of-conduct/#the-principles)
