# Charon Branching and Release Model

We follow [Trunk Based Development](https://trunkbaseddevelopment.com/) as the branching model for this repository.

> Trunk-based development has been identified by the [DORA research program](https://www.devops-research.com/research.html) as one of the capabilities that drive higher software delivery and organizational performance.

![Trunk Based Development](images/trunkbaseddev.png)

## Overview:

- Another way to think of it: *micro-commits on a stable master*.
- We simply refer to our trunk/master branch as "main".
- A single GitHub issue can (and likely should) be broken into multiple incremental "micro-commits" / "micro-PRs" / "short-lived feature branches".
- Large features/tickets/changes are split into multiple sequential micro-commits, each introducing a small incremental change. All while never breaking the trunk!
- CI is run on each commit to trunk, and if a failure is detected, fixing it is the highest priority for the team as it acts as a global blocker.
- Micro-commits ensure fast and early code reviews, which improves velocity and increases alignment.
- Micro-commits are pushed for review and then squash-merged into trunk. This process repeats until the ticket or feature is completed.
- Stacked diffs (multiple open dependent PRs) are possible but often require tricky rebases followed by force-pushes that may make PR comments outdated.

## Controlled Introduction of Change:

- Since a feature cannot be added as a single big merge from a large feature branch, tools and patterns are necessary to allow gradual, controlled introduction of incremental changes without breaking the code.
- New code can initially be added as “dead code”, meaning it hasn’t yet been integrated into the actual program. Once it is complete, it can be integrated into the program in a single PR.
- Some features should not be enabled directly in prod/mainnet but should be rolled out gradually: first tested in `alpha` (internal devnet only), then `beta` (internal and external testnet), and only then in `stable` (enabled everywhere). This can be achieved through simple [feature switches](https://trunkbaseddevelopment.com/feature-flags/) (if statements) that enable features based on their `feature_set` status.
- Another effective pattern for gradual feature introduction is [branching by abstraction](https://trunkbaseddevelopment.com/branch-by-abstraction/). This introduces an abstraction layer where a new feature must replace an old feature (like an interface). Using dependency injection, the new feature can be integrated during testing/staging while the old feature remains in production.
- Both feature switches and abstraction layers used to roll out a feature should be removed once the feature is fully released to prod/mainnet.

### Release Process

Charon is set up to create releases using Github Actions, triggered by tags. To create a new release, follow this process:

Key aspects of the release process:
- Releases are cut from release branches, not the main branch. Release branches are named `main-v0.X`.
- Release candidates, `v0.X.Y-rc[1-99]`, are created for each patch release from commits in the release branch. These are thoroughly tested both internally and externally before the official release is created.
- Critical patches and fixes are cherry-picked from the main branch into the release branch.
- The Charon binary version, `charon version`, is determined by Git tags at build time using `ldflags`, not hardcoded app/version versions.
- Hardcoded Charon app/version is only used to indicate the branch type and major version, `v0.X-rc` for release branches or `v0.Y-dev` for the main branch.

The process for creating the v0.16.0 release is as follows:
1. Note that the previous release was v0.15.X.
2. When approaching a new release, the dev team appoints a "release captain" responsible for overseeing the release process.
3. The dev team focuses on tickets to be included in the release.
4. The team avoids adding risky or large changes during the "pre-release" period.
5. Once all relevant changes have been merged into the main branch, a new release branch is created. It must be called `main-v0.16`.
   - Release branches are considered high-risk and must be treated with the same level of security as the `main` branch.
   - Note that GitHub branch matching doesn’t support OR logic, so we chose a common `main*` prefix for all protected branches.
6. After the release branch has been created, the `main` branch app/version is manually updated to `v0.17-dev` and `v0.17` is added to the `version.Supported()` versions.
   - `v0.X-dev` indicates that the code is in the main branch, and it’s pre-release code, not an official release.
   - It signifies that all code in this version will be included in the `v0.17.0` release.
7. The first commit on the `main-v0.16` release branch must manually update the app/version to `v0.16-rc`.
   - `v0.X-rc` indicates that the code is in a release branch and includes cherry-picked commits and fixes for an official release.
8. To create a release (`v0.16.X[-rcY]`), someone with git tag privileges creates and pushes a git tag to the latest commit on the release branch.
   - The `build-push-release` action dynamically updates the app/version to the git tag value when building the Docker image.
9. Before creating a `v0.16.X` release, a release candidate (`v0.16.X-rc[1-99]`) should be created and thoroughly tested both internally and externally.
10. After the release is created, release notes should be generated.
   - The release GitHub action auto-generates release notes.
   - If the notes are incorrect, they can be manually generated with: `go run testutil/genchangelog/main.go --range=v0.15.0..v0.16.0`.

Images are built and tagged for each commit on the main and release branches using the app/version tag, e.g. `v0.X-dev` for `main`, and `v0.X-rc` for release branches. Main branch commits are also tagged with `latest`.

Any commit on main that affects backward compatibility must update `app/version.Supported` versions.

Commits on release branches **must not** affect backward compatibility or modify the `app/version.Supported` versions.