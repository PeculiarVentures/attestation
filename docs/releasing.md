# Releasing

The four public workspaces share one version and one `v<version>` Git tag. The root package is private and supplies the release version. `release-please` updates the root version, workspace versions, internal dependency ranges and package-lock.json in a release PR. Release notes are generated from Conventional Commits in the release PR description and published to [GitHub Releases](https://github.com/PeculiarVentures/attestation/releases) when that PR is merged. Changelog file generation is disabled with `skip-changelog` in `release-please-config.json`. Only `feat`, `fix`, `perf`, `build` and `revert` commits and breaking changes appear in the notes and request a release.

## One-time setup

Configure an npm Trusted Publisher for **each** package:

- `@peculiar/attestation-common`
- `@peculiar/attestation-marvell`
- `@peculiar/attestation-yubico`
- `@peculiar/attestation-cli`

Use the GitHub organization `PeculiarVentures`, repository `attestation`, workflow filename `publish.yml`, and environment `npm`. Permit direct publication with `npm publish`. The GitHub `npm` environment must allow deployments from release commits on `main` and stable `v*` tags. Add environment protection rules if your release policy requires them. Trusted publishing uses GitHub-hosted runners and needs npm >=11.5.1; the workflow runs Node 24. No npm token is used by this workflow.

If npm does not yet contain a newly added package, publish its first version with a maintainer account before configuring its trusted publisher. Existing packages can be configured in their npm package settings. See the [npm Trusted Publisher documentation](https://docs.npmjs.com/trusted-publishers/) for setup and activation requirements.

Optionally configure a `RELEASE_TOKEN` GitHub App token or fine-grained PAT that can create release PRs and releases. When the default `GITHUB_TOKEN` creates or updates a release PR, its CI runs require approval: a user with write access must select **Approve workflows to run** on the PR. A GitHub App or PAT can trigger CI without that approval prompt. This token is for GitHub operations only.

## Normal release

1. Merge reviewed changes to `main` using Conventional Commit subjects. `feat:` requests a minor release; `fix:` requests a patch. A `!` subject or `BREAKING CHANGE:` footer requests a major release, including the ESM-only migration.
2. The Release workflow runs the reusable Test workflow (`test.yml`) before invoking release-please. Release-please creates or updates a release PR with the next shared version and release notes in its description.
3. Review the release PR, including all four package versions, internal dependency ranges, lockfile and release notes. Run CI on that PR. Do not manually edit generated versions independently.
4. Merge the release PR. Release-please creates its immutable `v<version>` tag and the GitHub Release with the notes from the PR. The publication job verifies the release commit SHA, builds that commit and publishes using OIDC with npm provenance.

To change the notes of a merged commit, add a `BEGIN_COMMIT_OVERRIDE` … `END_COMMIT_OVERRIDE` block with the replacement commit message to that PR's description before the release PR is merged; release-please uses it instead of the squash commit.

The publication job checks that every package has the root version, then publishes dependencies before their dependents (`common`, then `marvell` and `yubico`, then `cli`) and skips versions that `npm view` already finds on npm. The `v<major>` Git tag is moved after successful publication, provided the version is the latest stable tag in that major.

The publication job uses `npm ci --ignore-scripts` and publishes with lifecycle scripts disabled. The explicit build and package export check run before publishing. Do not introduce dependencies that require installation scripts for the release build without adjusting this process.

## Retry a failed or partial publication

Open **Actions → Release → Run workflow** and select the existing `v<version>` tag. Branch refs and tags that disagree with the package version are rejected. Do not rerun from `main`, change package versions or move the release tag.

The retry builds the same tagged source and skips exact package versions already present on npm. It stops at the first publication failure, so remaining dependents can be published by another retry after fixing access or registry availability. Check all four npm versions after a successful run.

Retry a partial release before creating a newer release: `npm publish` tags what it publishes as `latest`, so retrying an older version after a newer one has shipped would move `latest` backwards. Publish such a version by hand with a maintenance dist-tag instead.
