# Releasing

The four public workspaces share one version and one `v<version>` Git tag. The root package is private and supplies the release version. `release-please` updates the root version, workspace versions, internal dependency ranges and package-lock.json in a release PR, and records release notes in the root CHANGELOG.md. Workspace CHANGELOG.md files contain historical notes; new releases use the root changelog.

## One-time setup

Configure an npm Trusted Publisher for **each** package:

- `@peculiar/attestation-common`
- `@peculiar/attestation-marvell`
- `@peculiar/attestation-yubico`
- `@peculiar/attestation-cli`

Use the GitHub organization `PeculiarVentures`, repository `attestation`, workflow filename `release.yml`, and environment `npm`. Permit direct publication with `npm publish`. The GitHub `npm` environment must allow deployments from release commits on `main` and stable `v*` tags. Add environment protection rules if your release policy requires them. Trusted publishing uses GitHub-hosted runners and needs npm >=11.5.1; the workflow runs Node 24. No npm token is used by this workflow.

If npm does not yet contain a newly added package, publish its first version with a maintainer account before configuring its trusted publisher. Existing packages can be configured in their npm package settings. See the [npm Trusted Publisher documentation](https://docs.npmjs.com/trusted-publishers/) for setup and activation requirements.

Optionally configure a `RELEASE_TOKEN` GitHub App token or fine-grained PAT that can create release PRs and releases. A PR created using the default `GITHUB_TOKEN` does not trigger other workflows; without `RELEASE_TOKEN`, run CI on the release PR manually before merging. This token is for GitHub operations only.

## Normal release

1. Merge reviewed changes to `main` using Conventional Commit subjects. `feat:` requests a minor release; `fix:` requests a patch. A `!` subject or `BREAKING CHANGE:` footer requests a major release, including the ESM-only migration.
2. The Release workflow runs the reusable CI workflow before invoking release-please. Release-please creates or updates a release PR with the next shared version and changelog.
3. Review the release PR, including all four package versions, internal dependency ranges, lockfile and changelog. Run CI on that PR. Do not manually edit generated versions independently.
4. Merge the release PR. Release-please creates its immutable `v<version>` tag and GitHub Release. The publication job verifies the release commit SHA, builds that commit and publishes using OIDC with npm provenance.

Packages are published in dependency order: `common`, then `marvell` and `yubico`, then `cli`. The release script rejects mismatched versions, stale internal dependency ranges, dependency cycles and failed registry checks. Only a registry E404 is treated as an unpublished version. The `v<major>` Git tag is moved after successful publication, provided the version is the latest stable tag in that major.

The publication job uses `npm ci --ignore-scripts` and publishes with lifecycle scripts disabled. The explicit build and package export check run before publishing. Do not introduce dependencies that require installation scripts for the release build without adjusting this process.

## Retry a failed or partial publication

Open **Actions → Release → Run workflow** and select the existing `v<version>` tag. Branch refs and tags that disagree with the package version are rejected. Do not rerun from `main`, change package versions or move the release tag.

The retry builds the same tagged source and skips exact package versions already present on npm. It stops at the first publication failure, so remaining dependents can be published by another retry after fixing access or registry availability. Check all four npm versions after a successful run. An unavailable registry or an authentication failure stops the workflow instead of being mistaken for a missing package.

Retry a partial release before creating a newer release. The script refuses to publish a missing older version if that package already has a newer `latest` version on npm. Use a maintainer-controlled publication with an explicit maintenance dist-tag for that older version; this prevents a retry from moving `latest` backwards.

To inspect the release plan locally without publishing:

```sh
node scripts/release.mjs verify
node --test scripts/release.test.mjs
```
