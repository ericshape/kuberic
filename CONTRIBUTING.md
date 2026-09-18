# Contributing to Kuberic

Kuberic uses `main` as its only integration branch. Do not create a long-lived
`dev` or `develop` branch.

## Choose where to work

- Trusted agents and collaborators with write access work on a short-lived
  branch in this repository and open a PR to `main`.
- External contributors, untrusted agents, and work that must not have access
  to repository secrets use a fork and open a PR from the fork to `main`.

Fork pull requests must be treated as untrusted by workflows. Do not expose
secrets to them or run unreviewed fork code in a privileged workflow.

## One task, branch, and writer

Create each agent branch from the latest `main` and name it
`agent/<issue>-<slug>`, for example `agent/123-fix-replica-fencing`.

- Keep one issue or task in each branch and PR.
- Assign exactly one writing agent to a branch. Other agents may review or
  research, but must not push to that branch.
- Avoid assigning parallel tasks to the same files. Open a draft PR early so
  its owner and intended scope are visible.
- Do not assemble agents' work by cherry-picking commits between task branches.
  Represent dependencies with PRs instead.

Start dependent work serially whenever possible. If parallel work is necessary,
use a temporary PR stack:

1. Base the dependent branch and PR on its direct dependency.
2. List every dependency in the PR template.
3. Merge the parent PR first.
4. After its squash merge, update the child onto `main` and verify that its diff
   contains only the child task.
5. Delete each temporary branch after its PR merges.

## Pull requests

Open a draft PR as soon as the task scope is known. The PR must identify:

- its related issue;
- its sole branch owner;
- the components and files it intends to change;
- dependent or stacked PRs; and
- known overlap or conflict risk.

Keep the PR in draft while its scope or validation is incomplete. Mark it ready
only after its focused tests pass and the description reflects the final
change. Resolve all review conversations before merging.

Run the checks relevant to the change. The complete CI-equivalent Rust checks
are:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

Document commands and results in the PR. Add or update tests and documentation
when behavior changes.

## Review and merge

- Merge into `main` through a PR; never push directly to `main`.
- Require the `Build and test` job from the `CI / CD` workflow, an approving
  review, CODEOWNERS review, and resolved conversations.
- Put approved PRs into the merge queue so the queued merge candidate is tested
  against the current base. Do not repeatedly rebase merely to follow `main`;
  update a branch when it conflicts or its dependency changes.
- Use squash merge. One task should become one clearly titled commit on `main`.
- Delete the task branch after merge.

## Maintainer repository settings

Repository administrators must keep these GitHub settings enabled:

1. Set `main` as the default branch.
2. Under pull-request merge options, allow squash merge only, enable
   auto-merge, and automatically delete head branches.
3. Apply an active ruleset to `main` that:
   - requires a pull request and at least one approval;
   - requires review from CODEOWNERS;
   - requires all conversations to be resolved;
   - requires the `Build and test` status check from `CI / CD`;
   - requires the merge queue; and
   - blocks force pushes and branch deletion.
4. Do not grant routine bypass access. Reserve any bypass for documented
   recovery by a repository administrator.

These controls are GitHub repository settings and cannot be enforced by files
in the repository alone. The CI workflow includes the `merge_group` event so
required checks run for merge-queue candidates.
