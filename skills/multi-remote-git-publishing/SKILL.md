---
name: "multi-remote-git-publishing"
description: "Use when pushing a repo with multiple remotes or diverged/rewritten histories. Produces identity-verified, fast-forward-only publishes with lineage checks."
---

# Multi-remote git publishing

Publishes commits to repos with two or more remotes (internal gitea + public
GitHub mirrors, personal and public account remotes). Remotes of one repo can
hold completely different histories — one rewritten, one pre-rewrite, one
stale — so a push that is safe for one remote can publish excluded identities
or clobber rewritten history on another. Classify every remote before pushing
anywhere.

## Steps

1. Fetch every remote, not just the default: `git remote -v`, then
   `git fetch <remote> --quiet` for each. Done when all remotes are fetched.

2. Classify each remote against the local branch:

```
git rev-list --count <remote>/<branch>..<branch>    # ahead
git rev-list --count <branch>..<remote>/<branch>    # behind
git merge-base <branch> <remote>/<branch>           # empty = unrelated
```

   Done when every remote is labeled ahead-only, behind, diverged, or
   unrelated. Treat unrelated as diverged-and-dangerous, not as an error to
   retry.

3. Enumerate what a push would actually publish, and who authored it:

```
git log <remote>/<branch>..<branch> --format='%h %an <%ae> | %s'
git log <remote>/<branch> --format='%an <%ae>' | sort -u
```

   A push publishes the whole range, including commits from other sessions —
   not only yours. Done when every to-be-published commit and every remote
   lineage has an identity verdict against the owner's attribution rules.

4. Route each remote:

   - Ahead-only, identities clean: push directly.
   - Unrelated or diverged, remote holds the authoritative history: replay
     the commits onto it (step 5).
   - Remote lineage carries identities the owner has excluded from public
     attribution: do not push. Force-normalizing that remote is an owner
     decision — report it and continue with the remaining remotes.

5. Replay with gates. First `git branch backup-<branch> <branch>`, then
   `git checkout --detach <remote>/<branch>`, then `git cherry-pick <sha>`
   per commit, resolving conflicts toward the original commit's tree. Before
   moving the branch, both gates must pass:

```
git diff <original-sha> HEAD --stat          # must be empty (tree identical)
git log --format='%an <%ae>' HEAD | sort -u   # approved authors only
```

   Any difference: abort the push and report.

6. Publish fast-forward only: `git checkout -B <branch> HEAD`, then push.
   Never pass `--force` unless the owner explicitly requested it. Auth
   patterns:

   - https GitHub remotes:
     `git -c credential.helper= -c credential.helper='!gh auth git-credential' push <remote> <branch>`
     (authenticates with the gh CLI account; token never in commands or logs)
   - SSH remotes:
     `GIT_SSH_COMMAND="ssh -o BatchMode=yes" git push <remote> <branch>`
     (a missing key fails instead of hanging on a prompt)

7. Verify from the platform, not the push output alone:

```
gh api repos/<owner>/<repo>/commits?per_page=2    # HEAD SHA + author
gh api repos/<owner>/<repo>/contents/<new-path>   # spot-check a new file
```

   Done when the remote HEAD is the pushed SHA with the expected author.

8. Clean-room verification when asked to verify "all the changes" on another
   host: first make the complete state reachable — publish local-only commits
   (per the owner's flow) or exclude them explicitly; a clean room missing
   them silently tests a stale subset. On the target host, fresh-clone from
   the public remote, never copy the local working tree (the clone is what a
   stranger gets), build the environment from the repo's own dependency
   files, and run the project's battery: tests, typecheck, repo-specific
   checks. Done when pass/skip counts match the primary host, skip reasons
   included — the fresh clone catches local-state drift and dependency gaps
   the primary machine masks.
