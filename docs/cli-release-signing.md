# CLI release signing

Every `cli-v*` GitHub Release carries `SHA256SUMS.sig`, an **SSH signature** (`ssh-keygen -Y
sign`, Ed25519, namespace `jkbase-cli-release`) over the release's `SHA256SUMS`. That file's first
line, `# jkbase-cli <version>`, is part of the signed bytes (`sha256sum -c` skips it). All three
installers verify the signature **fail-closed**, before reading a line of `SHA256SUMS`. They then
check the signed version, then the archive against those signed bytes:

| Installer | Verifier | Trust root |
|---|---|---|
| `jkbase upgrade` | `ssh-key` crate (`crates/jkbase-cli/src/commands/release_sig.rs`) | `crates/jkbase-cli/release-keys/allowed_signers`, compiled in |
| `sites/www/install.sh` | `ssh-keygen -Y verify` (OpenSSH ≥ 8.1) | `ALLOWED_SIGNERS='…'` block (a copy) |
| `sites/www/install.ps1` | Windows' built-in `ssh-keygen.exe -Y verify` | `$allowedSigners = @'…'@` block (a copy) |

`release-keys/allowed_signers` is the single source of truth. `jkbase-cli`'s
`install_scripts_embed_the_same_keys` test fails if either script's copy differs from it. The
release workflow also verifies its fresh signature against that file at the tagged commit, so a
CI key that this release doesn't trust fails the release rather than reaching users.

**Why SSH signatures and not minisign.** They use the same Ed25519 primitive, but `ssh-keygen`
already ships on macOS, Windows 10+ and nearly every Linux. A fail-closed `curl | sh` installer
has to verify with a tool the user already has, and minisign is installed almost nowhere.

**What it protects.** Before this, `SHA256SUMS` came from the same place as the archives, so
anyone able to publish a release on the repo (a leaked token, a compromised workflow or account)
could ship a binary. Now that person also needs the signing key, which lives only in the
`cli-release` environment's `CLI_SIGNING_KEY` secret.

Only `cli-v*` tags may deploy to that environment, so branch and PR runs never see the key. The
signing job pins its actions to commit SHAs, so a moved action tag can't run code beside the key.

**Accepted trust decision (2026-11-24): anyone with write access can obtain the signing key.** A
tag runs the workflow file *at that tag*. Anyone who can push a commit and a `cli-v*` tag
controls the job that reads `CLI_SIGNING_KEY`, so they can exfiltrate it or sign whatever they
like. The tag pattern doesn't prevent this.

The way to close the gap is a required reviewer on the environment plus a `cli-v*` tag ruleset
(commands below). Joe chose not to add them. The repo's write collaborators (Joe and lost-conn)
are trusted to push releases, and on a free-tier personal repo a non-owner can't be made an admin
or a ruleset bypass, so a ruleset would lock lost-conn out of releasing.

So the signature protects against anyone who can upload release assets but can't push to the
repo, and against the download path. It does not protect against a write collaborator, or a
leaked token carrying write access.

**Revisit this whenever the collaborator set changes** (someone gains or loses write access, or a
write token may have leaked). Either apply the lockdown below, or treat the key as exposed and
rotate to the standby (see Rotation).

**Rollback.** An old, genuinely signed release served in place of a newer one also passes the
signature check, so the signed version line is checked as well:
- *A pinned version* (`JKBASE_VERSION`, `jkbase upgrade` with or without `--version`): it must
  equal the signed version.
- *Latest* (install scripts): the signed version must be no older than `latest` from
  `https://api.jkbase.app/cli`, a second origin that a release-host attacker doesn't control. If
  that endpoint can't be reached, the install fails closed. "No older" rather than "equal"
  because a release is published before the server that advertises it is deployed.
- *Every installer* also requires the new binary's `--version` to match the signed version.

**What it doesn't protect.**
- *Releases before 0.2.1* have no signature, so the scripts and `jkbase upgrade` refuse them
  (`JKBASE_VERSION=0.2.0` / `--version 0.2.0` no longer work).
- *Forks.* `JKBASE_UPDATE_REPO` still picks the repo, but its releases must be signed by a key in
  the running binary's trust root. A fork ships a CLI built with its own `allowed_signers`.

## Keys

Two keys are trusted:

- **primary**: signs releases. Its private half exists only in the `CLI_SIGNING_KEY` secret
  (unencrypted, since CI can't type a passphrase).
- **standby**: never used until a rotation. Its private half is kept offline, passphrase-
  protected (password manager). Every shipped CLI and script already trusts it, so a single
  rotation never strands an installed CLI. A CLI that skipped a whole rotation can be stranded;
  see the caveat under Rotation.

Every line of `allowed_signers` has exactly this shape (the CLI rejects anything else):

```
jkbase-release namespaces="jkbase-cli-release" ssh-ed25519 AAAA… comment
```

### One-time setup

Run this once (needs `gh` with admin on the repo):

```bash
d="$(mktemp -d)" && cd "$d" \
&& ssh-keygen -q -t ed25519 -N '' -C jkbase-cli-release-primary -f primary \
&& ssh-keygen -q -t ed25519 -C jkbase-cli-release-standby -f standby \
&& gh api -X PUT repos/joeleaver/jkbase/environments/cli-release -F 'deployment_branch_policy[protected_branches]=false' -F 'deployment_branch_policy[custom_branch_policies]=true' \
&& gh api -X POST repos/joeleaver/jkbase/environments/cli-release/deployment-branch-policies -f name='cli-v*' -f type=tag \
&& gh secret set CLI_SIGNING_KEY --repo joeleaver/jkbase --env cli-release < primary \
&& cat primary.pub standby.pub
```

*Not applied (see the accepted trust decision above).* To close the write-access gap, add a
required reviewer to the environment and limit who can create `cli-v*` tags:

```bash
gh api -X PUT repos/joeleaver/jkbase/environments/cli-release \
  -F 'deployment_branch_policy[protected_branches]=false' -F 'deployment_branch_policy[custom_branch_policies]=true' \
  -F 'reviewers[][type]=User' -F "reviewers[][id]=$(gh api user --jq .id)"
gh api -X POST repos/joeleaver/jkbase/rulesets --input - <<'JSON'
{"name": "cli-release tags", "target": "tag", "enforcement": "active",
 "conditions": {"ref_name": {"include": ["refs/tags/cli-v*"], "exclude": []}},
 "rules": [{"type": "creation"}, {"type": "update"}, {"type": "deletion"}],
 "bypass_actors": [{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}]}
JSON
```

Each release run then waits for **Review deployments → Approve** on the Actions run page. Only
approve runs you started yourself. A token that can itself approve deployments (an admin-scoped token, via the
API) could also clear this gate, so keep long-lived admin tokens out of CI and off shared
machines.

Then:

1. Put both `.pub` keys into `allowed_signers` and both script blocks, in the format above, and
   merge.
2. Store `standby` and its passphrase offline.
3. Run `shred -u "$d/primary" "$d/standby" && rm -rf "$d"`.

## Rotation

The rule that keeps installed CLIs working: **a key is only ever used to sign after a release
that trusts it has shipped.** The standby key satisfies this by construction.

**Routine, or the primary key is lost** (the secret was deleted):

1. Promote the standby: decrypt a copy (`ssh-keygen -p -f standby` into a temp dir) and run
   `gh secret set CLI_SIGNING_KEY --repo joeleaver/jkbase --env cli-release < standby`. Shred the
   decrypted copy.
2. Make a new standby: `ssh-keygen -t ed25519 -C jkbase-cli-release-standby-N -f standby`. Store
   it offline.
3. In `allowed_signers` and both script blocks, remove the old primary and add the new standby.
   Merge, then release as usual. That release is signed by the old standby (now primary), which
   every existing CLI trusts.

**The primary key is compromised:** do the same steps immediately, and also:

- Audit the GitHub Releases for anything not built by the workflow, and delete it.
- Deploy `sites/www` right after merging, so the live install scripts stop trusting the
  compromised key. They're served live, so this takes effect at once.
- Installed CLIs keep trusting the compromised key until they upgrade. There is no revocation
  channel, so say so in the release notes and ask users to `jkbase upgrade`.

**Caveat: skipped rotations.** A CLI trusts only the keys of the release it came from. Take a CLI
from before rotation 1 (trusting P0 + S0). Once rotation 2 has dropped S0, `jkbase upgrade` to
the latest fails closed for that CLI. Its signature error says to reinstall with the install
script, which always carries the current keys. Alternatively, `jkbase upgrade --version <a
release signed between the rotations>` steps through. So keep rotations rare, and name the last
release of each key era in its release notes.

**Both keys are compromised or lost:** generate a new pair and replace both lines. Installed
CLIs can't verify anything signed by the new keys, so `jkbase upgrade` fails closed for them and
users must reinstall with `install.sh` / `install.ps1`. Say this in the release notes.

## Verifying a release by hand

```bash
v=0.2.1; b="https://github.com/joeleaver/jkbase/releases/download/cli-v$v"
curl -fsSLO "$b/SHA256SUMS" -O "$b/SHA256SUMS.sig"
ssh-keygen -Y verify -f crates/jkbase-cli/release-keys/allowed_signers \
  -I jkbase-release -n jkbase-cli-release -s SHA256SUMS.sig < SHA256SUMS
```

## Tests

- `cargo test -p jkbase-cli` covers:
  - accept/reject: tampered, wrong key, wrong namespace, garbage, no keys;
  - strict `allowed_signers` parsing;
  - interop with real `ssh-keygen`, both directions;
  - the scripts embedding the same keys;
  - `upgrade`'s signed-digest path, including the version binding.
- `sh sites/www/tests/install_sh_test.sh` runs `install.sh` against a fake signed release, in CI on
  Linux and macOS. On top of the signature cases it covers rollback, a missing version line, a
  binary version mismatch, an unreachable `/cli`, missing or too-old `ssh-keygen`, and the
  `wget` path.
- `sites/www/tests/install_ps1_test.ps1 -Exe <jkbase.exe>` runs the same cases for `install.ps1`
  (Windows CI).
