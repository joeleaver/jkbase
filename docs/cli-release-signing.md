# CLI release signing

Every `cli-v*` GitHub Release carries `SHA256SUMS.sig`, an **SSH signature** (`ssh-keygen -Y
sign`, Ed25519, namespace `jkbase-cli-release`) over the release's `SHA256SUMS`. All three
installers verify it **fail-closed**, before reading a line of `SHA256SUMS`, and then check the
archive against those signed bytes:

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
`cli-release` environment's `CLI_SIGNING_KEY` secret. That environment's deployment policy admits
only `cli-v*` tags, so branch and PR workflows can't read the key.

**What it doesn't.**
- *Rollback.* An old, genuinely signed release re-uploaded under a newer tag passes signature
  checks. `jkbase upgrade` still refuses it, because the binary must report the version it asked
  for. `install.sh` with no pinned version would install that older genuine build.
- *Releases before 0.2.1* have no signature, so the scripts and `jkbase upgrade` refuse them
  (`JKBASE_VERSION=0.2.0` / `--version 0.2.0` no longer work).
- *Forks.* `JKBASE_UPDATE_REPO` still picks the repo, but its releases must be signed by a key in
  the running binary's trust root. A fork ships a CLI built with its own `allowed_signers`.

## Keys

Two keys are trusted:

- **primary**: signs releases. Its private half exists only in the `CLI_SIGNING_KEY` secret
  (unencrypted, since CI can't type a passphrase).
- **standby**: never used until a rotation. Its private half is kept offline, passphrase-
  protected (password manager). Because every shipped CLI and script already trusts it, a
  rotation never strands an installed CLI.

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

- `cargo test -p jkbase-cli release_sig` covers accept/reject (tampered, wrong key, wrong
  namespace, garbage, no keys), strict `allowed_signers` parsing, interop with real
  `ssh-keygen` in both directions, and the scripts embedding the same keys.
- `sh sites/www/tests/install_sh_test.sh` runs `install.sh` against a fake signed release (Linux
  and macOS in CI).
- `sites/www/tests/install_ps1_test.ps1 -Exe <jkbase.exe>` runs the same cases for `install.ps1`
  (Windows CI).
