use super::*;
use ssh_key::private::{Ed25519Keypair, PrivateKey};
use ssh_key::{HashAlg, LineEnding};

fn key(seed: u8) -> PrivateKey {
    PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
}

fn sign(k: &PrivateKey, ns: &str, msg: &[u8]) -> Vec<u8> {
    SshSig::sign(k, ns, HashAlg::Sha512, msg)
        .unwrap()
        .to_pem(LineEnding::LF)
        .unwrap()
        .into_bytes()
}

fn line(k: &PrivateKey) -> String {
    let pk = k.public_key().to_openssh().unwrap();
    format!("{PRINCIPAL} namespaces=\"{NAMESPACE}\" {pk} test-key\n")
}

const SUMS: &[u8] = b"aaaa  jkbase-x86_64-unknown-linux-musl.tar.gz\n";

#[test]
fn accepts_a_listed_key_including_a_second_one() {
    let (a, b) = (key(1), key(2));
    let keys = parse_allowed_signers(&format!("# c\n\n{}{}", line(&a), line(&b))).unwrap();
    assert_eq!(keys.len(), 2);
    verify_with(&keys, SUMS, &sign(&a, NAMESPACE, SUMS)).unwrap();
    // Rotation: a release signed by the standby key verifies too.
    verify_with(&keys, SUMS, &sign(&b, NAMESPACE, SUMS)).unwrap();
}

#[test]
fn rejects_tampering_wrong_key_wrong_namespace_and_garbage() {
    let a = key(1);
    let keys = parse_allowed_signers(&line(&a)).unwrap();
    let good = sign(&a, NAMESPACE, SUMS);
    assert!(verify_with(&keys, b"bbbb  jkbase-x86_64-unknown-linux-musl.tar.gz\n", &good).is_err());
    assert!(verify_with(&keys, SUMS, &sign(&key(3), NAMESPACE, SUMS)).is_err());
    assert!(verify_with(&keys, SUMS, &sign(&a, "file", SUMS)).is_err());
    assert!(verify_with(&keys, SUMS, &sign(&a, "git", SUMS)).is_err());
    assert!(verify_with(&keys, SUMS, b"").is_err());
    assert!(verify_with(&keys, SUMS, b"-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n").is_err());
}

#[test]
fn no_keys_fails_closed() {
    let a = key(1);
    let keys = parse_allowed_signers("# only comments\n\n").unwrap();
    assert!(keys.is_empty());
    let err = verify_with(&keys, SUMS, &sign(&a, NAMESPACE, SUMS)).unwrap_err();
    assert!(err.to_string().contains("no release-signing keys"), "{err}");
}

#[test]
fn allowed_signers_lines_are_parsed_strictly() {
    let pk = key(1).public_key().to_openssh().unwrap();
    for bad in [
        format!("someone namespaces=\"{NAMESPACE}\" {pk}"),
        format!("{PRINCIPAL} {pk}"),
        format!("{PRINCIPAL} namespaces=\"file\" {pk}"),
        format!("{PRINCIPAL} namespaces=\"{NAMESPACE},file\" {pk}"),
        format!("{PRINCIPAL} namespaces=\"{NAMESPACE}\" ssh-ed25519 AAAAnotbase64!"),
        format!("{PRINCIPAL} namespaces=\"{NAMESPACE}\" ssh-rsa AAAAB3NzaC1yc2E"),
        // Type label says ed25519, blob is something else.
        format!("{PRINCIPAL} namespaces=\"{NAMESPACE}\" ssh-ed25519 AAAAB3NzaC1yc2EAAAADAQABAAAAgQC"),
    ] {
        assert!(parse_allowed_signers(&bad).is_err(), "accepted: {bad}");
    }
}

/// The shipped trust root: non-empty, every line well-formed.
#[test]
fn embedded_keys_parse_and_are_present() {
    let keys = parse_allowed_signers(ALLOWED_SIGNERS).unwrap();
    assert!(!keys.is_empty(), "release-keys/allowed_signers lists no keys");
}

/// Non-comment lines of the key block a script embeds between `open` and `close`.
fn script_keys(path: &str, open: &str, close: &str) -> Vec<String> {
    let full = format!("{}/../../{path}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&full).unwrap_or_else(|e| panic!("{full}: {e}"));
    let start = text.find(open).unwrap_or_else(|| panic!("{path}: no `{open}`")) + open.len();
    let len = text[start..].find(close).unwrap_or_else(|| panic!("{path}: no `{close}`"));
    assert_eq!(text.matches(open).count(), 1, "{path}: `{open}` must appear once");
    key_lines(&text[start..start + len])
}

fn key_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect()
}

/// The install scripts carry a copy of the trust root (they're served standalone); a drift would
/// make them trust a different set of keys than `jkbase upgrade`.
#[test]
fn install_scripts_embed_the_same_keys() {
    let want = key_lines(ALLOWED_SIGNERS);
    assert_eq!(script_keys("sites/www/install.sh", "ALLOWED_SIGNERS='", "'"), want, "install.sh");
    assert_eq!(script_keys("sites/www/install.ps1", "$allowedSigners = @'", "'@"), want, "install.ps1");
}

/// Interop with the real tool in both directions: what CI's `ssh-keygen -Y sign` produces, we
/// verify; what we accept, `ssh-keygen -Y verify` (the install scripts' verifier) accepts.
#[cfg(unix)]
#[test]
fn interoperates_with_ssh_keygen() {
    use std::process::{Command, Stdio};
    let dir = std::env::temp_dir().join(format!("jkbase-sig-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let k = dir.join("k");
    let run = |args: &[&str], stdin: Option<&std::path::Path>| {
        let mut c = Command::new("ssh-keygen");
        c.args(args).stdout(Stdio::null()).stderr(Stdio::null());
        if let Some(p) = stdin {
            c.stdin(std::fs::File::open(p).unwrap());
        }
        c.status().expect("ssh-keygen (OpenSSH >= 8.1) is required to run this test").success()
    };
    assert!(run(&["-q", "-t", "ed25519", "-N", "", "-f", k.to_str().unwrap()], None));
    let sums = dir.join("SHA256SUMS");
    std::fs::write(&sums, SUMS).unwrap();
    assert!(run(&["-Y", "sign", "-f", k.to_str().unwrap(), "-n", NAMESPACE, sums.to_str().unwrap()], None));

    let pubkey = std::fs::read_to_string(dir.join("k.pub")).unwrap();
    let signers = format!("{PRINCIPAL} namespaces=\"{NAMESPACE}\" {}", pubkey.trim());
    let keys = parse_allowed_signers(&signers).unwrap();
    let sig = std::fs::read(dir.join("SHA256SUMS.sig")).unwrap();
    verify_with(&keys, SUMS, &sig).unwrap();
    assert!(verify_with(&keys, b"tampered", &sig).is_err());

    // Same allowed_signers line, read by ssh-keygen itself.
    let f = dir.join("allowed_signers");
    std::fs::write(&f, &signers).unwrap();
    let verify = |sig: &str| {
        run(&["-Y", "verify", "-f", f.to_str().unwrap(), "-I", PRINCIPAL, "-n", NAMESPACE, "-s", sig], Some(&sums))
    };
    assert!(verify(dir.join("SHA256SUMS.sig").to_str().unwrap()));
    // A signature by a key not in the file is refused by ssh-keygen too.
    let other = dir.join("other.sig");
    std::fs::write(&other, sign(&key(9), NAMESPACE, SUMS)).unwrap();
    assert!(!verify(other.to_str().unwrap()));
    let _ = std::fs::remove_dir_all(&dir);
}
